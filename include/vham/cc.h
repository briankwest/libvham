/* libvham/include/vham/cc.h — Call Control (CC) message builders.
 *
 * Currently supports CC_SETUP only (the call-origination message).
 * Mirrors CCFsm::UserMakeOut @ libsvcapi.so 0x2ec888.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_CC_H
#define VHAM_CC_H

#include "vham/codec.h"
#include "vham/sdp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Transport */
    uint32_t seq_no;

    /* SRVMSG header */
    uint32_t leg_id;             /* dwSrcFsmId — caller's leg/resource id */

    /* MM session auth context (echoed into CC_SETUP so the server
     * can bind the call to our registered session). Any NULL string
     * causes the corresponding IE to be omitted. */
    const char *auth_algorithm;  /* IE 0x07 */
    const char *auth_nonce;      /* IE 0x09 */
    const char *auth_realm;      /* IE 0x0a */
    const char *auth_response;   /* IE 0x0b */

    /* IEs */
    const char *called_num;      /* IE 0x0d — destination dispatch number */
    const char *calling_num;     /* IE 0x0e — origin (our own) dispatch num */
    uint32_t    service_type;    /* IE 0x23 — see vham_call_service */

    /* Channel sub-code — IE 0x45. The operator-facing channel list
     * on vham.net shows this as the "Password" column. It's not an
     * auth password but a CTCSS-style sub-channel selector (e.g.
     * "01".."10", "50") that partitions a single frequency into
     * multiple virtual groups. NULL/empty → IE 0x45 omitted (no
     * sub-code = the open / calling channel). */
    const char *channel_subcode;

    /* SDP offer. If `sdp_bytes` is NULL, IE 0x19 is omitted. */
    const uint8_t *sdp_bytes;
    size_t         sdp_len;

    /* IE 0x53 — CallConf. 11 u8 bytes + a NUL-terminated string.
     * The binary always sends this with presence=1 for CC_SETUP.
     * Defaults of all-zero + empty string are usually fine for a
     * basic PTT half-duplex call. Set `include_callconf=0` to omit
     * (server typically silently drops the call). */
    int        include_callconf;
    uint8_t    callconf_bytes[11];
    const char *callconf_str;

    /* Optional decoration (IE 0x76 — display name / extension) */
    const char *display_str;

    /* Optional private number (IE 0x7e — set when caller has a sub-num) */
    const char *priv_num;
} vham_cc_setup_t;

/* Build a CC_SETUP datagram (TAP header + SRVMSG header + IEs).
 * Returns bytes written, or -1 on error. */
int vham_build_cc_setup(const vham_cc_setup_t *p,
                        void *out, size_t out_cap);

/* ---------- CC call state machine ---------- */

typedef enum {
    VHAM_CALL_IDLE,         /* before SETUP */
    VHAM_CALL_SETUP_SENT,   /* SETUP sent, awaiting SETUPACK or REL */
    VHAM_CALL_SETUP_ACK,    /* server accepted SETUP, awaiting ALERT or CONN */
    VHAM_CALL_ALERTING,     /* callee phone is ringing */
    VHAM_CALL_CONNECTED,    /* CONN received; we owe a CONNACK */
    VHAM_CALL_ACTIVE,       /* CONNACK sent / received — media flowing */
    VHAM_CALL_RELEASING,    /* REL exchanged, awaiting RLC */
    VHAM_CALL_RELEASED,     /* terminal */
    VHAM_CALL_FAILED        /* terminal: protocol/parse/auth error */
} vham_call_state_t;

const char *vham_call_state_str(vham_call_state_t s);

typedef struct {
    /* Local identity (filled by caller) */
    char        my_num[32];           /* our dispatch number */
    char        peer_num[32];         /* the called party */

    /* Wire / transport */
    uint32_t    leg_id;               /* dwSrcFsmId — caller picks */
    uint32_t    seq_no;               /* monotonic TAP seq */

    /* Server fields captured from incoming frames */
    int         have_remote_leg;
    uint32_t    remote_leg_id;        /* server's dwSrcFsmId echoed back */

    /* Remote SDP (the answer) */
    int         have_remote_sdp;
    vham_sdp_t  remote_sdp;

    /* Cause of failure / release (IE 0x12 / IE 0x40) */
    uint32_t    last_cause;

    /* Last mic-grant decoded from a received CC_INFO (IE 0x54).
     * `mic_holder` is the dispatch num currently holding the mic
     * (empty if released). `mic_action` is the most recent action
     * code (0 if none observed). */
    char     mic_holder[32];
    uint8_t  mic_action;

    vham_call_state_t state;
} vham_cc_call_t;

/* Initialize a call to peer_num with my_num as the calling party. */
int vham_cc_call_init(vham_cc_call_t *c,
                      const char *my_num,
                      const char *peer_num,
                      uint32_t    leg_id);

/* Build the next CC frame the caller should send.
 *
 *   IDLE          → emits CC_SETUP, transitions to SETUP_SENT
 *   CONNECTED     → emits CC_CONNACK, transitions to ACTIVE
 *   RELEASING     → emits CC_RLC, transitions to RELEASED
 *
 * `sdp_bytes`/`sdp_len` and the auth_* strings are used only for the
 * SETUP emission. Auth fields should match what the MM session
 * accepted (typically vham_reg_client_t's last_algorithm / last_nonce
 * / last_realm / last_response_hex). NULL/empty omits the IE.
 *
 * Returns bytes written, or -1 if the state has nothing to emit. */
int vham_cc_call_emit(vham_cc_call_t *c,
                      const uint8_t *sdp_bytes, size_t sdp_len,
                      uint32_t service_type,
                      const char *channel_subcode,
                      const char *auth_algorithm,
                      const char *auth_nonce,
                      const char *auth_realm,
                      const char *auth_response,
                      void *out, size_t out_cap);

/* Feed an incoming CC frame (TAP header + SRVMSG + IEs) into the
 * state machine. Returns the new state. */
vham_call_state_t vham_cc_call_recv(vham_cc_call_t *c,
                                    const void *buf, size_t len);

/* Build a CC_INFO frame carrying a PTT mic-grant request (action=1)
 * or release (action=2). Mirrors `CCFsm::MicCtrl @ 0x2f19f8`.
 * Returns bytes written, or -1 on error. */
int vham_cc_call_mic_grant(vham_cc_call_t *c, int action,
                           void *out, size_t out_cap);

/* Build a CC_REL frame with a cause code in IE 0x40. Mirrors
 * `CCFsm::Rel`. The cause is emitted as a decimal string per the
 * binary's TLV_NUMBER convention.
 *
 * Common cause values:
 *   0x10 = normal hangup
 *   0x11 = user busy
 *   0x1c = call rejected
 *   0x29 = network failure
 *
 * Returns bytes written, or -1 on error. */
int vham_cc_call_release(vham_cc_call_t *c, uint32_t cause,
                         void *out, size_t out_cap);

/* Build a CC_CONN (callee answer) carrying our local SDP, mirroring
 * `CCFsm::UserAnswer`. Caller provides the SDP body bytes. */
int vham_cc_call_answer(vham_cc_call_t *c,
                        const uint8_t *sdp_bytes, size_t sdp_len,
                        void *out, size_t out_cap);

/* Build a CC_SETUPACK (server routing has accepted our SETUP).
 * Bare frame with no body IEs. Server may also send this to us. */
int vham_cc_call_setup_ack(vham_cc_call_t *c, void *out, size_t out_cap);

/* Build a CC_INFOACK acknowledging an INFO frame. */
int vham_cc_call_info_ack(vham_cc_call_t *c, void *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
