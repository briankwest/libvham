/* libvham/include/vham/regrsp.h — MM_REGRSP parser + a small,
 * I/O-free registration state machine.
 *
 * The state machine accepts buffers from the network and produces
 * buffers to send. It does not perform any UDP I/O itself — the
 * caller owns the socket.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_REGRSP_H
#define VHAM_REGRSP_H

#include "vham/codec.h"
#include "vham/regreq.h"
#include "vham/composites.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- MM_STATUSSUBS (wMsgId=0x90) ---------- */

/* StatusSubs subscription level (idt.ini convention):
 *   0 = no notify
 *   1 = basic (online/offline)
 *   2 = detailed (incl. call status)
 *   3 = most detailed (incl. peer numbers)
 */
enum vham_status_sub_level {
    VHAM_SUBS_NONE     = 0,
    VHAM_SUBS_BASIC    = 1,
    VHAM_SUBS_DETAILED = 2,
    VHAM_SUBS_VERBOSE  = 3,
};

/* Build a MM_STATUSSUBS datagram subscribing `target` at `level`.
 *
 *   target  — group/user pattern to subscribe to (e.g. "###" = all)
 *   level   — see vham_status_sub_level
 *   counter — IE 0x21 u32 sequence (incremented per subscribe)
 *   username — our dispatch number (echoed in IE 0x27)
 *
 * Returns bytes written, or -1 on error. */
int vham_build_status_subs(uint32_t seq_no,
                           const char *username,
                           const char *target,
                           uint8_t     level,
                           uint32_t    counter,
                           void *out, size_t out_cap);

/* Build an MM_QUIT frame — explicit logout. Returns bytes written. */
int vham_build_mm_quit(uint32_t seq_no, const char *username,
                       void *out, size_t out_cap);

/* ---------- MM_PROFREQ / MM_MODREQ / MM_ROUTEREQ / MM_NATT_PROB --
 *
 * Bare-bones senders for the remaining MM ops. They all share the
 * TAP-class-1 + Dst/Src=MM + IE 0x27 (our number) skeleton. The
 * caller can optionally include an IE 0x21 counter or other IEs
 * via the `extras` callback (NULL = none). The exact IE list each
 * server actually requires is server-specific and was not nailed
 * down in the binary — these are the minimum viable encoders. */
typedef int (*vham_mm_extra_pack_fn)(void *ctx, uint8_t *out, size_t cap);

int vham_build_mm_simple(uint16_t wmsgid,
                         uint32_t seq_no,
                         const char *username,
                         vham_mm_extra_pack_fn extras_fn,
                         void *extras_ctx,
                         void *out, size_t out_cap);

/* Same as above but lets you subscribe to multiple targets at once
 * (e.g. "###" wildcard + a specific channel like "146520"). Each
 * pair (targets[i], levels[i]) is packed as a separate StatusSubs
 * entry within IE 0x4b. */
typedef struct {
    const char *target;
    uint8_t     level;
} vham_subs_entry_t;

int vham_build_status_subs_multi(uint32_t seq_no,
                                 const char *username,
                                 const vham_subs_entry_t *entries,
                                 size_t      n_entries,
                                 uint32_t    counter,
                                 void *out, size_t out_cap);

/* ---------- Async MM notifications (server → client) ----------
 *
 * After login + STATUSSUBS, the server pushes events wrapped in an
 * MM_REGRSP envelope (wMsgId=0x0011, ucSrc=CC=5) with a sub-opcode
 * in IE 0x1e. We've identified one:
 *
 *   sub_opcode = 0x0021  →  "call activity for you"
 *                            (callee should prepare to receive a CC_SETUP)
 *
 * The structural shape: ucDst=MM (4), ucSrc=CC (5), wMsgId=0x0011,
 * IE 0x27 = our own dispatch number echoed back, IE 0x1d = small u8
 * status code, IE 0x1e = the sub-opcode. */
typedef struct {
    int      have_notify;
    uint16_t sub_opcode;        /* IE 0x1e (host order u16) */
    uint8_t  notify_status;     /* IE 0x1d (u8) */
    char     echoed_num[64];    /* IE 0x27 echo */
} vham_mm_notify_t;

/* Parse a server-pushed MM event. Returns 0 on success and sets
 * `out->have_notify` if the frame is recognised as an event. */
int vham_parse_mm_notify(const void *buf, size_t len,
                         vham_mm_notify_t *out);

/* ---------- MM_STATUSNOTIFY (wMsgId 0x91) ----------
 *
 * The proper server-pushed status notification (vs. the REGRSP-wrapped
 * "call-incoming" variant we already handle). Carries presence /
 * group-status updates for targets the client has subscribed to via
 * MM_STATUSSUBS.
 *
 * Common IEs (per binary string analysis):
 *   IE 0x27 — subject user number
 *   IE 0x21 — counter
 *   IE 0x6c — peer number (optional)
 *   IE 0x4d — GMemStatus composite (group member status — optional)
 *   IE 0x1d — status code (u8)
 */
typedef struct {
    int      have_subject;
    char     subject_num[64];
    int      have_counter;
    uint32_t counter;
    int      have_status;
    uint8_t  status;
    int      have_peer;
    char     peer_num[64];
} vham_status_notify_t;

int vham_parse_status_notify(const void *buf, size_t len,
                             vham_status_notify_t *out);

/* ---------- Parsed MM_REGRSP ---------- */
typedef struct {
    uint16_t sub_opcode;             /* IE 0x1e — 0x53 = challenge   */
    uint16_t cause;                  /* derived: 0 = ok, !0 = error  */
    int      have_sub_opcode;
    int      have_cause;

    /* Auth challenge (when sub_opcode == 0x53) */
    char     algorithm[64];          /* IE 0x07; "" if absent */
    char     nonce    [64];          /* IE 0x09 */
    char     realm    [64];          /* IE 0x0a */

    /* Server-provided fields that must be echoed on the next REGREQ */
    int      have_auth_mode;
    uint32_t auth_mode;              /* IE 0x62 */
    char     dispatch_num[64];       /* IE 0x70 */

    /* Redirect: the dispatcher node populates IE 0x24 with the
     * signaling-node endpoint to use next. Detected as
     * "have_server_addr && (sub_opcode == 0x53 || nonce absent)". */
    int      have_server_addr;
    uint32_t server_addr_ipv4;       /* host order */
    uint16_t server_addr_port;

    /* Session fields populated on success REGRSP */
    int      have_session_id;
    uint32_t session_id;             /* IE 0x44 */

    int      have_sys_time;
    uint16_t sys_year;               /* IE 0x8c (P_TIME) — all BE u16s */
    uint16_t sys_month;
    uint16_t sys_day;
    uint16_t sys_hour;
    uint16_t sys_min;
    uint16_t sys_sec;
    uint16_t sys_subsec;             /* msec or weekday */

    int      have_media_gw;
    uint32_t media_gw_ipv4;          /* IE 0x5a (6-byte PIpAddr, LE) */
    uint16_t media_gw_port;

    int      have_alt_endpoint;
    uint32_t alt_ipv4;               /* IE 0x84 */
    uint16_t alt_port;

    /* Opaque echo blobs — FTP server info (IE 0x59) and org info
     * (IE 0x5c) are nested structures we haven't fully decoded.
     * Surface them as opaque so callers can use the raw bytes. */
    uint8_t  ftp_blob[256]; size_t ftp_blob_len;
    uint8_t  org_blob[768]; size_t org_blob_len;
    uint8_t  ginfo_blob[2048]; size_t ginfo_blob_len;  /* IE 0x43 / 0x2d */

    /* Optional server-provided fields. Empty if not present. */
    char     server_token[64];       /* registration token */
} vham_regrsp_t;

/* Parse a full REGRSP datagram. Returns 0 on success, -1 if the
 * frame is not a well-formed MM_REGRSP. Unknown IEs are skipped. */
int vham_parse_regrsp(const void *buf, size_t len, vham_regrsp_t *out);

/* ---------- Registration state machine ---------- */
typedef enum {
    VHAM_REG_INIT,                   /* before first emit */
    VHAM_REG_SENT_INITIAL,           /* sent REGREQ #1, awaiting challenge */
    VHAM_REG_SENT_AUTH,              /* sent REGREQ #2 with auth, awaiting result */
    VHAM_REG_OK,                     /* registered */
    VHAM_REG_FAILED,                 /* server rejected */
    VHAM_REG_REDIRECT,               /* dispatcher sent IE 0x24 — caller must
                                      * reopen socket to the new endpoint
                                      * (`server_ipv4`/`server_port` updated)
                                      * and call vham_reg_client_emit again. */
} vham_reg_state_t;

typedef struct {
    /* Configuration — populated by vham_reg_client_init() */
    char        username[64];
    char        password[64];
    uint32_t    server_ipv4;
    uint16_t    server_port;
    uint32_t    seq_no;              /* monotonically incremented per send */

    /* Internal state */
    vham_reg_state_t state;

    /* Latest received challenge (kept so we can re-emit on the next send) */
    char        last_algorithm[64];
    char        last_nonce    [64];
    char        last_realm    [64];

    /* Server-allocated fields that must be echoed back. Captured from
     * the REGRSP and re-emitted on the next REGREQ. */
    int         have_auth_mode;
    uint32_t    auth_mode;            /* IE 0x62 */
    char        dispatch_num[64];     /* IE 0x70 */

    /* Last computed digest response */
    char        last_response_hex[33];

    /* Populated on success (state == VHAM_REG_OK). All "have_*"
     * flags indicate whether the field is present. Numeric values
     * are in host order. */
    int         have_session_id;
    uint32_t    session_id;

    int         have_sys_time;
    uint16_t    sys_year, sys_month, sys_day;
    uint16_t    sys_hour, sys_min, sys_sec, sys_subsec;

    int         have_media_gw;
    uint32_t    media_gw_ipv4;
    uint16_t    media_gw_port;

    int         have_alt_endpoint;
    uint32_t    alt_ipv4;
    uint16_t    alt_port;

    /* Parsed OrgList from IE 0x5c. */
    int            have_org;
    vham_orglist_t org;

    /* Parsed group-membership list from IE 0x43 or 0x2d. */
    int               have_ginfo;
    vham_user_ginfo_t ginfo;

    /* Parsed FTP server info from IE 0x59. */
    int            have_ftp;
    vham_ftpinfo_t ftp;
} vham_reg_client_t;

/* Initialize the client. After this, call vham_reg_client_emit() to
 * produce the first REGREQ. */
int vham_reg_client_init(vham_reg_client_t *c,
                         const char *username,
                         const char *password,
                         uint32_t server_ipv4,
                         uint16_t server_port);

/* Produce the next REGREQ datagram based on internal state.
 * Returns the bytes written, or -1 if the state machine is not in a
 * state that needs to send. */
int vham_reg_client_emit(vham_reg_client_t *c,
                         void *out, size_t out_cap);

/* Feed a received REGRSP into the state machine. Returns the new
 * state. Inspect c->state to decide what to do next. */
vham_reg_state_t vham_reg_client_recv(vham_reg_client_t *c,
                                      const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
