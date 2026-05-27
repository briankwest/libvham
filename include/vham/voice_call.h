/* libvham/include/vham/voice_call.h — high-level voice call orchestrator.
 *
 * A `vham_voice_call_t` owns everything between "I'm logged in and want
 * to make a PTT call" and "I'm done sending audio":
 *
 *   - opens / binds the RTP socket on MEDPORT_BASE + leg_id*4
 *     (or a caller-supplied port for explicit port-forwarding)
 *   - probes our public endpoint via STUN (informational)
 *   - sends CC_SETUP with the canonical audio SDP offer
 *   - runs the post-SETUP signaling loop: TAP-ACK on every incoming
 *     frame, parse CC_CONN's SDP for the per-call media port, send
 *     CC_CONNACK as soon as we're CONNECTED, handle CC_MODIFY mid-call
 *   - sends the mic-acquisition triplet (mic_grant + user_ctrl + talking_id)
 *   - starts the FF D3 01 media-NAT sentinel (initial 3× + 2s tick)
 *   - punches NAT with 5 silence frames
 *
 * After setup() returns 0, the caller pumps audio one PCM frame at a
 * time via pump_frame() — that single call encodes via the codec,
 * builds the RTP packet, sendto's, drains signaling (auto-ack, auto-
 * redirect), and ticks the NAT sentinel.  release() sends CC_REL and
 * closes the RTP socket.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_VOICE_CALL_H
#define VHAM_VOICE_CALL_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#include "vham/cc.h"
#include "vham/nat.h"
#include "vham/voice.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Already-logged-in signaling socket (vham_reg_client must have
     * completed REGREQ/REGRSP). */
    int             sig_fd;

    /* Identity */
    const char     *my_num;
    const char     *peer_num;           /* channel num or peer user */
    int             is_channel_call;    /* 1 for numeric channel target */
    const char     *channel_subcode;    /* IE 0x45 — NULL for user calls */
    uint32_t        leg_id;             /* dwSrcFsmId, random short */

    /* TAP seq counter shared with the reg_client. Read and updated
     * in place — the caller's reg_client.seq_no should equal *seq_no
     * before setup() and will be left at the post-call value after. */
    uint32_t       *seq_no;

    /* From the reg_client (echoed into CC_SETUP for auth). */
    const char     *auth_algorithm;
    const char     *auth_nonce;
    const char     *auth_realm;
    const char     *auth_response;

    /* Default media gateway from REGRSP (host order). The per-call
     * port from CC_CONN will override media_gw_port at setup time. */
    uint32_t        media_gw_ipv4;
    uint16_t        media_gw_port;

    /* Audio format the caller will feed pump_frame(). */
    uint8_t         payload_type;
    int             samples_per_frame;
    uint32_t        clock_rate;

    /* Optional: bind local RTP socket to this port instead of the
     * deterministic MEDPORT_BASE + leg_id*4. Use with explicit UDP
     * port-forwarding on the router to pin the public endpoint. */
    uint16_t        rtp_port_override;
} vham_voice_call_opts_t;

typedef struct {
    /* Sub-state */
    vham_cc_call_t        call;
    vham_media_nat_t      nat;
    vham_voice_tx_t       tx;

    /* Owned by us */
    int                   rtp_fd;
    uint16_t              rtp_port;       /* local port */
    struct sockaddr_in    media_dst;

    /* Informational */
    uint32_t              pub_ip;         /* STUN-discovered */
    uint16_t              pub_port;

    /* Borrowed */
    int                   sig_fd;         /* not closed by us */
    uint32_t             *seq_no_ref;     /* not freed by us */
    uint8_t               payload_type;
    int                   samples_per_frame;

    /* Lifecycle */
    int                   active;
} vham_voice_call_t;

/* Open the call: bind RTP, STUN-probe, send CC_SETUP, wait for
 * CC_CONN, send CC_CONNACK, claim mic, init NAT sentinel, NAT-punch.
 *
 * On success vc is fully initialized and ready for pump_frame.
 * Returns 0 on success, -1 on any unrecoverable error (in which case
 * any partially-acquired resources are released before return). */
int vham_voice_call_setup(vham_voice_call_t *vc,
                          const vham_voice_call_opts_t *opts);

/* Send one audio frame: encode `n_samples` 16-bit PCM at the codec's
 * clock rate, wrap in RTP, sendto the per-call media endpoint.
 * Ticks the NAT sentinel (re-sends FF D3 01 if 2s elapsed). Drains
 * any pending signaling (auto-acks every frame; auto-handles
 * CC_MODIFY mid-call redirects).
 *
 * `marker` should be 1 for the first frame of a talk spurt, 0 after.
 *
 * Returns:
 *    1   frame sent
 *    0   server CC_REL — stop sending and call release()
 *   -1   encode or sendto failure */
int vham_voice_call_pump_frame(vham_voice_call_t *vc,
                               const int16_t *pcm, size_t n_samples,
                               int marker);

/* Send CC_REL with the supplied cause code and close the RTP socket.
 * Caller still owns the signaling socket. */
void vham_voice_call_release(vham_voice_call_t *vc, uint32_t cause);

/* Accessors used by callers that want to poll inbound RTP themselves
 * (e.g. for echo / loopback tests). */
static inline int       vham_voice_call_rtp_fd  (const vham_voice_call_t *vc) { return vc->rtp_fd; }
static inline uint16_t  vham_voice_call_rtp_port(const vham_voice_call_t *vc) { return vc->rtp_port; }

#ifdef __cplusplus
}
#endif

#endif /* VHAM_VOICE_CALL_H */
