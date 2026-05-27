/* libvham/src/voice_call.c — high-level voice call orchestrator.
 *
 * Owns the soup of socket + signaling + media operations that
 * `cmd_transmit` used to interleave inline. See voice_call.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/voice_call.h"

#include "vham/codec.h"
#include "vham/codec_audio.h"
#include "vham/sdp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Setup-phase timing — emit only when VHAM_VC_TIMING=1 in the env. */
static void vc_phase(struct timeval *t0, struct timeval *prev,
                     const char *label) {
    const char *e = getenv("VHAM_VC_TIMING");
    if (!e || *e == '0') return;
    struct timeval now; gettimeofday(&now, NULL);
    long total = (now.tv_sec - t0->tv_sec) * 1000
               + (now.tv_usec - t0->tv_usec) / 1000;
    long dt    = (now.tv_sec - prev->tv_sec) * 1000
               + (now.tv_usec - prev->tv_usec) / 1000;
    fprintf(stderr, "  [vc t+%ldms] %s (+%ldms)\n", total, label, dt);
    *prev = now;
}

/* idt.ini SYSTEM section: MEDPORT=20000 is the base; the binary's
 * CIDTLeg::InitMySdp computes the leg's RTP port as base+leg_id*4. */
#define MEDPORT_BASE 20000

/* For the claim_mic callback. */
struct vc_send_ctx { int fd; };
static int vc_send_cb(const void *buf, size_t len, void *ctx_) {
    struct vc_send_ctx *cx = (struct vc_send_ctx *)ctx_;
    return send(cx->fd, buf, len, 0) == (ssize_t)len ? 0 : -1;
}

int vham_voice_call_setup(vham_voice_call_t *vc,
                          const vham_voice_call_opts_t *o) {
    if (!vc || !o || o->sig_fd < 0 || !o->seq_no) return -1;
    memset(vc, 0, sizeof *vc);
    struct timeval vc_t0, vc_prev; gettimeofday(&vc_t0, NULL); vc_prev = vc_t0;
    vc->sig_fd            = o->sig_fd;
    vc->seq_no_ref        = o->seq_no;
    vc->payload_type      = o->payload_type;
    vc->samples_per_frame = o->samples_per_frame;
    vc->rtp_fd            = -1;

    /* ---- open + bind the RTP socket ------------------------------ */
    uint16_t rtp_port = o->rtp_port_override
                            ? o->rtp_port_override
                            : (uint16_t)(MEDPORT_BASE + o->leg_id * 4);
    vc->rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (vc->rtp_fd < 0) goto fail;
    int reuse = 1;
    setsockopt(vc->rtp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    struct sockaddr_in lo = { .sin_family = AF_INET,
                              .sin_port   = htons(rtp_port),
                              .sin_addr   = { .s_addr = htonl(INADDR_ANY) } };
    if (bind(vc->rtp_fd, (struct sockaddr *)&lo, sizeof lo) != 0) goto fail;
    vc->rtp_port = rtp_port;

    vc_phase(&vc_t0, &vc_prev, "rtp bind");

    /* ---- STUN probe (informational only) -------------------------
     * 500 ms — Google's STUN responder typically answers in <100 ms.
     * If it doesn't come back fast enough we proceed without it; SDP
     * advertises IP=0 either way, so STUN is purely diagnostic here. */
    vham_stun_discover(vc->rtp_fd, "stun.l.google.com", 19302, 500,
                       &vc->pub_ip, &vc->pub_port);
    vc_phase(&vc_t0, &vc_prev, "stun");

    /* ---- build SDP offer + send CC_SETUP ------------------------- */
    uint8_t sdp[1024];
    int sdp_n = vham_build_sdp_offer_audio(0, rtp_port, sdp, sizeof sdp);
    if (sdp_n <= 0) goto fail;

    vham_cc_call_init(&vc->call, o->my_num, o->peer_num, o->leg_id);
    /* Match the cli's pre-Stage-5 seq accounting: increment the shared
     * counter first, set call.seq_no = N-1, then let vham_cc_call_emit
     * do its own ++ inside so the wire seq = N. */
    (*vc->seq_no_ref)++;
    vc->call.seq_no = *vc->seq_no_ref - 1;

    uint8_t buf[2048];
    int n = vham_cc_call_emit(&vc->call, sdp, (size_t)sdp_n,
                              VHAM_CALL_HALF_DUPLEX,
                              o->channel_subcode,
                              o->auth_algorithm, o->auth_nonce,
                              o->auth_realm,     o->auth_response,
                              buf, sizeof buf);
    if (n <= 0) goto fail;
    if (send(vc->sig_fd, buf, (size_t)n, 0) != (ssize_t)n) goto fail;
    vc_phase(&vc_t0, &vc_prev, "cc_setup sent");

    /* ---- recv loop: wait for CC_CONN with per-call media port ----
     * Short inner timeout (200 ms) so we tick the deadline often; the
     * outer 4 s deadline still covers real wide-area RTTs. The server
     * normally sends SETUPACK + CC_CONN within ~300 ms of CC_SETUP. */
    struct timeval tv_short = { .tv_usec = 200 * 1000 };
    setsockopt(vc->sig_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_short, sizeof tv_short);
    time_t deadline = time(NULL) + 4;
    uint8_t resp[2048];
    int got_media = 0;
    while (time(NULL) < deadline && !got_media) {
        ssize_t r = recv(vc->sig_fd, resp, sizeof resp, 0);
        if (r <= 0) continue;
        uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
        if (flags == VHAM_TAP_FLAG_ACK) continue;
        /* TAP-ACK echo */
        uint8_t ack[16];
        int an = vham_tap_build_ack_for(resp, (size_t)r, ack, sizeof ack);
        if (an > 0) send(vc->sig_fd, ack, (size_t)an, 0);
        /* Run through state machine */
        vham_cc_call_recv(&vc->call, resp, (size_t)r);
        if (vc->call.remote_media_port != 0) {
            if (vc->call.remote_media_ip == 0)
                vc->call.remote_media_ip = o->media_gw_ipv4;
            got_media = 1;
        }
        if (vc->call.state == VHAM_CALL_FAILED ||
            vc->call.state == VHAM_CALL_RELEASING) goto fail;
    }
    if (!got_media) goto fail;
    vc_phase(&vc_t0, &vc_prev, "got per-call port");

    /* ---- send CC_CONNACK ----------------------------------------- */
    {
        uint8_t ack_buf[256];
        int an = vham_cc_call_emit(&vc->call, NULL, 0,
                                   VHAM_CALL_HALF_DUPLEX, NULL,
                                   NULL, NULL, NULL, NULL,
                                   ack_buf, sizeof ack_buf);
        if (an > 0) send(vc->sig_fd, ack_buf, (size_t)an, 0);
    }

    /* ---- aim media socket at per-call port ----------------------- */
    vc->media_dst.sin_family      = AF_INET;
    vc->media_dst.sin_addr.s_addr = htonl(vc->call.remote_media_ip);
    vc->media_dst.sin_port        = htons(vc->call.remote_media_port);

    /* ---- claim the mic (mic_grant + user_ctrl + talking_id) ------ */
    {
        struct vc_send_ctx sctx = { vc->sig_fd };
        if (vham_cc_call_claim_mic(&vc->call, vc_send_cb, &sctx) != 0)
            goto fail;
    }
    vc_phase(&vc_t0, &vc_prev, "claim_mic sent");

    /* No post-mic drain — pump_frame() drains signaling on every
     * audio frame, so any leftover TAP-ACKs / CC_INFOACK after the
     * triplet get picked up there. Saves ~100 ms of setup latency. */

    /* Make sig_fd non-blocking for the pump phase (we drain it
     * opportunistically per audio frame, never want to stall). */
    int flags = fcntl(vc->sig_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(vc->sig_fd, F_SETFL, flags | O_NONBLOCK);

    /* ---- start media-channel NAT sentinel (3× + 2s tick) --------- */
    if (vham_media_nat_open(&vc->nat, vc->rtp_fd,
                            vc->call.remote_media_ip,
                            vc->call.remote_media_port) != 0)
        goto fail;

    /* ---- init RTP TX state + brief NAT-punch ---------------------
     * 2 back-to-back silence frames — the FF D3 01 sentinel sent by
     * vham_media_nat_open already created the NAT mapping; the silence
     * frames just confirm the RTP path is open. No usleep between
     * them — they go out immediately. */
    vham_codec_init();
    vham_voice_tx_init(&vc->tx, o->payload_type, (uint32_t)getpid());
    vham_voice_tx_set_mic(&vc->tx, 1);
    {
        int16_t *silence = calloc((size_t)o->samples_per_frame,
                                  sizeof(int16_t));
        if (silence) {
            uint8_t pkt[2048];
            for (int k = 0; k < 2; ++k) {
                int pn = vham_voice_tx_pcm_frame(&vc->tx, silence,
                                                 (size_t)o->samples_per_frame,
                                                 0, pkt, sizeof pkt);
                if (pn > 0)
                    sendto(vc->rtp_fd, pkt, (size_t)pn, 0,
                           (struct sockaddr *)&vc->media_dst,
                           sizeof vc->media_dst);
            }
            free(silence);
        }
    }

    vc_phase(&vc_t0, &vc_prev, "nat-punch done");
    vc->active = 1;
    return 0;

fail:
    if (vc->rtp_fd >= 0) { close(vc->rtp_fd); vc->rtp_fd = -1; }
    vc->active = 0;
    return -1;
}

int vham_voice_call_pump_frame(vham_voice_call_t *vc,
                               const int16_t *pcm, size_t n_samples,
                               int marker) {
    if (!vc || !vc->active) return -1;

    /* Encode + send the RTP packet. */
    uint8_t pkt[2048];
    int pn = vham_voice_tx_pcm_frame(&vc->tx, pcm, n_samples,
                                     (uint8_t)(marker ? 1 : 0),
                                     pkt, sizeof pkt);
    if (pn <= 0) return -1;
    ssize_t sn = sendto(vc->rtp_fd, pkt, (size_t)pn, 0,
                        (struct sockaddr *)&vc->media_dst,
                        sizeof vc->media_dst);
    if (sn != (ssize_t)pn) return -1;

    /* Drain incoming signaling. Auto-ACK every non-ACK, run through
     * state machine (which auto-updates remote_media_port on CC_MODIFY),
     * re-aim media_dst if the call moved. */
    uint8_t resp[2048];
    while (1) {
        ssize_t r = recv(vc->sig_fd, resp, sizeof resp, MSG_DONTWAIT);
        if (r <= 0) break;
        uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
        if (flags == VHAM_TAP_FLAG_ACK) continue;
        uint8_t ack[16];
        int an = vham_tap_build_ack_for(resp, (size_t)r, ack, sizeof ack);
        if (an > 0) send(vc->sig_fd, ack, (size_t)an, 0);
        vham_cc_call_recv(&vc->call, resp, (size_t)r);
        if (vc->call.state == VHAM_CALL_RELEASING ||
            vc->call.state == VHAM_CALL_RELEASED) return 0;
        /* Re-aim on redirect. */
        uint32_t new_ip   = vc->call.remote_media_ip;
        uint16_t new_port = vc->call.remote_media_port;
        if (new_port &&
            (new_ip   != ntohl(vc->media_dst.sin_addr.s_addr) ||
             new_port != ntohs(vc->media_dst.sin_port))) {
            vc->media_dst.sin_addr.s_addr = htonl(new_ip);
            vc->media_dst.sin_port        = htons(new_port);
        }
    }

    /* Re-send FF D3 01 if 2 s elapsed (CMediaTrans::Scan). */
    vham_media_nat_tick(&vc->nat);

    return 1;
}

void vham_voice_call_release(vham_voice_call_t *vc, uint32_t cause) {
    if (!vc) return;
    if (vc->active && vc->sig_fd >= 0) {
        (*vc->seq_no_ref)++;
        uint8_t buf[256];
        int n = vham_cc_call_release(&vc->call, cause, buf, sizeof buf);
        if (n > 0) send(vc->sig_fd, buf, (size_t)n, 0);
    }
    if (vc->rtp_fd >= 0) { close(vc->rtp_fd); vc->rtp_fd = -1; }
    vc->active = 0;
}
