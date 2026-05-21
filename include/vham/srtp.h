/* libvham/include/vham/srtp.h — DTLS-SRTP interface (stub).
 *
 * Full DTLS-SRTP / ICE / STUN support requires linking libsrtp +
 * mbedtls (or OpenSSL). The implementation is gated behind
 * VHAM_WITH_DTLS; without it, every operation returns -1 and the
 * header serves as the API contract for callers.
 *
 * Useful when this matters: WebRTC interop. The protocol's SDP
 * template lists `UDP/TLS/RTP/SAVPF` for media but the flows we
 * decoded never use it — so this is genuinely optional for
 * normal PoC operation.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_SRTP_H
#define VHAM_SRTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vham_srtp_session vham_srtp_session_t;

/* Initialize a DTLS-SRTP session.
 *   cert_pem / key_pem  — local cert and private key
 *   role                — 0 = active (client), 1 = passive (server)
 *
 * Returns a session handle (or NULL when DTLS support isn't compiled in). */
vham_srtp_session_t *vham_srtp_open(const char *cert_pem,
                                    const char *key_pem,
                                    int role);

void vham_srtp_close(vham_srtp_session_t *s);

/* Feed a UDP datagram. The implementation routes DTLS handshake
 * traffic to mbedtls and SRTP traffic to libsrtp.
 *
 * Returns:
 *    >0  cleartext RTP/RTCP bytes copied into out (subsequent media
 *        processing should consume these instead of the original frame)
 *     0  packet was DTLS handshake — no media bytes for caller
 *    -1  error / not built / drop */
int vham_srtp_unprotect(vham_srtp_session_t *s,
                        const void *in, size_t in_len,
                        uint8_t *out, size_t out_cap);

/* Drain any DTLS handshake bytes the implementation wants to send.
 * Call this after every recv during handshake until it returns 0.
 *   >0  bytes copied into `out`, send to peer
 *    0  nothing pending
 *   -1  error / handshake failed */
int vham_srtp_pop_outbound(vham_srtp_session_t *s,
                           uint8_t *out, size_t out_cap);

/* Protect (encrypt) outgoing RTP/RTCP. Only valid after handshake
 * is done. Returns bytes written, -1 on error or unbuilt. */
int vham_srtp_protect(vham_srtp_session_t *s,
                      const void *rtp, size_t rtp_len,
                      uint8_t *out, size_t out_cap);

/* Returns 1 once DTLS handshake completed and SRTP is ready. */
int vham_srtp_handshake_done(const vham_srtp_session_t *s);

/* Returns 1 if libvham was built with VHAM_WITH_DTLS, 0 otherwise. */
int vham_srtp_available(void);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_SRTP_H */
