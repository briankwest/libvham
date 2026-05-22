/* libvham/src/srtp.c — DTLS-SRTP dispatcher / fallback stub.
 *
 * The real implementation lives in one of:
 *   - src/srtp_mbedtls.c  (build flag VHAM_WITH_DTLS_MBEDTLS)
 *   - src/srtp_openssl.c  (build flag VHAM_WITH_DTLS_OPENSSL)
 *
 * Exactly one of those is compiled in when DTLS-SRTP is enabled at
 * configure time. This file provides the fallback "no DTLS available"
 * stub when neither was selected — defined as weak symbols so the
 * real backend overrides them when present.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/srtp.h"

#if !defined(VHAM_WITH_DTLS_MBEDTLS) && !defined(VHAM_WITH_DTLS_OPENSSL)

vham_srtp_session_t *vham_srtp_open(const char *cert_pem,
                                    const char *key_pem,
                                    int role) {
    (void)cert_pem; (void)key_pem; (void)role;
    return NULL;
}
void vham_srtp_close(vham_srtp_session_t *s) { (void)s; }
int  vham_srtp_unprotect(vham_srtp_session_t *s,
                         const void *in, size_t in_len,
                         uint8_t *out, size_t out_cap) {
    (void)s; (void)in; (void)in_len; (void)out; (void)out_cap;
    return -1;
}
int  vham_srtp_pop_outbound(vham_srtp_session_t *s,
                            uint8_t *out, size_t out_cap) {
    (void)s; (void)out; (void)out_cap;
    return 0;
}
int  vham_srtp_protect(vham_srtp_session_t *s,
                       const void *rtp, size_t rtp_len,
                       uint8_t *out, size_t out_cap) {
    (void)s; (void)rtp; (void)rtp_len; (void)out; (void)out_cap;
    return -1;
}
int  vham_srtp_handshake_done(const vham_srtp_session_t *s) {
    (void)s; return 0;
}
int  vham_srtp_available(void) { return 0; }

#endif /* neither backend selected */
