/* libvham/src/srtp.c — DTLS-SRTP via mbedtls + libsrtp.
 *
 * Real implementation (when built with VHAM_WITH_DTLS). Provides:
 *   - DTLS handshake over a virtual transport — caller feeds incoming
 *     datagrams and drains outbound ones, no socket I/O inside the
 *     library
 *   - SRTP key derivation per RFC 5764 §4.2
 *   - srtp_protect / srtp_unprotect via libsrtp
 *
 * Supported profile: AES_CM_128_HMAC_SHA1_80 (mandatory-to-implement).
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/srtp.h"

#ifndef VHAM_WITH_DTLS

/* ----------------- stub build (no DTLS) ----------------- */
vham_srtp_session_t *vham_srtp_open(const char *c, const char *k, int r) {
    (void)c; (void)k; (void)r; return NULL;
}
void vham_srtp_close(vham_srtp_session_t *s) { (void)s; }
int  vham_srtp_unprotect(vham_srtp_session_t *s, const void *i, size_t l,
                         uint8_t *o, size_t c) {
    (void)s; (void)i; (void)l; (void)o; (void)c; return -1;
}
int  vham_srtp_pop_outbound(vham_srtp_session_t *s, uint8_t *o, size_t c) {
    (void)s; (void)o; (void)c; return 0;
}
int  vham_srtp_protect(vham_srtp_session_t *s, const void *r, size_t l,
                       uint8_t *o, size_t c) {
    (void)s; (void)r; (void)l; (void)o; (void)c; return -1;
}
int  vham_srtp_handshake_done(const vham_srtp_session_t *s) { (void)s; return 0; }
int  vham_srtp_available(void) { return 0; }

#else   /* VHAM_WITH_DTLS — real implementation below */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/timing.h>
#include <mbedtls/error.h>

#include <srtp2/srtp.h>

/* In-flight buffers for the DTLS virtual transport. */
#define INFLIGHT_BUF_MAX  16384

struct vham_srtp_session {
    /* mbedtls state */
    mbedtls_ssl_context        ssl;
    mbedtls_ssl_config         conf;
    mbedtls_x509_crt           cert;
    mbedtls_pk_context         pkey;
    mbedtls_entropy_context    entropy;
    mbedtls_ctr_drbg_context   ctr_drbg;
    mbedtls_timing_delay_context timer;

    /* Virtual transport: bytes flowing through the DTLS layer. */
    uint8_t  inbox[INFLIGHT_BUF_MAX];   /* incoming DTLS records */
    size_t   inbox_len;
    uint8_t  outbox[INFLIGHT_BUF_MAX];  /* outgoing DTLS records */
    size_t   outbox_len;

    /* SRTP keying material derived from DTLS export. */
    uint8_t  srtp_key[60];               /* 30 bytes local + 30 remote */
    int      srtp_ready;

    /* libsrtp contexts (one per direction). */
    srtp_t   srtp_tx;
    srtp_t   srtp_rx;
    int      role;                       /* 0=active, 1=passive */
};

/* mbedtls BIO callbacks bridging to the inbox/outbox. */
static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    vham_srtp_session_t *s = (vham_srtp_session_t *)ctx;
    if (s->outbox_len + len > sizeof s->outbox) return -1;
    memcpy(s->outbox + s->outbox_len, buf, len);
    s->outbox_len += len;
    return (int)len;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    vham_srtp_session_t *s = (vham_srtp_session_t *)ctx;
    if (s->inbox_len == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t take = s->inbox_len < len ? s->inbox_len : len;
    memcpy(buf, s->inbox, take);
    memmove(s->inbox, s->inbox + take, s->inbox_len - take);
    s->inbox_len -= take;
    return (int)take;
}

/* DTLS-SRTP key export callback (RFC 5705 / RFC 5764). After the
 * handshake, mbedtls fires this once with master_secret + randoms
 * we can use to derive SRTP keys. */
static void export_keys_cb(void *p_expkey,
                           mbedtls_ssl_key_export_type type,
                           const unsigned char *secret, size_t secret_len,
                           const unsigned char client_random[32],
                           const unsigned char server_random[32],
                           mbedtls_tls_prf_types tls_prf_type) {
    if (type != MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET) return;
    vham_srtp_session_t *s = (vham_srtp_session_t *)p_expkey;
    /* SRTP keying material derivation per RFC 5764 §4.2:
     *   PRF(master_secret, "EXTRACTOR-dtls_srtp",
     *       client_random + server_random) — 60 bytes for
     *       AES_CM_128_HMAC_SHA1_80 (2 * (16 key + 14 salt)). */
    unsigned char seed[64];
    memcpy(seed,      client_random, 32);
    memcpy(seed + 32, server_random, 32);
    int rc = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len,
                                 "EXTRACTOR-dtls_srtp",
                                 seed, sizeof seed,
                                 s->srtp_key, sizeof s->srtp_key);
    if (rc == 0) s->srtp_ready = 1;
}

/* The mandatory-to-implement SRTP profile per RFC 5764. */
static const mbedtls_ssl_srtp_profile srtp_profiles[] = {
    MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
    MBEDTLS_TLS_SRTP_UNSET,
};

/* libsrtp global init guard. */
static int g_srtp_init_done;

vham_srtp_session_t *vham_srtp_open(const char *cert_pem,
                                    const char *key_pem,
                                    int role) {
    if (!cert_pem || !key_pem) return NULL;

    if (!g_srtp_init_done) {
        if (srtp_init() != srtp_err_status_ok) return NULL;
        g_srtp_init_done = 1;
    }

    vham_srtp_session_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->role = role;

    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->cert);
    mbedtls_pk_init(&s->pkey);
    mbedtls_entropy_init(&s->entropy);
    mbedtls_ctr_drbg_init(&s->ctr_drbg);

    const char *pers = "vham-srtp";
    if (mbedtls_ctr_drbg_seed(&s->ctr_drbg, mbedtls_entropy_func,
                              &s->entropy, (const unsigned char *)pers,
                              strlen(pers)) != 0) goto fail;

    /* Load cert + key (PEM). */
    if (mbedtls_x509_crt_parse(&s->cert,
            (const unsigned char *)cert_pem, strlen(cert_pem) + 1) != 0)
        goto fail;
    if (mbedtls_pk_parse_key(&s->pkey,
            (const unsigned char *)key_pem, strlen(key_pem) + 1,
            NULL, 0,
            mbedtls_ctr_drbg_random, &s->ctr_drbg) != 0)
        goto fail;

    int endpoint = role == 1 ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;
    if (mbedtls_ssl_config_defaults(&s->conf,
            endpoint,
            MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            MBEDTLS_SSL_PRESET_DEFAULT) != 0) goto fail;

    /* For WebRTC-style PoC, each side validates the peer's fingerprint
     * out-of-band via SDP — full chain validation is typically off. */
    mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->ctr_drbg);

    if (mbedtls_ssl_conf_own_cert(&s->conf, &s->cert, &s->pkey) != 0)
        goto fail;

    if (mbedtls_ssl_conf_dtls_srtp_protection_profiles(&s->conf,
            srtp_profiles) != 0) goto fail;

    if (mbedtls_ssl_setup(&s->ssl, &s->conf) != 0) goto fail;

    mbedtls_ssl_set_bio(&s->ssl, s, bio_send, bio_recv, NULL);
    mbedtls_ssl_set_timer_cb(&s->ssl, &s->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);
    mbedtls_ssl_set_export_keys_cb(&s->ssl, export_keys_cb, s);

    /* Drive the first handshake step so initial ClientHello / wait
     * is queued in the outbox (for active role). */
    int rc = mbedtls_ssl_handshake_step(&s->ssl);
    if (rc != 0 && rc != MBEDTLS_ERR_SSL_WANT_READ &&
        rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
        /* Hello-verify cookie path triggers WANT_READ; anything else
         * before we've heard from the peer is fine. */
    }
    return s;

fail:
    vham_srtp_close(s);
    return NULL;
}

void vham_srtp_close(vham_srtp_session_t *s) {
    if (!s) return;
    if (s->srtp_tx) srtp_dealloc(s->srtp_tx);
    if (s->srtp_rx) srtp_dealloc(s->srtp_rx);
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    mbedtls_x509_crt_free(&s->cert);
    mbedtls_pk_free(&s->pkey);
    mbedtls_ctr_drbg_free(&s->ctr_drbg);
    mbedtls_entropy_free(&s->entropy);
    free(s);
}

/* Install libsrtp contexts using the keying material we just exported. */
static int setup_srtp(vham_srtp_session_t *s) {
    /* RFC 5764 §4.2 key layout for AES_CM_128_HMAC_SHA1_80:
     *   bytes  0..15  : client write key   (16)
     *   bytes 16..31  : server write key   (16)
     *   bytes 32..45  : client write salt  (14)
     *   bytes 46..59  : server write salt  (14)
     */
    uint8_t client_key[16+14], server_key[16+14];
    memcpy(client_key,      s->srtp_key + 0,  16);
    memcpy(client_key + 16, s->srtp_key + 32, 14);
    memcpy(server_key,      s->srtp_key + 16, 16);
    memcpy(server_key + 16, s->srtp_key + 46, 14);

    srtp_policy_t tx = {0}, rx = {0};
    srtp_crypto_policy_set_rtp_default(&tx.rtp);
    srtp_crypto_policy_set_rtcp_default(&tx.rtcp);
    srtp_crypto_policy_set_rtp_default(&rx.rtp);
    srtp_crypto_policy_set_rtcp_default(&rx.rtcp);
    tx.ssrc.type = ssrc_any_outbound;
    rx.ssrc.type = ssrc_any_inbound;
    /* Active (client) writes with client_key, passive with server_key. */
    if (s->role == 0) {                  /* active = client */
        tx.key = client_key;
        rx.key = server_key;
    } else {
        tx.key = server_key;
        rx.key = client_key;
    }
    if (srtp_create(&s->srtp_tx, &tx) != srtp_err_status_ok) return -1;
    if (srtp_create(&s->srtp_rx, &rx) != srtp_err_status_ok) return -1;
    return 0;
}

/* Continue the handshake until it makes no more progress. */
static int drive_handshake(vham_srtp_session_t *s) {
    while (s->ssl.MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_HANDSHAKE_OVER) {
        int rc = mbedtls_ssl_handshake_step(&s->ssl);
        if (rc == 0) continue;
        if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
            rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
        return rc;
    }
    if (!s->srtp_ready) return -1;
    if (s->srtp_tx == NULL) {
        if (setup_srtp(s) != 0) return -1;
    }
    return 0;
}

int vham_srtp_unprotect(vham_srtp_session_t *s,
                        const void *in, size_t in_len,
                        uint8_t *out, size_t out_cap) {
    if (!s || !in || in_len == 0) return -1;
    const uint8_t *b = (const uint8_t *)in;

    /* DTLS records start with 0x14..0x17. RTP starts with 0x80/0x90. */
    int is_dtls = (b[0] >= 0x14 && b[0] <= 0x17);
    if (is_dtls) {
        if (s->inbox_len + in_len > sizeof s->inbox) return -1;
        memcpy(s->inbox + s->inbox_len, in, in_len);
        s->inbox_len += in_len;
        drive_handshake(s);
        return 0;
    }

    /* SRTP path. */
    if (!s->srtp_rx) return -1;
    if (in_len > out_cap) return -1;
    memcpy(out, in, in_len);
    int len = (int)in_len;
    if (srtp_unprotect(s->srtp_rx, out, &len) != srtp_err_status_ok)
        return -1;
    return len;
}

int vham_srtp_pop_outbound(vham_srtp_session_t *s,
                           uint8_t *out, size_t out_cap) {
    if (!s || !out) return -1;
    if (s->outbox_len == 0) return 0;
    size_t take = s->outbox_len < out_cap ? s->outbox_len : out_cap;
    memcpy(out, s->outbox, take);
    memmove(s->outbox, s->outbox + take, s->outbox_len - take);
    s->outbox_len -= take;
    return (int)take;
}

int vham_srtp_protect(vham_srtp_session_t *s,
                      const void *rtp, size_t rtp_len,
                      uint8_t *out, size_t out_cap) {
    if (!s || !rtp || !out) return -1;
    if (!s->srtp_tx) return -1;
    /* libsrtp grows the buffer by up to SRTP_MAX_TRAILER_LEN (10 for
     * default cipher). Caller must supply room. */
    if (rtp_len + 16 > out_cap) return -1;
    memcpy(out, rtp, rtp_len);
    int len = (int)rtp_len;
    if (srtp_protect(s->srtp_tx, out, &len) != srtp_err_status_ok)
        return -1;
    return len;
}

int vham_srtp_handshake_done(const vham_srtp_session_t *s) {
    if (!s) return 0;
    return s->srtp_ready && s->srtp_tx != NULL;
}

int vham_srtp_available(void) { return 1; }

#endif /* VHAM_WITH_DTLS */
