/* libvham/src/srtp_openssl.c — DTLS-SRTP via OpenSSL + libsrtp.
 *
 * Built only when VHAM_WITH_DTLS_OPENSSL is defined.
 *
 * OpenSSL ≥ 1.1 is required (1.0 had a different `SSL_CTX_set_tlsext_use_srtp`
 * signature). 3.x preferred.
 *
 * Architecture mirrors srtp_mbedtls.c: the DTLS context runs on a
 * virtual transport built from two memory BIOs. Caller drives the
 * handshake by:
 *   1. `vham_srtp_open()` — creates DTLS context, starts handshake
 *   2. `vham_srtp_pop_outbound(out, cap)` — drain bytes OpenSSL wants
 *      to put on the wire; send them to peer over UDP
 *   3. when a peer datagram arrives, `vham_srtp_unprotect(in, len, ...)`
 *      routes it: if it's DTLS (records 0x14..0x17) it goes back into
 *      the SSL engine; if it's SRTP, libsrtp decrypts.
 *
 * After handshake the SRTP keys are derived via RFC 5705 keying
 * material exporter (`SSL_export_keying_material`) using the label
 * "EXTRACTOR-dtls_srtp" per RFC 5764 §4.2.
 *
 * SPDX-License-Identifier: MIT
 */
#ifdef VHAM_WITH_DTLS_OPENSSL

#include "vham/srtp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/srtp.h>

#include <srtp2/srtp.h>

struct vham_srtp_session {
    SSL_CTX  *ctx;
    SSL      *ssl;
    BIO      *rbio;        /* incoming DTLS bytes go in here */
    BIO      *wbio;        /* outgoing DTLS bytes get queued here */
    int       role;        /* 0=active (client), 1=passive (server) */
    int       handshake_done;

    uint8_t   srtp_key[60];   /* RFC 5764 keying material:
                               * 16-byte client key + 16-byte server key +
                               * 14-byte client salt + 14-byte server salt */
    srtp_t    srtp_tx;
    srtp_t    srtp_rx;
};

static int g_srtp_init_done;

static void log_ssl_errors(const char *label) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof buf);
        fprintf(stderr, "  openssl: %s: %s\n", label, buf);
    }
}

vham_srtp_session_t *vham_srtp_open(const char *cert_pem,
                                    const char *key_pem,
                                    int role) {
    if (!cert_pem || !key_pem) return NULL;

    if (!g_srtp_init_done) {
        if (srtp_init() != srtp_err_status_ok) return NULL;
        g_srtp_init_done = 1;
    }

    /* One-time OpenSSL init is implicit since 1.1 — no calls needed. */

    vham_srtp_session_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->role = role;

    s->ctx = SSL_CTX_new(DTLS_method());
    if (!s->ctx) { vham_srtp_close(s); return NULL; }

    /* Minimum protocol — DTLS 1.0 is the floor for SRTP_AES128_CM_SHA1_80
     * interop, but we'll request 1.2 as the floor since 1.0 is dead. */
    SSL_CTX_set_min_proto_version(s->ctx, DTLS1_2_VERSION);

    /* Cert + key from PEM strings (no on-disk files needed). */
    BIO *cb = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = cb ? PEM_read_bio_X509(cb, NULL, NULL, NULL) : NULL;
    if (cb) BIO_free(cb);
    if (!cert || SSL_CTX_use_certificate(s->ctx, cert) != 1) {
        log_ssl_errors("use_certificate");
        if (cert) X509_free(cert);
        vham_srtp_close(s); return NULL;
    }
    X509_free(cert);

    BIO *kb = BIO_new_mem_buf(key_pem, -1);
    EVP_PKEY *pkey = kb ? PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL) : NULL;
    if (kb) BIO_free(kb);
    if (!pkey || SSL_CTX_use_PrivateKey(s->ctx, pkey) != 1) {
        log_ssl_errors("use_PrivateKey");
        if (pkey) EVP_PKEY_free(pkey);
        vham_srtp_close(s); return NULL;
    }
    EVP_PKEY_free(pkey);

    /* WebRTC-style: peer cert is fingerprinted out-of-band via SDP;
     * we don't do chain validation here. */
    SSL_CTX_set_verify(s->ctx, SSL_VERIFY_NONE, NULL);

    /* DTLS-SRTP profile — mandatory-to-implement per RFC 5764. */
    if (SSL_CTX_set_tlsext_use_srtp(s->ctx,
                                    "SRTP_AES128_CM_SHA1_80") != 0) {
        log_ssl_errors("set_tlsext_use_srtp");
        vham_srtp_close(s); return NULL;
    }

    s->ssl = SSL_new(s->ctx);
    if (!s->ssl) { vham_srtp_close(s); return NULL; }

    /* Virtual transport — incoming DTLS goes into rbio, outgoing
     * accumulates in wbio. */
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());
    if (!s->rbio || !s->wbio) { vham_srtp_close(s); return NULL; }
    /* mem BIOs return "want read" rather than EOF on empty input. */
    BIO_set_mem_eof_return(s->rbio, -1);
    BIO_set_mem_eof_return(s->wbio, -1);
    SSL_set_bio(s->ssl, s->rbio, s->wbio);
    /* After SSL_set_bio, the SSL owns the BIOs — null our refs to
     * avoid double-free in vham_srtp_close(). */
    s->rbio = NULL;
    s->wbio = NULL;

    if (role == 1) SSL_set_accept_state (s->ssl);
    else           SSL_set_connect_state(s->ssl);

    /* Drive the first handshake step so the ClientHello (active role)
     * is queued in wbio. Caller will retrieve it via pop_outbound. */
    SSL_do_handshake(s->ssl);  /* return code irrelevant — WANT_READ is fine */
    return s;
}

void vham_srtp_close(vham_srtp_session_t *s) {
    if (!s) return;
    if (s->srtp_tx) srtp_dealloc(s->srtp_tx);
    if (s->srtp_rx) srtp_dealloc(s->srtp_rx);
    if (s->ssl)  SSL_free(s->ssl);          /* also frees the attached BIOs */
    if (s->ctx)  SSL_CTX_free(s->ctx);
    free(s);
}

/* Derive SRTP keys from the just-completed DTLS handshake and create
 * the two libsrtp contexts. */
static int setup_srtp(vham_srtp_session_t *s) {
    /* RFC 5764 §4.2: PRF over master secret with label
     * "EXTRACTOR-dtls_srtp" and empty context, output 60 bytes for the
     * AES_CM_128_HMAC_SHA1_80 profile. */
    if (SSL_export_keying_material(s->ssl, s->srtp_key, sizeof s->srtp_key,
                                   "EXTRACTOR-dtls_srtp",
                                   strlen("EXTRACTOR-dtls_srtp"),
                                   NULL, 0, 0) != 1) {
        log_ssl_errors("export_keying_material");
        return -1;
    }

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
    if (s->role == 0) { tx.key = client_key; rx.key = server_key; }
    else              { tx.key = server_key; rx.key = client_key; }
    if (srtp_create(&s->srtp_tx, &tx) != srtp_err_status_ok) return -1;
    if (srtp_create(&s->srtp_rx, &rx) != srtp_err_status_ok) return -1;
    return 0;
}

/* Pump the handshake state machine until WANT_READ. Returns 0 on
 * partial progress, 1 if handshake completed (and SRTP set up), -1
 * on hard error. */
static int drive_handshake(vham_srtp_session_t *s) {
    if (s->handshake_done) return 1;
    int rc = SSL_do_handshake(s->ssl);
    if (rc == 1) {
        if (setup_srtp(s) != 0) return -1;
        s->handshake_done = 1;
        return 1;
    }
    int err = SSL_get_error(s->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
    log_ssl_errors("do_handshake");
    return -1;
}

int vham_srtp_unprotect(vham_srtp_session_t *s,
                        const void *in, size_t in_len,
                        uint8_t *out, size_t out_cap) {
    if (!s || !in || in_len == 0) return -1;
    const uint8_t *b = (const uint8_t *)in;
    /* DTLS records: ContentType in 20..23 (0x14..0x17) */
    int is_dtls = (b[0] >= 0x14 && b[0] <= 0x17);
    if (is_dtls) {
        /* Feed the SSL engine via its read BIO. */
        BIO *rb = SSL_get_rbio(s->ssl);
        BIO_write(rb, in, (int)in_len);
        drive_handshake(s);
        return 0;
    }
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
    BIO *wb = SSL_get_wbio(s->ssl);
    if (!wb) return 0;
    int pending = BIO_pending(wb);
    if (pending <= 0) return 0;
    int take = pending < (int)out_cap ? pending : (int)out_cap;
    int n = BIO_read(wb, out, take);
    return n < 0 ? 0 : n;
}

int vham_srtp_protect(vham_srtp_session_t *s,
                      const void *rtp, size_t rtp_len,
                      uint8_t *out, size_t out_cap) {
    if (!s || !rtp || !out) return -1;
    if (!s->srtp_tx) return -1;
    /* libsrtp grows the buffer by up to SRTP_MAX_TRAILER_LEN (10
     * with default cipher). Caller must supply room. */
    if (rtp_len + 16 > out_cap) return -1;
    memcpy(out, rtp, rtp_len);
    int len = (int)rtp_len;
    if (srtp_protect(s->srtp_tx, out, &len) != srtp_err_status_ok)
        return -1;
    return len;
}

int vham_srtp_handshake_done(const vham_srtp_session_t *s) {
    if (!s) return 0;
    return s->handshake_done && s->srtp_tx != NULL;
}

int vham_srtp_available(void) { return 1; }

#endif /* VHAM_WITH_DTLS_OPENSSL */
