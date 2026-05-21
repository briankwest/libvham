/* libvham/src/auth.c — RFC 2617 HTTP Digest, bit-for-bit compatible
 * with IDS_AuthMD5_Calc (Ghidra 0x23d9f0).
 *
 *   HA1 = MD5(username : realm : password)
 *   if (algorithm == "md5-sess")
 *       HA1 = MD5(HA1_bytes : nonce : cnonce)
 *   HA1_hex = lowercase_hex(HA1)
 *
 *   HA2 = MD5(method : uri)
 *   HA2_hex = lowercase_hex(HA2)
 *
 *   if (qop != NULL)
 *       response = MD5(HA1_hex : nonce : nc : cnonce : qop : HA2_hex)
 *   else
 *       response = MD5(HA1_hex : nonce : HA2_hex)
 *
 * For the registration flow exercised by libsvcapi.so, method is
 * always "REGISTER", uri is always "0.0.0.0", and qop/cnonce/nc are
 * NULL — so the response collapses to
 *
 *   response = MD5( MD5(user:realm:pw) : nonce : MD5("REGISTER:0.0.0.0") )
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/codec.h"
#include "md5_internal.h"
#include <string.h>

static void hash_str(vham_md5_ctx_t *c, const char *s) {
    if (s) vham_md5_update(c, s, strlen(s));
}

int vham_auth_md5(const char *username,
                  const char *realm,
                  const char *password,
                  const char *method,
                  const char *algorithm,
                  const char *nonce,
                  const char *cnonce,
                  const char *nc,
                  const char *uri,
                  const char *qop,
                  char       *response_out) {
    if (!username || !realm || !password || !method || !nonce || !uri ||
        !response_out) {
        return -1;
    }

    /* HA1 = MD5(username : realm : password) */
    vham_md5_ctx_t c;
    uint8_t ha1_bin[16];
    char    ha1_hex[33];

    vham_md5_init(&c);
    hash_str(&c, username);
    vham_md5_update(&c, ":", 1);
    hash_str(&c, realm);
    vham_md5_update(&c, ":", 1);
    hash_str(&c, password);
    vham_md5_final(&c, ha1_bin);

    if (algorithm && strcmp(algorithm, "md5-sess") == 0) {
        if (!cnonce) return -1;
        vham_md5_init(&c);
        vham_md5_update(&c, ha1_bin, 16);
        vham_md5_update(&c, ":", 1);
        hash_str(&c, nonce);
        vham_md5_update(&c, ":", 1);
        hash_str(&c, cnonce);
        vham_md5_final(&c, ha1_bin);
    }
    vham_md5_hex(ha1_bin, ha1_hex);

    /* HA2 = MD5(method : uri) */
    uint8_t ha2_bin[16];
    char    ha2_hex[33];
    vham_md5_init(&c);
    hash_str(&c, method);
    vham_md5_update(&c, ":", 1);
    hash_str(&c, uri);
    vham_md5_final(&c, ha2_bin);
    vham_md5_hex(ha2_bin, ha2_hex);

    /* response = MD5(HA1_hex : nonce [: nc : cnonce : qop] : HA2_hex) */
    uint8_t r_bin[16];
    vham_md5_init(&c);
    vham_md5_update(&c, ha1_hex, 32);
    vham_md5_update(&c, ":", 1);
    hash_str(&c, nonce);
    vham_md5_update(&c, ":", 1);
    if (qop) {
        hash_str(&c, nc);
        vham_md5_update(&c, ":", 1);
        hash_str(&c, cnonce);
        vham_md5_update(&c, ":", 1);
        hash_str(&c, qop);
        vham_md5_update(&c, ":", 1);
    }
    vham_md5_update(&c, ha2_hex, 32);
    vham_md5_final(&c, r_bin);
    vham_md5_hex(r_bin, response_out);
    return 0;
}
