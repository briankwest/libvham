/* libvham/test/mock_server.c — in-process server-side handler.
 *
 * Decodes a REGREQ, decides whether to challenge or accept, and
 * emits the appropriate REGRSP. This is a *minimal* implementation
 * that covers exactly the auth flow we use in tests.
 *
 * SPDX-License-Identifier: MIT
 */
#include "mock_server.h"
#include "vham/codec.h"
#include "../src/md5_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void mock_srv_init(mock_srv_t *s,
                   const char *username,
                   const char *password,
                   const char *realm,
                   const char *nonce) {
    memset(s, 0, sizeof *s);
    snprintf(s->username, sizeof s->username, "%s", username);
    snprintf(s->password, sizeof s->password, "%s", password);
    snprintf(s->realm,    sizeof s->realm,    "%s", realm);
    snprintf(s->nonce,    sizeof s->nonce,    "%s", nonce);
}

/* Build a REGRSP datagram. If `sub_opcode != 0`, the sub-opcode IE
 * 0x1e is set; if `cause != 0` the cause IE 0x40 is set. Auth IEs
 * are included whenever the corresponding string is non-NULL. */
static int build_regrsp(uint32_t seq_no,
                        uint16_t sub_opcode,
                        const char *algorithm,
                        const char *nonce,
                        const char *realm,
                        uint16_t cause,
                        void *out, size_t out_cap) {
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, 0))    return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, 0x0001)) return -1;
    if (vham_pack_u16(&b, VHAM_MM_REGRSP)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    /* SRVMSG header */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_MM_REGRSP,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* IEs */
    if (sub_opcode &&
        vham_pack_tlv_u16(&b, 1, VHAM_IE_SUB_OPCODE, sub_opcode))
        return -1;
    if (algorithm &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_ALGORITHM, algorithm))
        return -1;
    if (nonce &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_NONCE, nonce))
        return -1;
    if (realm &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_REALM, realm))
        return -1;
    if (cause) {
        char causebuf[8];
        snprintf(causebuf, sizeof causebuf, "%u", (unsigned)cause);
        if (vham_pack_tlv_str(&b, 1, VHAM_IE_CAUSE_NUM, causebuf)) return -1;
    }

    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}

/* Reproduce the digest the client should have computed. */
static void expected_response(const char *username, const char *realm,
                              const char *password, const char *nonce,
                              char out[33]) {
    /* HA1 = MD5(user:realm:password) */
    char ha1_hex[33], ha2_hex[33];
    {
        vham_md5_ctx_t c; uint8_t bin[16];
        vham_md5_init(&c);
        vham_md5_update(&c, username, strlen(username));
        vham_md5_update(&c, ":", 1);
        vham_md5_update(&c, realm, strlen(realm));
        vham_md5_update(&c, ":", 1);
        vham_md5_update(&c, password, strlen(password));
        vham_md5_final(&c, bin);
        vham_md5_hex(bin, ha1_hex);
    }
    /* HA2 = MD5("REGISTER:0.0.0.0") */
    {
        uint8_t bin[16];
        vham_md5("REGISTER:0.0.0.0", 16, bin);
        vham_md5_hex(bin, ha2_hex);
    }
    /* response = MD5(HA1:nonce:HA2) */
    {
        vham_md5_ctx_t c; uint8_t bin[16];
        vham_md5_init(&c);
        vham_md5_update(&c, ha1_hex, 32);
        vham_md5_update(&c, ":", 1);
        vham_md5_update(&c, nonce, strlen(nonce));
        vham_md5_update(&c, ":", 1);
        vham_md5_update(&c, ha2_hex, 32);
        vham_md5_final(&c, bin);
        vham_md5_hex(bin, out);
    }
}

int mock_srv_handle(mock_srv_t *s,
                    const void *in_buf, size_t in_len,
                    void *out, size_t out_cap) {
    /* Parse the incoming REGREQ */
    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(in_buf, in_len, &th, &sh, &rd) != 0) return -1;
    if (sh.wMsgId != VHAM_MM_REGREQ) return -1;

    s->regreqs_received++;

    /* Walk IEs to discover whether this is the initial or auth REGREQ */
    char         got_user[64] = {0};
    char         got_resp[64] = {0};
    char         got_nonce[64] = {0};
    char         got_realm[64] = {0};
    uint8_t      got_regtype = 0;
    int          have_response = 0;

    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_REG_TYPE:
            vham_ie_get_u8(&ie, &got_regtype);
            break;
        case VHAM_IE_IDENTITY_NUM: {
            const char *str = vham_ie_get_str(&ie);
            if (str) snprintf(got_user, sizeof got_user, "%s", str);
            break;
        }
        case VHAM_IE_AUTH_RESPONSE: {
            const char *str = vham_ie_get_str(&ie);
            if (str) {
                snprintf(got_resp, sizeof got_resp, "%s", str);
                have_response = 1;
            }
            break;
        }
        case VHAM_IE_AUTH_NONCE: {
            const char *str = vham_ie_get_str(&ie);
            if (str) snprintf(got_nonce, sizeof got_nonce, "%s", str);
            break;
        }
        case VHAM_IE_AUTH_REALM: {
            const char *str = vham_ie_get_str(&ie);
            if (str) snprintf(got_realm, sizeof got_realm, "%s", str);
            break;
        }
        }
    }
    if (rc != 0) return -1;
    if (got_regtype != VHAM_REGTYPE_USER) return -1;
    if (strcmp(got_user, s->username) != 0) {
        /* unknown user */
        s->saw_initial_regreq = !have_response;
        s->saw_auth_regreq    =  have_response;
        return build_regrsp(th.seq_no, 0, NULL, NULL, NULL,
                            1 /* cause: unknown user */,
                            out, out_cap);
    }

    if (!have_response) {
        /* Initial REGREQ → emit challenge */
        s->saw_initial_regreq = 1;
        return build_regrsp(th.seq_no, 0x0053,
                            "MD5", s->nonce, s->realm,
                            0, out, out_cap);
    }

    /* Auth REGREQ → verify response */
    s->saw_auth_regreq = 1;
    if (strcmp(got_nonce, s->nonce) != 0 ||
        strcmp(got_realm, s->realm) != 0) {
        return build_regrsp(th.seq_no, 0, NULL, NULL, NULL,
                            2 /* cause: stale nonce */,
                            out, out_cap);
    }
    char want[33];
    expected_response(s->username, s->realm, s->password, s->nonce, want);
    if (strcmp(want, got_resp) != 0) {
        return build_regrsp(th.seq_no, 0, NULL, NULL, NULL,
                            3 /* cause: auth failed */,
                            out, out_cap);
    }
    /* Success */
    return build_regrsp(th.seq_no, 0, NULL, NULL, NULL,
                        0 /* no cause = success */,
                        out, out_cap);
}
