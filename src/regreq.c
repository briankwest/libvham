/* libvham/src/regreq.c — encode MM_REGREQ.
 *
 * Mirrors MM::SendRegReq + TAP::SendMsgToNet from libsvcapi.so.
 * See protocol-spec/04-mm-regreq.md for the rationale of each IE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/regreq.h"
#include <string.h>

/* _TLV_NUMBER_s — verified wire form (SrvPackNum @ 0x2657e0): the
 * struct's first u16 is a presence flag; the string lives at offset
 * +4 and is emitted as `[u16 tag][u16 strlen+1][string][NUL]`. There
 * are no inner sub-TLVs on the wire. The JSON schema
 * `{"Code","Type","UtSn","Sn"}` is in-memory only and used by
 * higher-level helpers; the on-wire payload is just `Sn`.
 *
 * In other words: SrvPackNum(tag, num) == PPackTLVStr(tag, num.Sn).
 */
static int emit_number_ie(vham_buf_t *b, uint16_t tag, const char *sn) {
    if (!sn || !*sn) return 0;
    return vham_pack_tlv_str(b, 1, tag, sn);
}

/* PIpAddr — 8 bytes, all LITTLE-endian. Verified against the live
 * 47.253.13.238 server's REGRSP, which emits IE 0x24 as:
 *   ee 0d fd 2f   d9 27   00 00
 *   <ipv4 LE>     <port LE> <fam+pad>
 *   = 47.253.13.238 : 10201
 *
 * MM::SendRegReq does a straight `*(u32*) = *(u32*)` copy of the
 * server address (no byte-swap), so the wire format is whatever
 * host-byte-order the binary was compiled for — LE on ARM/x86.
 *
 * Family + pad bytes are both zero (we previously guessed 0x02 for
 * AF_INET; the actual wire value is 0x00). */
static void encode_pipaddr(uint8_t out[8], uint32_t ipv4_host,
                           uint16_t port_host) {
    out[0] = (uint8_t)(ipv4_host);
    out[1] = (uint8_t)(ipv4_host >>  8);
    out[2] = (uint8_t)(ipv4_host >> 16);
    out[3] = (uint8_t)(ipv4_host >> 24);
    out[4] = (uint8_t)(port_host);
    out[5] = (uint8_t)(port_host >> 8);
    out[6] = 0x00;
    out[7] = 0x00;
}

int vham_build_regreq(const vham_regreq_t *p, void *out, size_t out_cap) {
    if (!p || !out) return -1;
    if (out_cap < 32) return -1;

    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header — body_len patched later */
    if (vham_pack_u8(&b, 0x01)) return -1;
    if (vham_pack_u8(&b, 0x00)) return -1;
    if (vham_pack_u16(&b, 0x0000)) return -1;
    if (vham_pack_u32(&b, p->seq_no)) return -1;
    if (vham_pack_u16(&b, 0x0001)) return -1;       /* class = 1 */
    if (vham_pack_u16(&b, VHAM_MM_REGREQ)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;            /* placeholder */
    size_t body_start = b.off;

    /* SRVMSG header */
    vham_srvmsg_hdr_t sh = {
        .ucDst      = VHAM_MOD_MM,
        .ucSrc      = VHAM_MOD_MM,
        .wMsgId     = VHAM_MM_REGREQ,
        .dwDstFsmId = 0xffffffff,
        .dwSrcFsmId = 0xffffffff,
        .dwMsgLen   = 0,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* --- IEs --- */

    /* IE 0x1d — RegType */
    if (vham_pack_tlv_u8(&b, 1, VHAM_IE_REG_TYPE, p->reg_type)) return -1;

    /* IE 0x37 — feature mask */
    uint32_t mask = p->feature_mask ? p->feature_mask : 0x00000098u;
    if (vham_pack_tlv_u32(&b, 1, VHAM_IE_FEATURE_MASK, mask)) return -1;

    /* IE 0x24 — server PIpAddr (DataFix 8B) */
    uint8_t pip[8];
    encode_pipaddr(pip, p->server_ipv4, p->server_port);
    if (vham_pack_tlv_fix(&b, 1, VHAM_IE_SERVER_ADDR, pip, 8)) return -1;

    /* IE 0x27 — identity number */
    if (emit_number_ie(&b, VHAM_IE_IDENTITY_NUM, p->username)) return -1;

    /* IE 0x85 — self number */
    if (emit_number_ie(&b, VHAM_IE_SELF_NUM, p->self_num)) return -1;

    /* Auth-response phase: echo algorithm/nonce/realm + add response.
     *
     * Per MM::SendRegReq(param_2=1), each IE is only emitted if its
     * presence flag in the CP state was set — i.e. if the server
     * actually sent that IE in the REGRSP challenge. We replicate
     * that by skipping IEs whose string is empty. */
    if (p->auth_response_hex && *p->auth_response_hex) {
        if (vham_pack_tlv_str(&b,
                p->auth_algorithm && *p->auth_algorithm,
                VHAM_IE_AUTH_ALGORITHM, p->auth_algorithm)) return -1;
        if (vham_pack_tlv_str(&b,
                p->auth_nonce && *p->auth_nonce,
                VHAM_IE_AUTH_NONCE, p->auth_nonce)) return -1;
        if (vham_pack_tlv_str(&b,
                p->auth_realm && *p->auth_realm,
                VHAM_IE_AUTH_REALM, p->auth_realm)) return -1;
        if (vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_RESPONSE,
                              p->auth_response_hex)) return -1;
    }

    /* IE 0x62 — auth-mode echo. Sent in both initial and auth phases
     * when the server has previously included it; mirrors the
     * `this[0x21bb0]` machinery in MM::SendRegReq. */
    if (p->echo_auth_mode) {
        if (vham_pack_tlv_u32(&b, 1, VHAM_IE_AUTH_MODE,
                              p->auth_mode_value)) return -1;
    }

    /* IE 0x70 — dispatch-number echo. The server allocates this in
     * the REGRSP and expects to see it on subsequent REGREQs. */
    if (p->auth_dispatch_num && *p->auth_dispatch_num) {
        if (vham_pack_tlv_str(&b, 1, VHAM_IE_DISPATCH_NUM,
                              p->auth_dispatch_num)) return -1;
    }

    /* Patch SRVMSG.dwMsgLen and TAP.body_len */
    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start))
        return -1;
    /* TAP body_len is (SRVMSG header + IEs) = b.off - body_start */
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);

    if (b.err) return -1;
    return (int)b.off;
}
