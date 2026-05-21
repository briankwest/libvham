/* libvham/src/codec.c — atomic + TLV encoders.
 *
 * Each function mirrors a `PPack*` in libsvcapi.so. Source-of-truth
 * for the bit layout is the Ghidra decompilation in
 * decompiled/PPack*.c, e.g.:
 *
 *   PPackU16(0x269ca4):  buf[off] = v>>8;  buf[off+1] = v;  off += 2
 *   PPackIntelU16:       buf[off] = v;     buf[off+1] = v>>8; off += 2
 *   PPackTLVStr:         len includes the NUL terminator
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/codec.h"
#include <string.h>

/* helper: try to reserve n bytes; bumps off on success, sets err on
 * overflow (matches PPack* which return -1 and do not touch the
 * caller's offset on overflow). */
static int reserve(vham_buf_t *b, size_t n) {
    if (b->err) return -1;
    if (b->off + n > b->cap) { b->err = -1; return -1; }
    return 0;
}

int vham_pack_u8(vham_buf_t *b, uint8_t v) {
    if (reserve(b, 1)) return -1;
    b->buf[b->off++] = v;
    return 0;
}

int vham_pack_u16(vham_buf_t *b, uint16_t v) {
    if (reserve(b, 2)) return -1;
    b->buf[b->off++] = (uint8_t)(v >> 8);
    b->buf[b->off++] = (uint8_t)(v);
    return 0;
}

int vham_pack_u24(vham_buf_t *b, uint32_t v) {
    if (reserve(b, 3)) return -1;
    b->buf[b->off++] = (uint8_t)(v >> 16);
    b->buf[b->off++] = (uint8_t)(v >> 8);
    b->buf[b->off++] = (uint8_t)(v);
    return 0;
}

int vham_pack_u32(vham_buf_t *b, uint32_t v) {
    if (reserve(b, 4)) return -1;
    b->buf[b->off++] = (uint8_t)(v >> 24);
    b->buf[b->off++] = (uint8_t)(v >> 16);
    b->buf[b->off++] = (uint8_t)(v >> 8);
    b->buf[b->off++] = (uint8_t)(v);
    return 0;
}

int vham_pack_intel_u16(vham_buf_t *b, uint16_t v) {
    if (reserve(b, 2)) return -1;
    b->buf[b->off++] = (uint8_t)(v);
    b->buf[b->off++] = (uint8_t)(v >> 8);
    return 0;
}

int vham_pack_intel_u32(vham_buf_t *b, uint32_t v) {
    if (reserve(b, 4)) return -1;
    b->buf[b->off++] = (uint8_t)(v);
    b->buf[b->off++] = (uint8_t)(v >> 8);
    b->buf[b->off++] = (uint8_t)(v >> 16);
    b->buf[b->off++] = (uint8_t)(v >> 24);
    return 0;
}

int vham_pack_str(vham_buf_t *b, const char *s) {
    if (s == NULL) {
        return vham_pack_u8(b, 0);
    }
    size_t n = strlen(s);
    if (reserve(b, n + 1)) return -1;
    memcpy(b->buf + b->off, s, n);
    b->off += n;
    b->buf[b->off++] = 0;
    return 0;
}

int vham_pack_str_no0(vham_buf_t *b, const void *p, size_t n) {
    if (reserve(b, n)) return -1;
    memcpy(b->buf + b->off, p, n);
    b->off += n;
    return 0;
}

int vham_pack_fix(vham_buf_t *b, const void *p, size_t n) {
    return vham_pack_str_no0(b, p, n);
}

int vham_pack_tlv_u8(vham_buf_t *b, int present, uint16_t tag, uint8_t v) {
    if (!present) return 0;
    if (vham_pack_u16(b, tag) || vham_pack_u16(b, 1) || vham_pack_u8(b, v))
        return -1;
    return 0;
}

int vham_pack_tlv_u16(vham_buf_t *b, int present, uint16_t tag, uint16_t v) {
    if (!present) return 0;
    if (vham_pack_u16(b, tag) || vham_pack_u16(b, 2) || vham_pack_u16(b, v))
        return -1;
    return 0;
}

int vham_pack_tlv_u32(vham_buf_t *b, int present, uint16_t tag, uint32_t v) {
    if (!present) return 0;
    if (vham_pack_u16(b, tag) || vham_pack_u16(b, 4) || vham_pack_u32(b, v))
        return -1;
    return 0;
}

int vham_pack_tlv_str(vham_buf_t *b, int present, uint16_t tag, const char *s) {
    if (!present) return 0;
    if (s == NULL) { b->err = -1; return -1; }
    size_t n = strlen(s) + 1;          /* include NUL */
    if (n > 0xFFFF) { b->err = -1; return -1; }
    if (vham_pack_u16(b, tag) || vham_pack_u16(b, (uint16_t)n) ||
        vham_pack_str(b, s))
        return -1;
    return 0;
}

int vham_pack_tlv_fix(vham_buf_t *b, int present, uint16_t tag,
                      const void *p, size_t n) {
    if (!present) return 0;
    if (n > 0xFFFF) { b->err = -1; return -1; }
    if (vham_pack_u16(b, tag) || vham_pack_u16(b, (uint16_t)n) ||
        vham_pack_fix(b, p, n))
        return -1;
    return 0;
}

int vham_pack_tap_header(vham_buf_t *b, const vham_tap_hdr_t *h) {
    if (vham_pack_u8 (b, h->ver_hi)    ||
        vham_pack_u8 (b, h->ver_lo)    ||
        vham_pack_u16(b, h->flags)     ||
        vham_pack_u32(b, h->seq_no)    ||
        vham_pack_u16(b, h->class_id)  ||
        vham_pack_u16(b, h->cmd)       ||
        vham_pack_u32(b, h->body_len))
        return -1;
    return 0;
}

int vham_pack_srvmsg_header(vham_buf_t *b, const vham_srvmsg_hdr_t *h,
                            size_t *out_len_offset) {
    if (vham_pack_u8 (b, h->ucDst)         ||
        vham_pack_u8 (b, h->ucSrc)         ||
        vham_pack_u16(b, h->wMsgId)        ||
        vham_pack_u32(b, h->dwDstFsmId)    ||
        vham_pack_u32(b, h->dwSrcFsmId))
        return -1;
    if (out_len_offset) *out_len_offset = b->off;
    if (vham_pack_u32(b, 0))               /* placeholder for dwMsgLen */
        return -1;
    return 0;
}

int vham_build_tap_ack(uint32_t seq, uint16_t class_id, uint16_t cmd,
                       void *out, size_t out_cap) {
    if (out_cap < 16) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    vham_tap_hdr_t h = {
        .ver_hi   = 0x01,
        .ver_lo   = 0x00,
        .flags    = VHAM_TAP_FLAG_ACK,
        .seq_no   = seq,
        .class_id = class_id,
        .cmd      = cmd,
        .body_len = 0,
    };
    if (vham_pack_tap_header(&b, &h) != 0) return -1;
    return (int)b.off;
}

int vham_build_nat_ping(void *out, size_t out_cap) {
    if (!out || out_cap < 3) return -1;
    uint8_t *p = (uint8_t *)out;
    p[0] = 0xFF;
    p[1] = 0xD3;
    p[2] = 0xF1;
    return 3;
}

int vham_build_nat_setup(void *out, size_t out_cap) {
    if (!out || out_cap < 8) return -1;
    uint8_t *p = (uint8_t *)out;
    p[0] = 0xFF; p[1] = 0xD3; p[2] = 0x01;
    p[3] = 0x00; p[4] = 0x00; p[5] = 0x00; p[6] = 0x00; p[7] = 0x00;
    return 8;
}

int vham_is_nat_packet(const void *buf, size_t len) {
    if (!buf || len < 3) return 0;
    const uint8_t *p = (const uint8_t *)buf;
    return (p[0] == 0xFF && p[1] == 0xD3) ? 1 : 0;
}

int vham_patch_srvmsg_len(vham_buf_t *b, size_t len_offset, size_t body_start) {
    if (b->err) return -1;
    if (len_offset + 4 > b->cap) { b->err = -1; return -1; }
    if (b->off < body_start)     { b->err = -1; return -1; }
    uint32_t body = (uint32_t)(b->off - body_start);
    b->buf[len_offset    ] = (uint8_t)(body >> 24);
    b->buf[len_offset + 1] = (uint8_t)(body >> 16);
    b->buf[len_offset + 2] = (uint8_t)(body >> 8);
    b->buf[len_offset + 3] = (uint8_t)(body);
    return 0;
}
