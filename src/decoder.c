/* libvham/src/decoder.c — TLV / SRVMSG / TAP parsers.
 *
 * Designed to round-trip with libvham's encoder and to handle real
 * traffic from libsvcapi.so.
 *
 * Mirrors SrvUnpkByteMsg @ 0x26f9d8 and SrvUnpkIe @ 0x26e348.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/codec.h"
#include <string.h>

int vham_next_ie(vham_reader_t *r, vham_ie_t *ie) {
    if (!r || !ie || !r->buf) return -1;
    if (r->off >= r->cap) return 0;             /* clean end of buffer */
    if (r->cap - r->off < 4) return -1;         /* truncated TLV hdr */

    uint16_t tag = vham_unpack_u16(r->buf + r->off);
    uint16_t len = vham_unpack_u16(r->buf + r->off + 2);
    if ((size_t)(len) > r->cap - r->off - 4) return -1;  /* truncated value */

    ie->tag   = tag;
    ie->len   = len;
    ie->value = r->buf + r->off + 4;
    r->off += 4u + (size_t)len;
    return 1;
}

int vham_ie_get_u8(const vham_ie_t *ie, uint8_t *out) {
    if (!ie || !out || ie->len != 1) return -1;
    *out = vham_unpack_u8(ie->value);
    return 0;
}

int vham_ie_get_u16(const vham_ie_t *ie, uint16_t *out) {
    if (!ie || !out || ie->len != 2) return -1;
    *out = vham_unpack_u16(ie->value);
    return 0;
}

int vham_ie_get_u32(const vham_ie_t *ie, uint32_t *out) {
    if (!ie || !out || ie->len != 4) return -1;
    *out = vham_unpack_u32(ie->value);
    return 0;
}

const char *vham_ie_get_str(const vham_ie_t *ie) {
    if (!ie || ie->len == 0) return NULL;
    /* Strings on the wire include the trailing NUL (PPackTLVStr sets
     * length = strlen+1 and writes the NUL). Verify the last byte is
     * NUL so a downstream strlen is safe. */
    if (ie->value[ie->len - 1] != 0) return NULL;
    return (const char *)ie->value;
}

/* All accessors return the IPv4 address in "convention A": the
 * high octet of the dotted-quad in the high byte of the u32.
 * Example: 47.253.13.238 ↔ 0x2ffd0dee. Pair with htonl() to assign
 * to struct in_addr.s_addr on a little-endian host. */

/* 6-byte SYSIPADDR — emitted by SrvPackIpAddr (IE 0x5a/0x84/0x8d).
 * The encoder uses explicit PPackU8 calls, so the wire byte order
 * is BIG endian (network byte order) for both ip and port. */
int vham_ie_get_ipaddr6(const vham_ie_t *ie, vham_ipaddr_t *out) {
    if (!ie || !out || ie->len != 6) return -1;
    out->ipv4   = ((uint32_t)ie->value[0] << 24)
               | ((uint32_t)ie->value[1] << 16)
               | ((uint32_t)ie->value[2] <<  8)
               | (uint32_t)ie->value[3];
    out->port   = ((uint16_t)ie->value[4] << 8) | (uint16_t)ie->value[5];
    out->family = 0;
    out->pad    = 0;
    return 0;
}

/* 8-byte PIpAddr — emitted via PPackTLVDataFix on a raw struct
 * memcpy (see MM::SendRegReq), so the wire format is whatever host
 * byte order the binary was compiled for. ARM/x86 = LITTLE endian
 * for both ip and port. */
int vham_ie_get_ipaddr(const vham_ie_t *ie, vham_ipaddr_t *out) {
    if (!ie || !out || ie->len != 8) return -1;
    out->ipv4   = ((uint32_t)ie->value[3] << 24)
               | ((uint32_t)ie->value[2] << 16)
               | ((uint32_t)ie->value[1] <<  8)
               | (uint32_t)ie->value[0];
    out->port   = (uint16_t)ie->value[4] | ((uint16_t)ie->value[5] << 8);
    out->family = ie->value[6];
    out->pad    = ie->value[7];
    return 0;
}

int vham_parse_packet(const void *buf, size_t len,
                      vham_tap_hdr_t    *tap_out,
                      vham_srvmsg_hdr_t *srvmsg_out,
                      vham_reader_t     *iter_out) {
    if (!buf || len < 32) return -1;        /* TAP + SRVMSG = 32B minimum */
    const uint8_t *p = (const uint8_t *)buf;

    /* TAP header */
    vham_tap_hdr_t t;
    t.ver_hi   = p[0];
    t.ver_lo   = p[1];
    t.flags    = vham_unpack_u16(p + 2);
    t.seq_no   = vham_unpack_u32(p + 4);
    t.class_id = vham_unpack_u16(p + 8);
    t.cmd      = vham_unpack_u16(p + 10);
    t.body_len = vham_unpack_u32(p + 12);
    /* The TAP body is everything after this 16-byte header. */
    if (t.body_len != len - 16) return -1;
    if (tap_out) *tap_out = t;

    /* SRVMSG header */
    const uint8_t *s = p + 16;
    vham_srvmsg_hdr_t h;
    h.ucDst      = s[0];
    h.ucSrc      = s[1];
    h.wMsgId     = vham_unpack_u16(s + 2);
    h.dwDstFsmId = vham_unpack_u32(s + 4);
    h.dwSrcFsmId = vham_unpack_u32(s + 8);
    h.dwMsgLen   = vham_unpack_u32(s + 12);
    if (h.dwMsgLen != t.body_len - 16) return -1;
    if (h.wMsgId  != t.cmd)            return -1;   /* duplicated field check */
    if (srvmsg_out) *srvmsg_out = h;

    if (iter_out) {
        iter_out->buf = s + 16;
        iter_out->cap = h.dwMsgLen;
        iter_out->off = 0;
    }
    return 0;
}
