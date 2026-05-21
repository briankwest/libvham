/* libvham/src/rtp.c — RFC 3550 RTP encoder/decoder.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/rtp.h"
#include <string.h>

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}
static uint16_t get_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

int vham_rtp_build(const vham_rtp_pkt_t *p, void *out_, size_t out_cap) {
    if (!p || !out_) return -1;
    if (p->csrc_count > VHAM_RTP_MAX_CSRC) return -1;
    if (p->payload_type > 127) return -1;

    size_t need = 12 + 4 * (size_t)p->csrc_count;
    size_t ext_bytes = 0;
    if (p->have_extension) {
        ext_bytes = 4 + 4 * (size_t)p->ext_word_count;
        need += ext_bytes;
    }
    need += p->payload_len;
    size_t pad_bytes = 0;
    if (p->padding) {
        pad_bytes = p->padding_len ? p->padding_len : 1;
        if (pad_bytes == 0 || pad_bytes > 255) return -1;
        need += pad_bytes;
    }
    if (need > out_cap) return -1;

    uint8_t *out = (uint8_t *)out_;
    uint8_t b0 = (uint8_t)(
        (VHAM_RTP_VERSION & 0x3) << 6 |
        (p->padding   & 0x1) << 5 |
        (p->extension & 0x1) << 4 |
        (p->csrc_count & 0xF));
    uint8_t b1 = (uint8_t)(
        (p->marker      & 0x1) << 7 |
        (p->payload_type & 0x7F));
    out[0] = b0;
    out[1] = b1;
    put_u16(out + 2, p->sequence);
    put_u32(out + 4, p->timestamp);
    put_u32(out + 8, p->ssrc);

    size_t off = 12;
    for (uint8_t i = 0; i < p->csrc_count; ++i) {
        put_u32(out + off, p->csrc[i]);
        off += 4;
    }

    if (p->have_extension) {
        put_u16(out + off, p->ext_profile);
        put_u16(out + off + 2, p->ext_word_count);
        off += 4;
        if (p->ext_word_count > 0) {
            if (!p->ext_data) return -1;
            memcpy(out + off, p->ext_data, 4 * (size_t)p->ext_word_count);
            off += 4 * (size_t)p->ext_word_count;
        }
    }

    if (p->payload_len > 0) {
        if (!p->payload) return -1;
        memcpy(out + off, p->payload, p->payload_len);
        off += p->payload_len;
    }

    if (pad_bytes > 0) {
        memset(out + off, 0, pad_bytes - 1);
        out[off + pad_bytes - 1] = (uint8_t)pad_bytes;
        off += pad_bytes;
    }

    return (int)off;
}

int vham_rtp_parse(const void *buf_, size_t len, vham_rtp_pkt_t *pkt) {
    if (!buf_ || !pkt || len < VHAM_RTP_HDR_MIN) return -1;
    const uint8_t *buf = (const uint8_t *)buf_;
    memset(pkt, 0, sizeof *pkt);

    uint8_t b0 = buf[0], b1 = buf[1];
    pkt->version      = (uint8_t)((b0 >> 6) & 0x3);
    pkt->padding      = (uint8_t)((b0 >> 5) & 0x1);
    pkt->extension    = (uint8_t)((b0 >> 4) & 0x1);
    pkt->csrc_count   = (uint8_t)( b0       & 0xF);
    pkt->marker       = (uint8_t)((b1 >> 7) & 0x1);
    pkt->payload_type = (uint8_t)( b1       & 0x7F);
    pkt->sequence     = get_u16(buf + 2);
    pkt->timestamp    = get_u32(buf + 4);
    pkt->ssrc         = get_u32(buf + 8);

    if (pkt->version != VHAM_RTP_VERSION) return -1;

    size_t off = 12;
    if (off + 4u * pkt->csrc_count > len) return -1;
    for (uint8_t i = 0; i < pkt->csrc_count; ++i) {
        pkt->csrc[i] = get_u32(buf + off);
        off += 4;
    }

    if (pkt->extension) {
        if (off + 4 > len) return -1;
        pkt->have_extension = 1;
        pkt->ext_profile    = get_u16(buf + off);
        pkt->ext_word_count = get_u16(buf + off + 2);
        off += 4;
        size_t ext_bytes = 4u * (size_t)pkt->ext_word_count;
        if (off + ext_bytes > len) return -1;
        pkt->ext_data = (pkt->ext_word_count > 0) ? buf + off : NULL;
        off += ext_bytes;
    }

    /* payload + optional trailing padding */
    size_t payload_end = len;
    if (pkt->padding) {
        if (len == off) return -1;
        uint8_t pad = buf[len - 1];
        if (pad == 0 || (size_t)pad > len - off) return -1;
        pkt->padding_len = pad;
        payload_end = len - pad;
    }
    pkt->payload     = buf + off;
    pkt->payload_len = payload_end - off;
    return 0;
}

int vham_rtp_build_audio(uint8_t pt, uint16_t seq, uint32_t ts, uint32_t ssrc,
                         uint8_t marker, const void *payload, size_t plen,
                         void *out, size_t out_cap) {
    vham_rtp_pkt_t p = {
        .version      = VHAM_RTP_VERSION,
        .payload_type = pt,
        .marker       = marker ? 1 : 0,
        .sequence     = seq,
        .timestamp    = ts,
        .ssrc         = ssrc,
        .payload      = (const uint8_t *)payload,
        .payload_len  = plen,
    };
    return vham_rtp_build(&p, out, out_cap);
}

int vham_rtp_tcp_frame(const void *rtp_buf, size_t rtp_len,
                       void *out, size_t out_cap) {
    if (!rtp_buf || !out) return -1;
    if (rtp_len > 0xffff) return -1;
    if (rtp_len + 2 > out_cap) return -1;
    uint8_t *p = (uint8_t *)out;
    p[0] = (uint8_t)(rtp_len >> 8);
    p[1] = (uint8_t)(rtp_len & 0xff);
    memcpy(p + 2, rtp_buf, rtp_len);
    return (int)(rtp_len + 2);
}

int vham_rtp_tcp_unframe(const void *in, size_t in_len,
                         const uint8_t **rtp_buf, size_t *rtp_len) {
    if (!in) return -1;
    if (in_len < 2) return 0;
    const uint8_t *p = (const uint8_t *)in;
    size_t len = ((size_t)p[0] << 8) | p[1];
    if (in_len < 2 + len) return 0;
    if (rtp_buf) *rtp_buf = p + 2;
    if (rtp_len) *rtp_len = len;
    return (int)(2 + len);
}
