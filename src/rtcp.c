/* libvham/src/rtcp.c — RFC 3550 §6 SR/RR/SDES encoder + parser.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/rtcp.h"

/* RTCP common header layout:
 *   byte 0: V(2) | P(1) | RC(5)
 *   byte 1: PT(8)
 *   byte 2-3: length-in-32-bit-words-minus-1 (big-endian)
 */

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void put_u24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}
static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint32_t get_u24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/* Pack one RR block (24 bytes). */
static void put_rr_block(uint8_t *p, const vham_rtcp_rr_block_t *b) {
    put_u32(p,      b->ssrc);
    p[4] = b->fraction_lost;
    put_u24(p + 5,  b->cumulative_lost);
    put_u32(p + 8,  b->highest_seq);
    put_u32(p + 12, b->jitter);
    put_u32(p + 16, b->lsr);
    put_u32(p + 20, b->dlsr);
}

static int pack_sdes_cname(uint8_t *out, size_t cap,
                           uint32_t ssrc, const char *cname) {
    if (!cname) cname = "vham";
    size_t cn_len = strlen(cname);
    if (cn_len > 255) cn_len = 255;
    /* SDES chunk: SSRC(4) + item-type(1) + item-len(1) + text + 0..3 pad */
    size_t chunk = 4 + 2 + cn_len + 1;       /* +1 for END item */
    /* pad chunk to a 32-bit boundary */
    while (chunk % 4 != 0) chunk++;

    size_t total = 4 /*hdr*/ + chunk;
    if (total > cap) return -1;

    /* Header */
    out[0] = 0x81;                            /* V=2 P=0 SC=1 */
    out[1] = VHAM_RTCP_PT_SDES;
    put_u16(out + 2, (uint16_t)((total / 4) - 1));
    /* SSRC */
    put_u32(out + 4, ssrc);
    /* CNAME item */
    out[8]  = 1;                              /* item type = CNAME */
    out[9]  = (uint8_t)cn_len;
    memcpy(out + 10, cname, cn_len);
    /* END item + padding */
    size_t end_at = 10 + cn_len;
    while (end_at < total) out[end_at++] = 0;
    return (int)total;
}

int vham_rtcp_build_sr(uint32_t ssrc, uint64_t ntp_ts, uint32_t rtp_ts,
                       uint32_t packets, uint32_t octets,
                       const vham_rtcp_rr_block_t *blocks, size_t n_blocks,
                       const char *cname,
                       void *out, size_t out_cap) {
    if (!out) return -1;
    if (n_blocks > 31) return -1;
    /* SR length: 8 (hdr+ssrc) + 20 (sender info) + 24*n_blocks */
    size_t sr_len = 8 + 20 + 24 * n_blocks;
    if (sr_len > out_cap) return -1;
    uint8_t *p = (uint8_t *)out;
    p[0] = (uint8_t)(0x80 | (n_blocks & 0x1f));
    p[1] = VHAM_RTCP_PT_SR;
    put_u16(p + 2, (uint16_t)((sr_len / 4) - 1));
    put_u32(p + 4, ssrc);
    put_u32(p + 8,  (uint32_t)(ntp_ts >> 32));
    put_u32(p + 12, (uint32_t)ntp_ts);
    put_u32(p + 16, rtp_ts);
    put_u32(p + 20, packets);
    put_u32(p + 24, octets);
    for (size_t i = 0; i < n_blocks; ++i)
        put_rr_block(p + 28 + 24*i, &blocks[i]);

    /* Append SDES */
    int sd = pack_sdes_cname(p + sr_len, out_cap - sr_len, ssrc, cname);
    if (sd < 0) return -1;
    return (int)(sr_len + (size_t)sd);
}

int vham_rtcp_build_rr(uint32_t ssrc,
                       const vham_rtcp_rr_block_t *blocks, size_t n_blocks,
                       const char *cname,
                       void *out, size_t out_cap) {
    if (!out) return -1;
    if (n_blocks > 31) return -1;
    size_t rr_len = 8 + 24 * n_blocks;
    if (rr_len > out_cap) return -1;
    uint8_t *p = (uint8_t *)out;
    p[0] = (uint8_t)(0x80 | (n_blocks & 0x1f));
    p[1] = VHAM_RTCP_PT_RR;
    put_u16(p + 2, (uint16_t)((rr_len / 4) - 1));
    put_u32(p + 4, ssrc);
    for (size_t i = 0; i < n_blocks; ++i)
        put_rr_block(p + 8 + 24*i, &blocks[i]);
    int sd = pack_sdes_cname(p + rr_len, out_cap - rr_len, ssrc, cname);
    if (sd < 0) return -1;
    return (int)(rr_len + (size_t)sd);
}

int vham_rtcp_parse(const void *buf, size_t len, vham_rtcp_pkt_t *out) {
    if (!buf || !out || len < 8) return -1;
    const uint8_t *p = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    out->rc = (uint8_t)(p[0] & 0x1f);
    out->pt = p[1];
    uint16_t words = get_u16(p + 2);
    size_t plen = ((size_t)words + 1) * 4;
    if (plen > len) return -1;

    if (out->pt == VHAM_RTCP_PT_SR && plen >= 28) {
        out->ssrc    = get_u32(p + 4);
        out->ntp_ts  = ((uint64_t)get_u32(p + 8) << 32) | get_u32(p + 12);
        out->rtp_ts  = get_u32(p + 16);
        out->packets = get_u32(p + 20);
        out->octets  = get_u32(p + 24);
        size_t bo = 28;
        for (int i = 0; i < out->rc && i < 4 && bo + 24 <= plen; ++i, bo += 24) {
            vham_rtcp_rr_block_t *b = &out->blocks[i];
            b->ssrc            = get_u32(p + bo);
            b->fraction_lost   = p[bo + 4];
            b->cumulative_lost = get_u24(p + bo + 5);
            b->highest_seq     = get_u32(p + bo + 8);
            b->jitter          = get_u32(p + bo + 12);
            b->lsr             = get_u32(p + bo + 16);
            b->dlsr            = get_u32(p + bo + 20);
            out->block_count++;
        }
    } else if (out->pt == VHAM_RTCP_PT_RR && plen >= 8) {
        out->ssrc = get_u32(p + 4);
        size_t bo = 8;
        for (int i = 0; i < out->rc && i < 4 && bo + 24 <= plen; ++i, bo += 24) {
            vham_rtcp_rr_block_t *b = &out->blocks[i];
            b->ssrc            = get_u32(p + bo);
            b->fraction_lost   = p[bo + 4];
            b->cumulative_lost = get_u24(p + bo + 5);
            b->highest_seq     = get_u32(p + bo + 8);
            b->jitter          = get_u32(p + bo + 12);
            b->lsr             = get_u32(p + bo + 16);
            b->dlsr            = get_u32(p + bo + 20);
            out->block_count++;
        }
    } else if (out->pt == VHAM_RTCP_PT_SDES) {
        /* not yet parsed in detail */
    }
    return (int)plen;
}
