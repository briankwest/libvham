/* libvham/include/vham/rtcp.h — minimal RTCP encoder + parser.
 *
 * Implements RFC 3550 §6.4:
 *   - SR (sender report,   PT 200)
 *   - RR (receiver report, PT 201)
 *   - SDES (source description, PT 202) — CNAME only
 *
 * Frames are emitted as a "compound packet" per RFC convention:
 * SR/RR followed by SDES.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_RTCP_H
#define VHAM_RTCP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_RTCP_PT_SR    200
#define VHAM_RTCP_PT_RR    201
#define VHAM_RTCP_PT_SDES  202
#define VHAM_RTCP_PT_BYE   203

/* One receiver-report block (24 bytes on the wire). */
typedef struct {
    uint32_t ssrc;
    uint8_t  fraction_lost;
    uint32_t cumulative_lost;     /* 24-bit BE */
    uint32_t highest_seq;
    uint32_t jitter;
    uint32_t lsr;                 /* last SR timestamp middle 32 bits */
    uint32_t dlsr;                /* delay since last SR (1/65536 s) */
} vham_rtcp_rr_block_t;

/* Build a compound SR + SDES(CNAME) packet.
 *
 *   ssrc          our SSRC
 *   ntp_ts        64-bit NTP timestamp at send time
 *   rtp_ts        RTP timestamp at send time
 *   packets       senderpacketcount (cumulative)
 *   octets        sender octet count (cumulative payload bytes)
 *   blocks        zero or more RR blocks (we report on peers)
 *   n_blocks      count
 *   cname         CNAME string (≤255 chars)
 *
 * Returns bytes written, -1 on error. */
int vham_rtcp_build_sr(uint32_t ssrc, uint64_t ntp_ts, uint32_t rtp_ts,
                       uint32_t packets, uint32_t octets,
                       const vham_rtcp_rr_block_t *blocks, size_t n_blocks,
                       const char *cname,
                       void *out, size_t out_cap);

/* Same shape but as a Receiver Report (no sender block). */
int vham_rtcp_build_rr(uint32_t ssrc,
                       const vham_rtcp_rr_block_t *blocks, size_t n_blocks,
                       const char *cname,
                       void *out, size_t out_cap);

/* Parsed view of a single RTCP packet. */
typedef struct {
    uint8_t  pt;            /* 200 / 201 / 202 / ... */
    uint8_t  rc;            /* report count or item count */
    uint32_t ssrc;          /* sender SSRC (SR/RR) */
    /* SR-only fields */
    uint64_t ntp_ts;
    uint32_t rtp_ts;
    uint32_t packets;
    uint32_t octets;
    /* up to 4 RR blocks */
    vham_rtcp_rr_block_t blocks[4];
    int      block_count;
} vham_rtcp_pkt_t;

/* Parse the FIRST packet in a compound. Returns bytes consumed, or -1
 * on error. To walk a compound, advance the buffer by that many bytes
 * and call again. */
int vham_rtcp_parse(const void *buf, size_t len, vham_rtcp_pkt_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_RTCP_H */
