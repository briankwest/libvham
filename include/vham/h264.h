/* libvham/include/vham/h264.h — H.264 RTP packetization per RFC 6184.
 *
 * This module slices an H.264 NAL unit into RTP payloads:
 *   - Small NAL (< MTU - 12)        → single-NAL packet (just the NAL bytes)
 *   - Larger NAL                    → FU-A fragments
 *
 * The reassembler walks RTP payloads in order and emits complete
 * NAL units back. STAP-A aggregation is supported on the receive
 * path (parsing) but the sender emits single-NAL or FU-A only.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_H264_H
#define VHAM_H264_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_H264_MAX_NAL  (256 * 1024)
#define VHAM_H264_MTU_DEF  1400

/* RFC 6184 NAL types as carried in RTP payload byte 0:
 *   1..23  = single NAL unit
 *   24     = STAP-A (aggregation)
 *   28     = FU-A (fragmentation) */
#define VHAM_H264_NALU_STAP_A 24
#define VHAM_H264_NALU_FU_A   28

/* One RTP payload slice ready to be packed into an RTP packet. */
typedef struct {
    uint8_t  data[VHAM_H264_MTU_DEF];
    size_t   length;
    uint8_t  marker;          /* set on the LAST slice of an access unit */
} vham_h264_slice_t;

/* Fragment a single NAL into RTP payload slices. Each slice fits in
 * one RTP packet (length ≤ MTU). The caller is expected to RTP-wrap
 * each slice with vham_rtp_build_audio()-style code (same PT for the
 * whole stream, timestamp shared across slices of one access unit).
 *
 * `nal` should start at the NAL header byte (no 0x000001 prefix).
 *
 * Returns the slice count, -1 on error. */
int vham_h264_fragment(const uint8_t *nal, size_t nal_len,
                       size_t mtu,
                       vham_h264_slice_t *slices_out, size_t cap);

/* H.264 RTP payload reassembler. Holds one in-progress FU-A NAL.
 *
 * Feed each RTP payload via vham_h264_rx_feed(). When a complete NAL
 * has been assembled the function copies it into `out`/`out_cap` and
 * returns its length. Otherwise returns 0 (need more data) or -1 on
 * malformed input.
 *
 * The receiver supports single-NAL, FU-A, and STAP-A (returning the
 * first aggregated NAL — call again to fetch subsequent ones from
 * the same STAP-A). */
typedef struct {
    uint8_t  in_progress;
    uint8_t  fu_nal_header;       /* reconstructed NAL header for FU-A */
    uint8_t  buf[VHAM_H264_MAX_NAL];
    size_t   buf_len;

    /* STAP-A state: when nonzero, point into the *most recent* STAP-A
     * payload; cursor advances each time we pull a NAL out. */
    const uint8_t *stap_ptr;
    size_t         stap_left;
    uint8_t        stap_buf[VHAM_H264_MAX_NAL];
    size_t         stap_size;
} vham_h264_rx_t;

void vham_h264_rx_init(vham_h264_rx_t *rx);

int  vham_h264_rx_feed(vham_h264_rx_t *rx,
                       const uint8_t *payload, size_t length,
                       uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_H264_H */
