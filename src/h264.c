/* libvham/src/h264.c — H.264 RTP packetization (RFC 6184).
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/h264.h"

int vham_h264_fragment(const uint8_t *nal, size_t nal_len, size_t mtu,
                       vham_h264_slice_t *slices, size_t cap) {
    if (!nal || nal_len < 1 || !slices) return -1;
    if (mtu == 0 || mtu > VHAM_H264_MTU_DEF) mtu = VHAM_H264_MTU_DEF;

    /* Single-NAL packet if it fits in one MTU. */
    if (nal_len <= mtu) {
        if (cap < 1) return -1;
        memcpy(slices[0].data, nal, nal_len);
        slices[0].length = nal_len;
        slices[0].marker = 1;
        return 1;
    }

    /* FU-A: NAL header is split across the FU indicator + FU header.
     *   FU indicator (1B): F | NRI | type(28)
     *   FU header    (1B): S | E | R | type
     */
    uint8_t fnri = (uint8_t)(nal[0] & 0xe0);
    uint8_t ntyp = (uint8_t)(nal[0] & 0x1f);
    const uint8_t *payload = nal + 1;
    size_t   remaining     = nal_len - 1;
    size_t   chunk         = mtu - 2;        /* room for FU ind + FU hdr */

    int produced = 0;
    int is_first = 1;
    while (remaining > 0) {
        if (produced >= (int)cap) return -1;
        size_t take = remaining > chunk ? chunk : remaining;
        int is_last = (take == remaining);

        slices[produced].data[0] = (uint8_t)(fnri | VHAM_H264_NALU_FU_A);
        slices[produced].data[1] = (uint8_t)((is_first ? 0x80 : 0) |
                                             (is_last  ? 0x40 : 0) |
                                              ntyp);
        memcpy(slices[produced].data + 2, payload, take);
        slices[produced].length = 2 + take;
        slices[produced].marker = (uint8_t)is_last;

        payload   += take;
        remaining -= take;
        produced++;
        is_first   = 0;
    }
    return produced;
}

void vham_h264_rx_init(vham_h264_rx_t *rx) {
    if (rx) memset(rx, 0, sizeof *rx);
}

static int copy_out(uint8_t *out, size_t out_cap,
                    const uint8_t *src, size_t n) {
    if (n > out_cap) return -1;
    memcpy(out, src, n);
    return (int)n;
}

int vham_h264_rx_feed(vham_h264_rx_t *rx,
                      const uint8_t *payload, size_t length,
                      uint8_t *out, size_t out_cap) {
    if (!rx || !payload || length < 1 || !out) return -1;

    /* If there's a STAP-A in progress, return next NAL from it. */
    if (rx->stap_left) {
        if (rx->stap_left < 2) { rx->stap_left = 0; return -1; }
        uint16_t nl = (uint16_t)((rx->stap_ptr[0] << 8) | rx->stap_ptr[1]);
        if (nl > rx->stap_left - 2) { rx->stap_left = 0; return -1; }
        int rc = copy_out(out, out_cap, rx->stap_ptr + 2, nl);
        rx->stap_ptr  += 2 + nl;
        rx->stap_left -= 2 + nl;
        return rc;
    }

    uint8_t nal_type = (uint8_t)(payload[0] & 0x1f);

    if (nal_type >= 1 && nal_type <= 23) {
        /* Single NAL */
        return copy_out(out, out_cap, payload, length);
    }
    if (nal_type == VHAM_H264_NALU_STAP_A) {
        /* Save aggregate payload + return first NAL */
        if (length > sizeof rx->stap_buf) return -1;
        memcpy(rx->stap_buf, payload + 1, length - 1);
        rx->stap_size = length - 1;
        rx->stap_ptr  = rx->stap_buf;
        rx->stap_left = rx->stap_size;
        if (rx->stap_left < 2) return -1;
        uint16_t nl = (uint16_t)((rx->stap_ptr[0] << 8) | rx->stap_ptr[1]);
        if (nl > rx->stap_left - 2) { rx->stap_left = 0; return -1; }
        int rc = copy_out(out, out_cap, rx->stap_ptr + 2, nl);
        rx->stap_ptr  += 2 + nl;
        rx->stap_left -= 2 + nl;
        return rc;
    }
    if (nal_type == VHAM_H264_NALU_FU_A) {
        if (length < 2) return -1;
        uint8_t fu_hdr = payload[1];
        uint8_t start  = (uint8_t)(fu_hdr & 0x80);
        uint8_t end    = (uint8_t)(fu_hdr & 0x40);
        uint8_t typ    = (uint8_t)(fu_hdr & 0x1f);
        uint8_t fnri   = (uint8_t)(payload[0] & 0xe0);

        if (start) {
            rx->in_progress  = 1;
            rx->fu_nal_header = (uint8_t)(fnri | typ);
            rx->buf[0] = rx->fu_nal_header;
            rx->buf_len = 1;
        }
        if (!rx->in_progress) return -1;

        size_t frag_len = length - 2;
        if (rx->buf_len + frag_len > sizeof rx->buf) {
            rx->in_progress = 0;
            return -1;
        }
        memcpy(rx->buf + rx->buf_len, payload + 2, frag_len);
        rx->buf_len += frag_len;

        if (end) {
            int rc = copy_out(out, out_cap, rx->buf, rx->buf_len);
            rx->in_progress = 0;
            return rc;
        }
        return 0;
    }
    return -1;
}
