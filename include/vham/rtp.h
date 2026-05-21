/* libvham/include/vham/rtp.h — RFC 3550 RTP header.
 *
 * Full encoder/decoder with support for padding (P), extension (X),
 * CSRC list (CC), marker (M), payload type (PT), 16-bit sequence
 * number, 32-bit timestamp, 32-bit SSRC.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           timestamp                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           synchronization source (SSRC) identifier            |
 *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *  |            contributing source (CSRC) identifiers (0..15)     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | header extension (if X=1): u16 profile, u16 length(words), data |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | payload ...                                                   |
 *  | (last byte = padding length, if P=1)                          |
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_RTP_H
#define VHAM_RTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_RTP_VERSION  2
#define VHAM_RTP_MAX_CSRC 15
#define VHAM_RTP_HDR_MIN  12

/* Common RTP audio payload types */
enum vham_rtp_pt {
    VHAM_RTP_PT_PCMU      = 0,   /* G.711 µ-law, 8 kHz, mono */
    VHAM_RTP_PT_PCMA      = 8,   /* G.711 A-law,  8 kHz, mono */
    VHAM_RTP_PT_DTMF      = 101, /* RFC 4733 telephone-event (dynamic) */
    VHAM_RTP_PT_OPUS      = 111, /* dynamic; varies */
    VHAM_RTP_PT_H264      = 98,
    VHAM_RTP_PT_H265      = 111,
};

typedef struct {
    uint8_t  version;            /* always 2 */
    uint8_t  padding;            /* 0 or 1 */
    uint8_t  extension;          /* 0 or 1 */
    uint8_t  marker;             /* 0 or 1 */
    uint8_t  payload_type;       /* 0..127 */
    uint16_t sequence;           /* host order */
    uint32_t timestamp;          /* host order */
    uint32_t ssrc;               /* host order */
    uint8_t  csrc_count;         /* 0..15 */
    uint32_t csrc[VHAM_RTP_MAX_CSRC]; /* host order */

    /* Header extension (RFC 3550 §5.3.1) */
    int      have_extension;
    uint16_t ext_profile;
    /* The extension payload is `ext_word_count` 32-bit words. */
    uint16_t ext_word_count;
    const uint8_t *ext_data;     /* parser fills; encoder reads */

    /* Payload */
    const uint8_t *payload;
    size_t         payload_len;

    /* Padding length (bytes including the trailing length byte).
     * Encoder uses this if padding != 0; decoder fills it. */
    uint8_t  padding_len;
} vham_rtp_pkt_t;

/* Encode an RTP packet. Returns bytes written, or -1 on error. */
int vham_rtp_build(const vham_rtp_pkt_t *p, void *out, size_t out_cap);

/* Decode an RTP packet (zero-copy: pkt's pointers reference `buf`).
 * Returns 0 on success, -1 on malformed. */
int vham_rtp_parse(const void *buf, size_t len, vham_rtp_pkt_t *pkt);

/* Convenience: build a basic audio RTP packet (no ext, no padding, no CSRC). */
int vham_rtp_build_audio(uint8_t pt, uint16_t seq, uint32_t ts, uint32_t ssrc,
                         uint8_t marker, const void *payload, size_t plen,
                         void *out, size_t out_cap);

/* Helpers for sequence-number arithmetic with wraparound (RFC 3550 A.1) */
static inline int16_t vham_rtp_seq_diff(uint16_t a, uint16_t b) {
    return (int16_t)(a - b);
}

/* ---------- RFC 4571 framing (RTP over TCP) ----------
 *
 * Wraps a UDP-style RTP/RTCP packet with a 2-byte big-endian length
 * prefix. Used when the protocol falls back to TCP transport for
 * media or when interoperating with WebRTC-style RTP-over-TCP. */

/* Encode `rtp_buf`/`rtp_len` into `out` with a 2-byte BE length prefix.
 * Returns total bytes written (= rtp_len + 2), or -1 on overflow. */
int vham_rtp_tcp_frame(const void *rtp_buf, size_t rtp_len,
                       void *out, size_t out_cap);

/* Decode one framed packet. On success, sets `*rtp_buf` and `*rtp_len`
 * to point INTO `in` (zero-copy) and returns bytes consumed.
 * Returns 0 if there isn't enough data yet, -1 on malformed input. */
int vham_rtp_tcp_unframe(const void *in, size_t in_len,
                         const uint8_t **rtp_buf, size_t *rtp_len);

#ifdef __cplusplus
}
#endif

#endif
