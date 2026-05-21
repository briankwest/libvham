/* libvham/include/vham/segment.h — TAP message segmentation.
 *
 * Large SRVMSG bodies are split into multiple TAP datagrams in the
 * official stack via `RecvSegMsg::UnPack`. Until we have a captured
 * sample to pin the exact wire format, this module exposes a minimal
 * mechanism that mirrors the most common segmentation pattern in
 * similar Chinese PoC stacks:
 *
 *   First fragment:  TAP cmd | total_len(u32) | offset(u32) = 0 | data
 *   Middle/last:     TAP cmd | total_len(u32) | offset(u32) > 0 | data
 *
 * Reassembly is keyed on (class, seq). Up to VHAM_SEG_ENTRIES messages
 * in flight; up to VHAM_SEG_BUF_MAX bytes per reassembled body.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_SEGMENT_H
#define VHAM_SEGMENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_SEG_MTU         1384        /* practical safe size */
#define VHAM_SEG_ENTRIES     4
#define VHAM_SEG_BUF_MAX     65536

typedef struct {
    int      in_use;
    uint16_t class_id;
    uint32_t seq;
    uint32_t total_len;
    uint32_t received_len;
    uint8_t  data[VHAM_SEG_BUF_MAX];
} vham_seg_entry_t;

typedef struct {
    vham_seg_entry_t entry[VHAM_SEG_ENTRIES];
} vham_seg_t;

void vham_seg_init(vham_seg_t *s);

/* Feed one fragment. Returns:
 *    1  → reassembly complete; `*out_buf` / `*out_len` point at it
 *    0  → fragment accepted, more expected
 *   -1  → error / overflow / unknown stream */
int  vham_seg_feed(vham_seg_t *s, uint16_t class_id, uint32_t seq,
                   uint32_t total_len, uint32_t offset,
                   const uint8_t *frag, size_t frag_len,
                   const uint8_t **out_buf, size_t *out_len);

/* Drop the buffer once the caller has consumed it. */
void vham_seg_release(vham_seg_t *s, uint16_t class_id, uint32_t seq);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_SEGMENT_H */
