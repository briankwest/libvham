/* libvham/src/segment.c — segment reassembler.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/segment.h"

void vham_seg_init(vham_seg_t *s) {
    if (s) memset(s, 0, sizeof *s);
}

static vham_seg_entry_t *find_or_alloc(vham_seg_t *s,
                                       uint16_t class_id, uint32_t seq) {
    /* Existing? */
    for (int i = 0; i < VHAM_SEG_ENTRIES; ++i) {
        vham_seg_entry_t *e = &s->entry[i];
        if (e->in_use && e->class_id == class_id && e->seq == seq) return e;
    }
    /* New */
    for (int i = 0; i < VHAM_SEG_ENTRIES; ++i) {
        vham_seg_entry_t *e = &s->entry[i];
        if (!e->in_use) {
            memset(e, 0, sizeof *e);
            e->in_use   = 1;
            e->class_id = class_id;
            e->seq      = seq;
            return e;
        }
    }
    return NULL;
}

int vham_seg_feed(vham_seg_t *s, uint16_t class_id, uint32_t seq,
                  uint32_t total_len, uint32_t offset,
                  const uint8_t *frag, size_t frag_len,
                  const uint8_t **out_buf, size_t *out_len) {
    if (!s || !frag || total_len > VHAM_SEG_BUF_MAX) return -1;
    if (offset + frag_len > total_len) return -1;

    vham_seg_entry_t *e = find_or_alloc(s, class_id, seq);
    if (!e) return -1;
    if (e->total_len == 0) e->total_len = total_len;
    if (e->total_len != total_len) return -1;

    memcpy(e->data + offset, frag, frag_len);
    e->received_len += (uint32_t)frag_len;

    if (e->received_len >= e->total_len) {
        if (out_buf) *out_buf = e->data;
        if (out_len) *out_len = e->total_len;
        return 1;
    }
    return 0;
}

void vham_seg_release(vham_seg_t *s, uint16_t class_id, uint32_t seq) {
    if (!s) return;
    for (int i = 0; i < VHAM_SEG_ENTRIES; ++i) {
        vham_seg_entry_t *e = &s->entry[i];
        if (e->in_use && e->class_id == class_id && e->seq == seq) {
            e->in_use = 0;
            return;
        }
    }
}
