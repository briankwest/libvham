/* libvham/src/retx.c — TAP retransmit tracker.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/retx.h"

void vham_retx_init(vham_retx_t *r) {
    if (r) memset(r, 0, sizeof *r);
}

int vham_retx_track(vham_retx_t *r, uint16_t class_id, uint32_t seq,
                    const void *buf, size_t len, uint64_t now_ms) {
    if (!r || !buf || len > VHAM_RETX_PAYLOAD) return -1;
    for (int i = 0; i < VHAM_RETX_CAP; ++i) {
        vham_retx_pkt_t *p = &r->slot[i];
        if (p->in_use) continue;
        p->in_use     = 1;
        p->class_id   = class_id;
        p->seq        = seq;
        p->len        = (uint16_t)len;
        p->sent_at_ms = now_ms;
        p->retries    = 0;
        memcpy(p->buf, buf, len);
        return 0;
    }
    return -1;                  /* full */
}

int vham_retx_ack(vham_retx_t *r, uint16_t class_id, uint32_t seq) {
    if (!r) return 0;
    for (int i = 0; i < VHAM_RETX_CAP; ++i) {
        vham_retx_pkt_t *p = &r->slot[i];
        if (p->in_use && p->class_id == class_id && p->seq == seq) {
            p->in_use = 0;
            return 1;
        }
    }
    return 0;
}

vham_retx_pkt_t *vham_retx_next_due(vham_retx_t *r,
                                    uint64_t now_ms, uint32_t retry_ms) {
    if (!r) return NULL;
    for (int i = 0; i < VHAM_RETX_CAP; ++i) {
        vham_retx_pkt_t *p = &r->slot[i];
        if (!p->in_use) continue;
        if (p->retries >= VHAM_RETX_MAX_TRIES) {
            p->in_use = 0;
            r->gave_up++;
            continue;
        }
        if (now_ms - p->sent_at_ms >= retry_ms) return p;
    }
    return NULL;
}

void vham_retx_mark_resent(vham_retx_t *r, vham_retx_pkt_t *p,
                           uint64_t now_ms) {
    if (!r || !p || !p->in_use) return;
    p->retries++;
    p->sent_at_ms = now_ms;
    if (p->retries >= VHAM_RETX_MAX_TRIES) {
        p->in_use = 0;
        r->gave_up++;
    }
}
