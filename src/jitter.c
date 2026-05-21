/* libvham/src/jitter.c — RTP jitter buffer.
 *
 * Implementation: fixed-size array indexed by (timestamp - base_ts) /
 * frame_samples. Newest sample timestamp tracked so we can decide
 * when the buffer is "full enough" to start playout.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/jitter.h"

void vham_jitter_init(vham_jitter_t *jb, uint32_t clock_rate, uint32_t target_ms) {
    memset(jb, 0, sizeof *jb);
    jb->clock_rate = clock_rate ? clock_rate : 8000;
    jb->target_ms  = target_ms  ? target_ms  : 60;
}

/* Find the slot for `timestamp`. If the buffer hasn't started playout
 * yet and `timestamp` is earlier than the current base, recenter the
 * buffer to that earlier timestamp (shifting slots right). Returns -1
 * if the packet is late (after playout started) or out of range. */
static int slot_for(vham_jitter_t *jb, uint32_t timestamp,
                    uint32_t frame_ts_step) {
    if (frame_ts_step == 0) frame_ts_step = 160;
    if (!jb->base_set) {
        jb->base_ts  = timestamp;
        jb->base_set = 1;
    }

    int32_t delta = (int32_t)(timestamp - jb->base_ts);
    if (delta < 0) {
        if (jb->started) return -1;                        /* truly late */
        /* Recenter: shift existing slots right by `shift` and lower base. */
        int shift = (int)((-delta) / (int32_t)frame_ts_step);
        if (shift <= 0 || shift >= VHAM_JITTER_CAP) return -1;
        for (int i = VHAM_JITTER_CAP - 1; i >= shift; --i)
            jb->slot[i] = jb->slot[i - shift];
        for (int i = 0; i < shift; ++i)
            jb->slot[i].in_use = 0;
        jb->base_ts -= (uint32_t)shift * frame_ts_step;
        delta = (int32_t)(timestamp - jb->base_ts);
    }
    int slot = (int)(delta / (int32_t)frame_ts_step);
    if (slot < 0 || slot >= VHAM_JITTER_CAP) return -1;
    return slot;
}

int vham_jitter_push(vham_jitter_t *jb, uint16_t seq, uint32_t timestamp,
                     const uint8_t *payload, size_t length) {
    if (!jb || !payload || length > VHAM_JITTER_PAYLOAD) return -1;
    jb->rx_count++;

    /* Step = 20 ms worth of samples at the configured clock rate. */
    uint32_t step = (jb->clock_rate * 20) / 1000;
    if (step == 0) step = 160;

    int slot = slot_for(jb, timestamp, step);
    if (slot < 0) {
        jb->dropped_late++;
        return -1;
    }
    if (jb->slot[slot].in_use) {
        jb->dropped_dup++;
        return -1;
    }
    jb->slot[slot].seq       = seq;
    jb->slot[slot].timestamp = timestamp;
    jb->slot[slot].length    = (uint16_t)length;
    memcpy(jb->slot[slot].payload, payload, length);
    jb->slot[slot].in_use    = 1;

    /* Start delivering once we've accumulated target_ms of audio. */
    if (!jb->started) {
        uint32_t depth_samples = (uint32_t)(slot + 1) * step;
        uint32_t depth_ms = (depth_samples * 1000) / jb->clock_rate;
        if (depth_ms >= jb->target_ms) jb->started = 1;
    }
    return 0;
}

int vham_jitter_pop(vham_jitter_t *jb, vham_jitter_pkt_t *out) {
    if (!jb || !out || !jb->started) return 0;

    uint32_t step = (jb->clock_rate * 20) / 1000;
    if (step == 0) step = 160;

    /* The slot for `base_ts` is always slot 0. If it has data,
     * deliver it; otherwise return nothing (caller PLC's). */
    if (jb->slot[0].in_use) {
        *out = jb->slot[0];
        out->in_use = 1;
        jb->delivered++;
    } else {
        return 0;
    }

    /* Shift the array left by one and advance base. */
    for (int i = 0; i + 1 < VHAM_JITTER_CAP; ++i)
        jb->slot[i] = jb->slot[i + 1];
    jb->slot[VHAM_JITTER_CAP - 1].in_use = 0;
    jb->base_ts += step;
    return 1;
}
