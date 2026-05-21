/* libvham/include/vham/jitter.h — RTP jitter buffer.
 *
 * Small, deterministic buffer keyed on RTP timestamp. Use:
 *
 *   vham_jitter_init(&jb, 8000, 60);   // 8 kHz clock, 60 ms target
 *   for (each rx packet) {
 *       vham_jitter_push(&jb, &pkt);
 *   }
 *   vham_jitter_pkt_t out;
 *   while (vham_jitter_pop(&jb, &out)) { ... }
 *
 * Late packets are dropped (counted in `lost`); out-of-order packets
 * are inserted at the right slot. Memory is fixed-size — the buffer
 * holds up to VHAM_JITTER_CAP packets.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_JITTER_H
#define VHAM_JITTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_JITTER_CAP        16
#define VHAM_JITTER_PAYLOAD    1500

typedef struct {
    uint32_t timestamp;
    uint16_t seq;
    uint16_t length;
    uint8_t  payload[VHAM_JITTER_PAYLOAD];
    int      in_use;
} vham_jitter_pkt_t;

typedef struct {
    uint32_t          clock_rate;     /* Hz */
    uint32_t          target_ms;      /* desired buffer depth in ms */
    uint32_t          base_ts;        /* timestamp of next packet to pop */
    int               base_set;
    int               started;        /* false until buffer has filled to target */
    vham_jitter_pkt_t slot[VHAM_JITTER_CAP];

    /* stats (reset on init) */
    uint32_t          rx_count;
    uint32_t          dropped_late;
    uint32_t          dropped_dup;
    uint32_t          delivered;
} vham_jitter_t;

void vham_jitter_init(vham_jitter_t *jb, uint32_t clock_rate, uint32_t target_ms);

/* Push a received packet. Returns 0 on success, -1 if dropped (late
 * or duplicate or buffer full). */
int  vham_jitter_push(vham_jitter_t *jb, uint16_t seq, uint32_t timestamp,
                      const uint8_t *payload, size_t length);

/* Pop the next packet in playout order. Returns 1 if `out` populated,
 * 0 if nothing is ready yet. */
int  vham_jitter_pop(vham_jitter_t *jb, vham_jitter_pkt_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_JITTER_H */
