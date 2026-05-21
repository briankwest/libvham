/* libvham/include/vham/retx.h — TAP-level retransmit tracker.
 *
 * The protocol uses application-level ACKs (TAP flag 0x0001) instead
 * of a transport-level retry mechanism. Mirrors `ReTrans::Send` /
 * `TAP::TapReTransSendFunc` in libsvcapi.
 *
 * Usage:
 *
 *   vham_retx_t r;
 *   vham_retx_init(&r);
 *
 *   // On send:
 *   vham_retx_track(&r, class_id, seq, buf, len, monotonic_ms);
 *
 *   // On ACK (frame has flag 0x0001):
 *   vham_retx_ack(&r, class_id, seq);
 *
 *   // Periodically:
 *   vham_retx_pkt_t *p;
 *   while ((p = vham_retx_next_due(&r, now_ms, retry_ms)) != NULL) {
 *       send(fd, p->buf, p->len);
 *       p->retries++;
 *       p->sent_at_ms = now_ms;
 *   }
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_RETX_H
#define VHAM_RETX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHAM_RETX_CAP       16
#define VHAM_RETX_PAYLOAD   1500
#define VHAM_RETX_MAX_TRIES 3

typedef struct {
    int      in_use;
    uint16_t class_id;
    uint32_t seq;
    uint8_t  buf[VHAM_RETX_PAYLOAD];
    uint16_t len;
    uint64_t sent_at_ms;
    uint8_t  retries;
} vham_retx_pkt_t;

typedef struct {
    vham_retx_pkt_t slot[VHAM_RETX_CAP];
    uint32_t        gave_up;          /* count of frames that exceeded retries */
} vham_retx_t;

void vham_retx_init(vham_retx_t *r);

/* Register an outbound frame. Returns 0 on success, -1 if full. */
int  vham_retx_track(vham_retx_t *r, uint16_t class_id, uint32_t seq,
                     const void *buf, size_t len, uint64_t now_ms);

/* Clear the slot matching (class_id, seq). Returns 1 if matched. */
int  vham_retx_ack(vham_retx_t *r, uint16_t class_id, uint32_t seq);

/* Find one frame whose retry timer is due. The caller resends and
 * updates `sent_at_ms` + `retries` (or `vham_retx_mark_resent`).
 * Returns NULL when nothing is due. */
vham_retx_pkt_t *vham_retx_next_due(vham_retx_t *r,
                                    uint64_t now_ms, uint32_t retry_ms);

/* Convenience: bump the retry counter and timestamp, or drop the
 * entry if MAX_TRIES exceeded. */
void vham_retx_mark_resent(vham_retx_t *r, vham_retx_pkt_t *p,
                           uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_RETX_H */
