/* libvham/include/vham/dtmf.h — RFC 4733 telephone-event payload.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     event     |E|R| volume    |          duration             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_DTMF_H
#define VHAM_DTMF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Event codes: 0..9, *=10, #=11, A..D=12..15 */
enum vham_dtmf_event {
    VHAM_DTMF_0 = 0,  VHAM_DTMF_1, VHAM_DTMF_2, VHAM_DTMF_3,
    VHAM_DTMF_4, VHAM_DTMF_5, VHAM_DTMF_6, VHAM_DTMF_7,
    VHAM_DTMF_8, VHAM_DTMF_9,
    VHAM_DTMF_STAR  = 10,
    VHAM_DTMF_POUND = 11,
    VHAM_DTMF_A     = 12,
    VHAM_DTMF_B     = 13,
    VHAM_DTMF_C     = 14,
    VHAM_DTMF_D     = 15,
    VHAM_DTMF_FLASH = 16,
};

typedef struct {
    uint8_t  event;      /* see vham_dtmf_event */
    uint8_t  end;        /* 1 = end-of-event (final packet for this tone) */
    uint8_t  reserved;   /* always 0 */
    uint8_t  volume;     /* 0..63, in -dBm0 (e.g. 10 = -10 dBm0) */
    uint16_t duration;   /* in timestamp units (8000 Hz → 8/ms) */
} vham_dtmf_event_t;

/* Encode the 4-byte RFC 4733 payload. Returns 4 on success, -1 on error. */
int vham_dtmf_build(const vham_dtmf_event_t *e, void *out, size_t out_cap);

/* Decode a 4-byte payload. Returns 0 on success, -1 if buffer too small. */
int vham_dtmf_parse(const void *buf, size_t len, vham_dtmf_event_t *e);

/* Map an ASCII digit to a DTMF event code (-1 if unknown). */
int vham_dtmf_from_char(char c);

#ifdef __cplusplus
}
#endif

#endif
