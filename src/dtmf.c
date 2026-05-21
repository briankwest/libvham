/* libvham/src/dtmf.c — RFC 4733 telephone-event payload.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/dtmf.h"

int vham_dtmf_build(const vham_dtmf_event_t *e, void *out_, size_t out_cap) {
    if (!e || !out_ || out_cap < 4) return -1;
    if (e->volume > 63 || e->event > 0x7F) return -1;
    uint8_t *p = (uint8_t *)out_;
    p[0] = e->event;
    p[1] = (uint8_t)((e->end ? 0x80 : 0) |
                     ((e->reserved & 0x01) << 6) |
                     (e->volume & 0x3F));
    p[2] = (uint8_t)(e->duration >> 8);
    p[3] = (uint8_t)(e->duration);
    return 4;
}

int vham_dtmf_parse(const void *buf_, size_t len, vham_dtmf_event_t *e) {
    if (!buf_ || !e || len < 4) return -1;
    const uint8_t *p = (const uint8_t *)buf_;
    e->event    = p[0];
    e->end      = (uint8_t)((p[1] >> 7) & 1);
    e->reserved = (uint8_t)((p[1] >> 6) & 1);
    e->volume   = (uint8_t)(p[1] & 0x3F);
    e->duration = (uint16_t)(((uint16_t)p[2] << 8) | p[3]);
    return 0;
}

int vham_dtmf_from_char(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c == '*') return VHAM_DTMF_STAR;
    if (c == '#') return VHAM_DTMF_POUND;
    if (c >= 'A' && c <= 'D') return VHAM_DTMF_A + (c - 'A');
    if (c >= 'a' && c <= 'd') return VHAM_DTMF_A + (c - 'a');
    return -1;
}
