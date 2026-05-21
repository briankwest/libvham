/* libvham/src/g711.c — ITU-T G.711 µ-law and A-law.
 *
 * Direct port of the Sun Microsystems g711.c reference
 * implementation (public domain), which is the canonical reference
 * implementation cited by every other G.711 implementation.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/g711.h"

#define ULAW_BIAS  0x84
#define ULAW_CLIP  32635

/* Segment thresholds for µ-law and A-law (used to find the segment
 * number given a magnitude). Linear search beats branchless tricks
 * here for clarity. */
static int seg_search(int val, const short *table, int n) {
    for (int i = 0; i < n; ++i) {
        if (val <= table[i]) return i;
    }
    return n;
}

/* ---------- µ-law (PCMU, payload type 0) ---------- */

static const short u_seg_end[8] = {
    0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF, 0x3FFF, 0x7FFF
};

uint8_t vham_g711_linear_to_ulaw(int16_t pcm) {
    int sign = (pcm >> 8) & 0x80;
    int mag  = sign ? -pcm : pcm;
    if (mag > ULAW_CLIP) mag = ULAW_CLIP;
    mag += ULAW_BIAS;

    int seg = seg_search(mag, u_seg_end, 8);
    if (seg >= 8) return (uint8_t)(0x7F ^ sign);  /* shouldn't happen after CLIP */
    int u = ((seg << 4) | ((mag >> (seg + 3)) & 0x0F));
    return (uint8_t)(~(u | sign) & 0xFF);
}

int16_t vham_g711_ulaw_to_linear(uint8_t mu) {
    int u = ~mu & 0xFF;
    int t = ((u & 0x0F) << 3) + ULAW_BIAS;
    t <<= (u & 0x70) >> 4;
    return (int16_t)((u & 0x80) ? (ULAW_BIAS - t) : (t - ULAW_BIAS));
}

/* ---------- A-law (PCMA, payload type 8) ---------- */

#define ALAW_AMI_MASK 0x55

static const short a_seg_end[8] = {
    0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF
};

uint8_t vham_g711_linear_to_alaw(int16_t pcm_in) {
    /* A-law operates on 13-bit input; drop the bottom 3 bits. */
    int pcm = pcm_in >> 3;
    int mask;
    if (pcm >= 0) {
        mask = 0xD5;   /* sign + AMI alternation */
    } else {
        mask = 0x55;
        pcm = -pcm - 1;
    }
    int seg = seg_search(pcm, a_seg_end, 8);
    if (seg >= 8) return (uint8_t)(0x7F ^ mask);
    int a = seg << 4;
    if (seg < 2) {
        a |= (pcm >> 1) & 0x0F;
    } else {
        a |= (pcm >> seg) & 0x0F;
    }
    return (uint8_t)(a ^ mask);
}

int16_t vham_g711_alaw_to_linear(uint8_t a) {
    int v = a ^ ALAW_AMI_MASK;
    int seg = (v & 0x70) >> 4;
    int t = (v & 0x0F) << 4;
    switch (seg) {
    case 0:  t += 8;       break;
    case 1:  t += 0x108;   break;
    default: t += 0x108;  t <<= seg - 1;
    }
    return (int16_t)((v & 0x80) ? t : -t);
}

/* ---------- Buffer convenience wrappers ---------- */

void vham_g711_encode_ulaw(const int16_t *pcm, size_t n, uint8_t *out) {
    for (size_t i = 0; i < n; ++i) out[i] = vham_g711_linear_to_ulaw(pcm[i]);
}
void vham_g711_decode_ulaw(const uint8_t *in, size_t n, int16_t *pcm) {
    for (size_t i = 0; i < n; ++i) pcm[i] = vham_g711_ulaw_to_linear(in[i]);
}
void vham_g711_encode_alaw(const int16_t *pcm, size_t n, uint8_t *out) {
    for (size_t i = 0; i < n; ++i) out[i] = vham_g711_linear_to_alaw(pcm[i]);
}
void vham_g711_decode_alaw(const uint8_t *in, size_t n, int16_t *pcm) {
    for (size_t i = 0; i < n; ++i) pcm[i] = vham_g711_alaw_to_linear(in[i]);
}
