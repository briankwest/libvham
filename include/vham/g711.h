/* libvham/include/vham/g711.h — ITU-T G.711 PCMU (µ-law) and PCMA (A-law)
 *
 * Reference implementation, no lookup tables — direct formulas straight
 * from the standard. 8 kHz mono, 16-bit signed PCM ↔ 8-bit codewords.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_G711_H
#define VHAM_G711_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-sample conversions */
uint8_t vham_g711_linear_to_ulaw(int16_t sample);
int16_t vham_g711_ulaw_to_linear(uint8_t mu);
uint8_t vham_g711_linear_to_alaw(int16_t sample);
int16_t vham_g711_alaw_to_linear(uint8_t a);

/* Buffer conversions. Encoders compress n samples into n bytes;
 * decoders expand n codewords into n int16 samples. */
void vham_g711_encode_ulaw(const int16_t *pcm, size_t n, uint8_t *out);
void vham_g711_decode_ulaw(const uint8_t *in, size_t n, int16_t *pcm);
void vham_g711_encode_alaw(const int16_t *pcm, size_t n, uint8_t *out);
void vham_g711_decode_alaw(const uint8_t *in, size_t n, int16_t *pcm);

#ifdef __cplusplus
}
#endif

#endif
