/* libvham/include/vham/codec_audio.h — codec dispatch table.
 *
 * Provides a uniform `vham_audio_codec_t` interface so the voice
 * path can encode/decode against PCMU/PCMA today and Opus/AMR/iLBC
 * tomorrow without touching the call setup or RTP layers.
 *
 * Built-in backends:
 *   PT 0   PCMU (G.711 µ-law) — always available
 *   PT 8   PCMA (G.711 A-law) — always available
 *   PT 106 Opus               — present if VHAM_WITH_OPUS at build
 *
 * Backends register at startup via `vham_codec_register`.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_CODEC_AUDIO_H
#define VHAM_CODEC_AUDIO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vham_audio_codec vham_audio_codec_t;

struct vham_audio_codec {
    uint8_t      payload_type;
    const char  *name;            /* "PCMU", "PCMA", "opus", ... */
    uint32_t     clock_rate;      /* 8000 / 16000 / 48000 ... */
    uint8_t      channels;
    uint16_t     frame_samples;   /* samples per 20 ms frame at clock_rate */

    /* Encode `n_samples` of 16-bit PCM into `out` (caller-allocated).
     * Returns bytes written, -1 on error. The encoder must consume
     * exactly `frame_samples` samples per call. */
    int (*encode)(vham_audio_codec_t *c,
                  const int16_t *pcm, size_t n_samples,
                  uint8_t *out, size_t out_cap);

    /* Decode `in_len` bytes into `pcm` (caller-allocated for
     * `frame_samples`). Returns samples written, -1 on error. */
    int (*decode)(vham_audio_codec_t *c,
                  const uint8_t *in, size_t in_len,
                  int16_t *pcm, size_t pcm_cap);

    void  *state;                 /* backend-private */
};

/* Look up a codec by RTP payload type. Returns NULL if unsupported.
 * The returned pointer is valid for process lifetime. */
vham_audio_codec_t *vham_codec_by_pt(uint8_t pt);

/* Register a codec backend. Called by the built-in backends at
 * startup via constructors. Returns 0 on success, -1 on overflow. */
int vham_codec_register(vham_audio_codec_t *c);

/* Force-initialize the built-in table. Must be called before any
 * vham_codec_by_pt(). The voice path calls this implicitly. */
void vham_codec_init(void);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_CODEC_AUDIO_H */
