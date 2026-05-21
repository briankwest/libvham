/* libvham/src/codec_audio.c — codec dispatch + G.711 backends.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/codec_audio.h"
#include "vham/g711.h"

#define VHAM_CODEC_TABLE_MAX 8

static vham_audio_codec_t *g_table[VHAM_CODEC_TABLE_MAX];
static size_t              g_count;
static int                 g_initialized;

/* --- G.711 µ-law (PT 0) --- */

static int pcmu_encode(vham_audio_codec_t *c, const int16_t *pcm,
                       size_t n_samples, uint8_t *out, size_t out_cap) {
    (void)c;
    if (n_samples != 160 || out_cap < 160) return -1;
    vham_g711_encode_ulaw(pcm, n_samples, out);
    return 160;
}

static int pcmu_decode(vham_audio_codec_t *c, const uint8_t *in,
                       size_t in_len, int16_t *pcm, size_t pcm_cap) {
    (void)c;
    if (in_len > pcm_cap) return -1;
    vham_g711_decode_ulaw(in, in_len, pcm);
    return (int)in_len;
}

static vham_audio_codec_t pcmu = {
    .payload_type = 0,  .name = "PCMU", .clock_rate = 8000,
    .channels = 1, .frame_samples = 160,
    .encode = pcmu_encode, .decode = pcmu_decode,
};

/* --- G.711 A-law (PT 8) --- */

static int pcma_encode(vham_audio_codec_t *c, const int16_t *pcm,
                       size_t n_samples, uint8_t *out, size_t out_cap) {
    (void)c;
    if (n_samples != 160 || out_cap < 160) return -1;
    vham_g711_encode_alaw(pcm, n_samples, out);
    return 160;
}

static int pcma_decode(vham_audio_codec_t *c, const uint8_t *in,
                       size_t in_len, int16_t *pcm, size_t pcm_cap) {
    (void)c;
    if (in_len > pcm_cap) return -1;
    vham_g711_decode_alaw(in, in_len, pcm);
    return (int)in_len;
}

static vham_audio_codec_t pcma = {
    .payload_type = 8,  .name = "PCMA", .clock_rate = 8000,
    .channels = 1, .frame_samples = 160,
    .encode = pcma_encode, .decode = pcma_decode,
};

/* --- Optional codec backends. When their lib is linked at build
 * time, the real encoder/decoder is registered. Without it, a
 * "unsupported" stub stays in the table so SDP code can still
 * reference the PT — encode/decode just return -1. --- */

#ifdef VHAM_WITH_OPUS
extern vham_audio_codec_t *vham_opus_codec(void);
#endif
#ifdef VHAM_WITH_AMR
extern vham_audio_codec_t *vham_amrnb_codec(void);
extern vham_audio_codec_t *vham_amrwb_codec(void);
#endif
#ifdef VHAM_WITH_ILBC
extern vham_audio_codec_t *vham_ilbc_codec(void);
#endif

static int unsupported_encode(vham_audio_codec_t *c,
                              const int16_t *pcm, size_t n,
                              uint8_t *out, size_t out_cap) {
    (void)c; (void)pcm; (void)n; (void)out; (void)out_cap;
    return -1;
}
static int unsupported_decode(vham_audio_codec_t *c,
                              const uint8_t *in, size_t in_len,
                              int16_t *pcm, size_t pcm_cap) {
    (void)c; (void)in; (void)in_len; (void)pcm; (void)pcm_cap;
    return -1;
}

static vham_audio_codec_t amrnb_stub = {
    .payload_type = 96, .name = "AMR", .clock_rate = 8000,
    .channels = 1, .frame_samples = 160,
    .encode = unsupported_encode, .decode = unsupported_decode,
};
static vham_audio_codec_t amrwb_stub = {
    .payload_type = 97, .name = "AMR-WB", .clock_rate = 16000,
    .channels = 1, .frame_samples = 320,
    .encode = unsupported_encode, .decode = unsupported_decode,
};
static vham_audio_codec_t ilbc_stub = {
    .payload_type = 102, .name = "iLBC", .clock_rate = 8000,
    .channels = 1, .frame_samples = 160,
    .encode = unsupported_encode, .decode = unsupported_decode,
};

void vham_codec_init(void) {
    if (g_initialized) return;
    vham_codec_register(&pcmu);
    vham_codec_register(&pcma);

#ifdef VHAM_WITH_AMR
    vham_audio_codec_t *a = vham_amrnb_codec();
    vham_codec_register(a ? a : &amrnb_stub);
    vham_audio_codec_t *aw = vham_amrwb_codec();
    vham_codec_register(aw ? aw : &amrwb_stub);
#else
    vham_codec_register(&amrnb_stub);
    vham_codec_register(&amrwb_stub);
#endif

#ifdef VHAM_WITH_ILBC
    vham_audio_codec_t *il = vham_ilbc_codec();
    vham_codec_register(il ? il : &ilbc_stub);
#else
    vham_codec_register(&ilbc_stub);
#endif

#ifdef VHAM_WITH_OPUS
    vham_audio_codec_t *o = vham_opus_codec();
    if (o) vham_codec_register(o);
#endif
    g_initialized = 1;
}

int vham_codec_register(vham_audio_codec_t *c) {
    if (!c || g_count >= VHAM_CODEC_TABLE_MAX) return -1;
    g_table[g_count++] = c;
    return 0;
}

vham_audio_codec_t *vham_codec_by_pt(uint8_t pt) {
    vham_codec_init();
    for (size_t i = 0; i < g_count; ++i)
        if (g_table[i]->payload_type == pt) return g_table[i];
    return NULL;
}
