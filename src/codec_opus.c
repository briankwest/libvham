/* libvham/src/codec_opus.c — Opus backend for the codec dispatch table.
 *
 * Only compiled when VHAM_WITH_OPUS is set at build time. Links
 * against libopus (https://opus-codec.org/, BSD-3-Clause).
 *
 * Default config: 48 kHz mono, 20 ms frames (960 samples). PT 106
 * matches the binary's default audio codec choice (`idt.ini`).
 *
 * The codec dispatch interface fixes `frame_samples` per codec, so
 * encoding a frame must consume exactly 960 samples. The voice layer
 * sees Opus as "another 20 ms codec" and slots in transparently.
 *
 * SPDX-License-Identifier: MIT
 */
#ifdef VHAM_WITH_OPUS

#include <opus.h>
#include <stdlib.h>
#include <string.h>

#include "vham/codec_audio.h"

/* Opus at 48 kHz, mono, 20 ms = 960 samples per frame. */
#define OPUS_PT             106
#define OPUS_CLOCK_RATE     48000
#define OPUS_CHANNELS       1
#define OPUS_FRAME_SAMPLES  960
#define OPUS_MAX_PAYLOAD    1276        /* per RFC 6716 */

typedef struct {
    OpusEncoder *enc;
    OpusDecoder *dec;
} opus_state_t;

static opus_state_t g_state;

static int opus_enc(vham_audio_codec_t *c,
                    const int16_t *pcm, size_t n_samples,
                    uint8_t *out, size_t out_cap) {
    opus_state_t *s = (opus_state_t *)c->state;
    if (!s || !s->enc) return -1;
    if (n_samples != OPUS_FRAME_SAMPLES) return -1;
    if (out_cap > INT32_MAX) out_cap = OPUS_MAX_PAYLOAD;
    int n = opus_encode(s->enc, pcm, (int)n_samples, out, (opus_int32)out_cap);
    return n < 0 ? -1 : n;
}

static int opus_dec(vham_audio_codec_t *c,
                    const uint8_t *in, size_t in_len,
                    int16_t *pcm, size_t pcm_cap) {
    opus_state_t *s = (opus_state_t *)c->state;
    if (!s || !s->dec) return -1;
    int max = (int)(pcm_cap < OPUS_FRAME_SAMPLES ? pcm_cap : OPUS_FRAME_SAMPLES);
    int n = opus_decode(s->dec, in, (opus_int32)in_len, pcm, max, 0);
    return n < 0 ? -1 : n;
}

static vham_audio_codec_t opus_codec = {
    .payload_type   = OPUS_PT,
    .name           = "opus",
    .clock_rate     = OPUS_CLOCK_RATE,
    .channels       = OPUS_CHANNELS,
    .frame_samples  = OPUS_FRAME_SAMPLES,
    .encode         = opus_enc,
    .decode         = opus_dec,
    .state          = &g_state,
};

vham_audio_codec_t *vham_opus_codec(void) {
    if (!g_state.enc) {
        int err = 0;
        g_state.enc = opus_encoder_create(OPUS_CLOCK_RATE, OPUS_CHANNELS,
                                          OPUS_APPLICATION_VOIP, &err);
        if (err != OPUS_OK) { g_state.enc = NULL; return NULL; }
        /* PoC-friendly: full-band quality, light CBR-ish bitrate. */
        opus_encoder_ctl(g_state.enc, OPUS_SET_BITRATE(24000));
        opus_encoder_ctl(g_state.enc, OPUS_SET_INBAND_FEC(1));
        opus_encoder_ctl(g_state.enc, OPUS_SET_PACKET_LOSS_PERC(5));
    }
    if (!g_state.dec) {
        int err = 0;
        g_state.dec = opus_decoder_create(OPUS_CLOCK_RATE, OPUS_CHANNELS, &err);
        if (err != OPUS_OK) { g_state.dec = NULL; return NULL; }
    }
    return &opus_codec;
}

#endif /* VHAM_WITH_OPUS */
