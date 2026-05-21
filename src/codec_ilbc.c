/* libvham/src/codec_ilbc.c — iLBC backend via libilbc (WebRTC iLBC, BSD).
 *
 * Configured for 20 ms frames at 8 kHz = 160 samples → 38 bytes/frame.
 * (Alternative 30 ms / 240 samples → 50 bytes/frame exists but the
 * audit-table reserves PT 102 for the 20 ms variant.)
 *
 * Enabled with VHAM_WITH_ILBC.
 *
 * SPDX-License-Identifier: MIT
 */
#ifdef VHAM_WITH_ILBC

#include <ilbc.h>
#include <stdlib.h>
#include <string.h>

#include "vham/codec_audio.h"

typedef struct {
    IlbcEncoderInstance *enc;
    IlbcDecoderInstance *dec;
} ilbc_state_t;
static ilbc_state_t g_state;

#define ILBC_FRAME_SAMPLES  160      /* 20 ms @ 8 kHz */
#define ILBC_FRAME_BYTES     38

static int ilbc_enc(vham_audio_codec_t *c,
                    const int16_t *pcm, size_t n_samples,
                    uint8_t *out, size_t out_cap) {
    ilbc_state_t *s = (ilbc_state_t *)c->state;
    if (!s || !s->enc) return -1;
    if (n_samples != ILBC_FRAME_SAMPLES) return -1;
    if (out_cap < ILBC_FRAME_BYTES) return -1;
    int n = WebRtcIlbcfix_Encode(s->enc, pcm, n_samples, out);
    return n;
}

static int ilbc_dec(vham_audio_codec_t *c,
                    const uint8_t *in, size_t in_len,
                    int16_t *pcm, size_t pcm_cap) {
    ilbc_state_t *s = (ilbc_state_t *)c->state;
    if (!s || !s->dec) return -1;
    if (pcm_cap < ILBC_FRAME_SAMPLES) return -1;
    int16_t speech_type = 0;
    int n = WebRtcIlbcfix_Decode(s->dec, in, in_len, pcm, &speech_type);
    return n;
}

static vham_audio_codec_t ilbc = {
    .payload_type = 102, .name = "iLBC", .clock_rate = 8000,
    .channels = 1, .frame_samples = ILBC_FRAME_SAMPLES,
    .encode = ilbc_enc, .decode = ilbc_dec,
    .state = &g_state,
};

vham_audio_codec_t *vham_ilbc_codec(void) {
    if (!g_state.enc) {
        WebRtcIlbcfix_EncoderCreate(&g_state.enc);
        if (!g_state.enc) return NULL;
        WebRtcIlbcfix_EncoderInit(g_state.enc, 20);
    }
    if (!g_state.dec) {
        WebRtcIlbcfix_DecoderCreate(&g_state.dec);
        if (!g_state.dec) return NULL;
        WebRtcIlbcfix_DecoderInit(g_state.dec, 20);
    }
    return &ilbc;
}

#endif /* VHAM_WITH_ILBC */
