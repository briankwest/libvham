/* libvham/src/codec_ilbc.c — iLBC backend via libilbc (WebRTC iLBC, BSD).
 *
 * The radio's idt.ini specifies:
 *   [RTP_AUDIO_0] CODE=106 PKGTIME=60
 * meaning iLBC at PT 106 (dynamic) with 60 ms packetization — three
 * 20 ms iLBC frames per RTP packet, 38 bytes each → 114-byte payload.
 *
 * The encoder accepts EITHER:
 *   n_samples == 160 (20 ms, one frame, 38 bytes out)
 *   n_samples == 480 (60 ms, three frames, 114 bytes out — what the
 *                     radio uses on the wire)
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
#define ILBC_PKT_SAMPLES    480      /* 60 ms = 3 × 20 ms */
#define ILBC_PKT_BYTES      (ILBC_FRAME_BYTES * 3)

static int ilbc_enc(vham_audio_codec_t *c,
                    const int16_t *pcm, size_t n_samples,
                    uint8_t *out, size_t out_cap) {
    ilbc_state_t *s = (ilbc_state_t *)c->state;
    if (!s || !s->enc) return -1;
    if (n_samples == ILBC_FRAME_SAMPLES) {
        if (out_cap < ILBC_FRAME_BYTES) return -1;
        return WebRtcIlbcfix_Encode(s->enc, pcm, n_samples, out);
    }
    if (n_samples == ILBC_PKT_SAMPLES) {
        if (out_cap < ILBC_PKT_BYTES) return -1;
        int total = 0;
        for (int i = 0; i < 3; ++i) {
            int n = WebRtcIlbcfix_Encode(s->enc,
                                         pcm + i * ILBC_FRAME_SAMPLES,
                                         ILBC_FRAME_SAMPLES,
                                         out + total);
            if (n != ILBC_FRAME_BYTES) return -1;
            total += n;
        }
        return total;
    }
    return -1;
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
    .payload_type = 106, .name = "iLBC", .clock_rate = 8000,
    .channels = 1, .frame_samples = ILBC_PKT_SAMPLES,   /* 60 ms default */
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
