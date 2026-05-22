/* libvham/src/codec_amr.c — AMR-NB + AMR-WB backends.
 *
 * AMR-NB uses libopencore-amrnb (LGPL/Apache-2.0).
 * AMR-WB encoder uses libvo-amrwbenc, decoder uses libopencore-amrwb.
 *
 * Frame sizes:
 *   AMR-NB:  8 kHz, 20 ms = 160 samples in,  32 bytes out (MR122)
 *   AMR-WB: 16 kHz, 20 ms = 320 samples in,  61 bytes out (mode 8 = 23.85)
 *
 * Enabled with VHAM_WITH_AMR at build time.
 *
 * SPDX-License-Identifier: MIT
 */
#ifdef VHAM_WITH_AMR

#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrnb/interf_dec.h>
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>
#include <stdlib.h>
#include <string.h>

#include "vham/codec_audio.h"

/* ---------- AMR-NB (PT 96) ---------- */
typedef struct {
    void *enc;
    void *dec;
} amrnb_state_t;
static amrnb_state_t g_nb;

static int amrnb_enc(vham_audio_codec_t *c,
                     const int16_t *pcm, size_t n_samples,
                     uint8_t *out, size_t out_cap) {
    amrnb_state_t *s = (amrnb_state_t *)c->state;
    if (!s || !s->enc || n_samples != 160 || out_cap < 32) return -1;
    /* MR122 = 12.2 kbps = best quality, 32-byte frame */
    int n = Encoder_Interface_Encode(s->enc, MR122, pcm, out, 0);
    return n < 0 ? -1 : n;
}

static int amrnb_dec(vham_audio_codec_t *c,
                     const uint8_t *in, size_t in_len,
                     int16_t *pcm, size_t pcm_cap) {
    amrnb_state_t *s = (amrnb_state_t *)c->state;
    if (!s || !s->dec || pcm_cap < 160 || in_len < 1) return -1;
    Decoder_Interface_Decode(s->dec, in, pcm, 0);
    return 160;
}

static vham_audio_codec_t amrnb = {
    .payload_type = 96, .name = "AMR", .clock_rate = 8000,
    .channels = 1, .frame_samples = 160,
    .encode = amrnb_enc, .decode = amrnb_dec,
    .state = &g_nb,
};

vham_audio_codec_t *vham_amrnb_codec(void) {
    if (!g_nb.enc) g_nb.enc = Encoder_Interface_init(0);
    if (!g_nb.dec) g_nb.dec = Decoder_Interface_init();
    return (g_nb.enc && g_nb.dec) ? &amrnb : NULL;
}

/* ---------- AMR-WB (PT 97) ---------- */
typedef struct {
    void *enc;
    void *dec;
} amrwb_state_t;
static amrwb_state_t g_wb;

static int amrwb_enc(vham_audio_codec_t *c,
                     const int16_t *pcm, size_t n_samples,
                     uint8_t *out, size_t out_cap) {
    amrwb_state_t *s = (amrwb_state_t *)c->state;
    if (!s || !s->enc || n_samples != 320 || out_cap < 61) return -1;
    /* Mode 8 = 23.85 kbps, max quality.
     *
     * NB: E_IF_encode writes 3GPP TS 26.201 §A.2 IF1 storage format
     * (one header byte + speech). That isn't a valid RTP payload —
     * RFC 4867 §4.3 (bandwidth-efficient) or §4.4 (octet-aligned)
     * rearranges the same bits into a CMR + ToC + speech layout.
     *
     * Today this is fine for offline round-trip tests (encode →
     * decode in the same lib), but for wire interop a 50-LOC
     * IF1 → octet-aligned wrapper is still missing. See
     * protocol-spec/99-audit.md "Known wire-format gap". */
    int n = E_IF_encode(s->enc, 8, pcm, out, 0);
    return n < 0 ? -1 : n;
}

static int amrwb_dec(vham_audio_codec_t *c,
                     const uint8_t *in, size_t in_len,
                     int16_t *pcm, size_t pcm_cap) {
    amrwb_state_t *s = (amrwb_state_t *)c->state;
    if (!s || !s->dec || pcm_cap < 320 || in_len < 1) return -1;
    D_IF_decode(s->dec, in, pcm, 0);
    return 320;
}

static vham_audio_codec_t amrwb = {
    .payload_type = 97, .name = "AMR-WB", .clock_rate = 16000,
    .channels = 1, .frame_samples = 320,
    .encode = amrwb_enc, .decode = amrwb_dec,
    .state = &g_wb,
};

vham_audio_codec_t *vham_amrwb_codec(void) {
    if (!g_wb.enc) g_wb.enc = E_IF_init();
    if (!g_wb.dec) g_wb.dec = D_IF_init();
    return (g_wb.enc && g_wb.dec) ? &amrwb : NULL;
}

#endif /* VHAM_WITH_AMR */
