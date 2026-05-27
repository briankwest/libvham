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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vham/codec_audio.h"

/* ---------- AMR-NB (PT 96) ---------- */
typedef struct {
    void *enc;
    void *dec;
} amrnb_state_t;
static amrnb_state_t g_nb;

/* AMR-NB mode → speech bits (per 3GPP TS 26.101 §3.6.1 / RFC 4867 §3.6). */
static const int amrnb_mode_bits[9] = {
    /* 0=4.75, 1=5.15, 2=5.90, 3=6.70, 4=7.40, 5=7.95, 6=10.2, 7=12.2, 8=SID */
    95, 103, 118, 134, 148, 159, 204, 244, 39
};

/* Convert an opencore-amrnb single-frame output (File/IF1 layout —
 * byte 0 = F|FT(4)|Q|RR, bytes 1..N = speech with low-bit padding) into
 * RFC 4867 §4.3 bandwidth-efficient single-frame payload, matching the
 * radio's `AMR_Convert_File_RTP_OneFrame @ 0x24a55c` byte-for-byte.
 *
 * Wire bits (single-frame, F=0):
 *   bits  0.. 3   CMR  (4)   — echoed as FT per the binary's convention
 *   bit   4       F    (1)   = 0
 *   bits  5.. 8   FT   (4)
 *   bit   9       Q    (1)
 *   bits 10..(10+speech_bits-1)  speech bits, MSB-first
 *   trailing bits to byte boundary = 0
 *
 * The binary's code uses `*pbVar8 * 0x40 | pbVar8[1] >> 2` — i.e. shift
 * each speech byte left by 6 and OR the next byte's top 6 bits — which
 * is the bit-aligned packing that matches the formula above.
 *
 * Returns total payload bytes written, or -1 if `out` is too small. */
static int amrnb_be_pack(const uint8_t *file_frame, int file_frame_len,
                         uint8_t mode, int speech_bits,
                         uint8_t *out, size_t out_cap) {
    int speech_bytes = (speech_bits + 7) / 8;
    if (1 + speech_bytes > file_frame_len) return -1;
    int total_bits  = 4 + 1 + 4 + 1 + speech_bits;  /* CMR+F+FT+Q+speech */
    int total_bytes = (total_bits + 7) / 8;
    if (out_cap < (size_t)total_bytes) return -1;
    memset(out, 0, (size_t)total_bytes);

    /* byte 0: CMR(=FT)(4) | F(1)=0 | FT[3:1](3) */
    out[0] = (uint8_t)((mode << 4) | (mode >> 1));
    /* byte 1 top bits: FT[0](1) | Q(1)=1 | speech[0..5] */
    out[1] = (uint8_t)(((mode & 0x01) << 7) | (1 << 6)
                       | (file_frame[1] >> 2));
    /* subsequent bytes: shift each speech byte left by 6 OR'd with next>>2 */
    for (int i = 1; i < speech_bytes; ++i) {
        uint8_t next = (i + 1 < speech_bytes) ? file_frame[i + 1] : 0;
        out[1 + i] = (uint8_t)((file_frame[i] << 6) | (next >> 2));
    }
    return total_bytes;
}

/* RFC 4867 §4.4 octet-aligned single-frame payload. CMR byte + ToC byte
 * + raw speech bytes (no bit shifting). Reserved in case the channel
 * requires `octet-align=1` instead of BE — currently unused. */
__attribute__((unused))
static int amrnb_oa_pack(const uint8_t *file_frame, int file_frame_len,
                         uint8_t mode, int speech_bits,
                         uint8_t *out, size_t out_cap) {
    int speech_bytes = (speech_bits + 7) / 8;
    if (1 + speech_bytes > file_frame_len) return -1;
    if (out_cap < (size_t)(2 + speech_bytes)) return -1;
    out[0] = 0xF0;                         /* CMR = no change requested */
    out[1] = (uint8_t)((mode << 3) | 0x04); /* ToC: F=0|FT|Q=1|RR=00 */
    memcpy(out + 2, file_frame + 1, (size_t)speech_bytes);
    return 2 + speech_bytes;
}

static int amrnb_enc(vham_audio_codec_t *c,
                     const int16_t *pcm, size_t n_samples,
                     uint8_t *out, size_t out_cap) {
    amrnb_state_t *s = (amrnb_state_t *)c->state;
    if (!s || !s->enc || n_samples != 160 || out_cap < 33) return -1;

    uint8_t file_frame[64];
    int n = Encoder_Interface_Encode(s->enc, MR122, pcm, file_frame, 0);
    if (n <= 0) return -1;

    /* opencore-amrnb writes File-format byte 0 = F|FT(bits 6..3)|Q|RR. */
    uint8_t mode = (uint8_t)((file_frame[0] >> 3) & 0x0F);
    if (mode > 8) return -1;
    int speech_bits = amrnb_mode_bits[mode];
    return amrnb_be_pack(file_frame, n, mode, speech_bits, out, out_cap);
}

static int amrnb_dec(vham_audio_codec_t *c,
                     const uint8_t *in, size_t in_len,
                     int16_t *pcm, size_t pcm_cap) {
    amrnb_state_t *s = (amrnb_state_t *)c->state;
    if (!s || !s->dec || pcm_cap < 160 || in_len < 1) return -1;
    Decoder_Interface_Decode(s->dec, in, pcm, 0);
    return 160;
}

/* SdpFillPtParam @ 0x259918 codec table: 'a' → PT 0x61=97 for AMR-NB. */
static vham_audio_codec_t amrnb = {
    .payload_type = 97, .name = "AMR", .clock_rate = 8000,
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

/* AMR-WB mode → speech bits (per 3GPP TS 26.201 §A.2 / RFC 4867 §3.3). */
static const int amrwb_mode_bits[9] = {
    132, 177, 253, 285, 317, 365, 397, 461, 477
};

/* Same bit-packing layout as AMR-NB BE — the binary's
 * AMR_Convert_File_RTP_OneFrame handles both NB and WB with the same
 * routine. CMR/FT widths and Q-bit position are identical between the
 * two. The only difference is the per-mode speech-bit count. */
static int amrwb_be_pack(const uint8_t *file_frame, int file_frame_len,
                         uint8_t mode, int speech_bits,
                         uint8_t *out, size_t out_cap) {
    int speech_bytes = (speech_bits + 7) / 8;
    if (1 + speech_bytes > file_frame_len) return -1;
    int total_bits  = 4 + 1 + 4 + 1 + speech_bits;
    int total_bytes = (total_bits + 7) / 8;
    if (out_cap < (size_t)total_bytes) return -1;
    memset(out, 0, (size_t)total_bytes);
    out[0] = (uint8_t)((mode << 4) | (mode >> 1));
    out[1] = (uint8_t)(((mode & 0x01) << 7) | (1 << 6)
                       | (file_frame[1] >> 2));
    for (int i = 1; i < speech_bytes; ++i) {
        uint8_t next = (i + 1 < speech_bytes) ? file_frame[i + 1] : 0;
        out[1 + i] = (uint8_t)((file_frame[i] << 6) | (next >> 2));
    }
    return total_bytes;
}

static int amrwb_enc(vham_audio_codec_t *c,
                     const int16_t *pcm, size_t n_samples,
                     uint8_t *out, size_t out_cap) {
    amrwb_state_t *s = (amrwb_state_t *)c->state;
    if (!s || !s->enc || n_samples != 320 || out_cap < 64) return -1;

    uint8_t file_frame[64];
    int n = E_IF_encode(s->enc, 8, pcm, file_frame, 0);
    if (n <= 0) return -1;

    /* vo-amrwbenc writes File-format byte 0 = F|FT(bits 6..3)|Q|RR. */
    uint8_t mode = (uint8_t)((file_frame[0] >> 3) & 0x0F);
    if (mode > 8) return -1;
    int speech_bits = amrwb_mode_bits[mode];
    return amrwb_be_pack(file_frame, n, mode, speech_bits, out, out_cap);
}

static int amrwb_dec(vham_audio_codec_t *c,
                     const uint8_t *in, size_t in_len,
                     int16_t *pcm, size_t pcm_cap) {
    amrwb_state_t *s = (amrwb_state_t *)c->state;
    if (!s || !s->dec || pcm_cap < 320 || in_len < 1) return -1;
    D_IF_decode(s->dec, in, pcm, 0);
    return 320;
}

/* SdpFillPtParam @ 0x259918 codec table: 'k' → PT 0x6b=107 for AMR-WB. */
static vham_audio_codec_t amrwb = {
    .payload_type = 107, .name = "AMR-WB", .clock_rate = 16000,
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
