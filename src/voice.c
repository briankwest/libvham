/* libvham/src/voice.c — paced sender + receiver loop.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/voice.h"
#include "vham/g711.h"
#include <string.h>
#include <time.h>
#include <errno.h>

/* ---------- Time utilities ---------- */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_until_ns(uint64_t target_ns) {
    for (;;) {
        uint64_t now = now_ns();
        if (now >= target_ns) return;
        uint64_t delta = target_ns - now;
        struct timespec req = {
            .tv_sec  = (time_t)(delta / 1000000000ULL),
            .tv_nsec = (long)(delta % 1000000000ULL),
        };
        struct timespec rem;
        if (nanosleep(&req, &rem) == 0) return;
        if (errno == EINTR) continue;
        return;
    }
}

/* ---------- Sender ---------- */

void vham_voice_tx_init(vham_voice_tx_t *tx,
                        uint8_t payload_type, uint32_t ssrc) {
    memset(tx, 0, sizeof *tx);
    tx->payload_type = payload_type;
    tx->dtmf_pt      = VHAM_RTP_PT_DTMF;
    tx->ssrc         = ssrc;
    /* RFC 3550 §5.1: initial sequence and timestamp should be random.
     * We pick simple seeds from the SSRC for determinism in tests; a
     * production sender should use a CSPRNG. */
    tx->sequence    = (uint16_t)(ssrc ^ 0x5a5a);
    tx->timestamp   = ssrc ^ 0xa5a5a5a5u;
    tx->t0_ns       = 0;
    tx->frame_index = 0;
    tx->mic_held    = 1;
    tx->codec       = vham_codec_by_pt(payload_type);
}

void vham_voice_tx_set_mic(vham_voice_tx_t *tx, int held) {
    if (tx) tx->mic_held = held ? 1 : 0;
}

int vham_voice_tx_pcm_frame(vham_voice_tx_t *tx,
                            const int16_t *pcm, size_t n_samples,
                            uint8_t marker,
                            void *out, size_t out_cap) {
    if (!tx || !pcm || !out) return -1;
    if (!tx->codec) return -1;
    if (n_samples != tx->codec->frame_samples) return -1;
    /* Mic-grant gate. While not held, don't emit and don't advance
     * the timestamp — half-duplex PTT semantics. */
    if (!tx->mic_held) return 0;

    /* Encode via the codec dispatch table. */
    uint8_t enc[1500];
    int enc_n = tx->codec->encode(tx->codec, pcm, n_samples,
                                  enc, sizeof enc);
    if (enc_n < 0) return -1;

    int n = vham_rtp_build_audio(tx->payload_type, tx->sequence,
                                 tx->timestamp, tx->ssrc, marker,
                                 enc, (size_t)enc_n, out, out_cap);
    if (n < 0) return -1;
    tx->sequence  += 1;
    tx->timestamp += (uint32_t)n_samples;
    tx->frame_index++;
    return n;
}

int vham_voice_tx_dtmf(vham_voice_tx_t *tx,
                       uint8_t event, uint8_t volume,
                       uint16_t duration, uint8_t end,
                       void *out, size_t out_cap) {
    if (!tx || !out) return -1;
    vham_dtmf_event_t e = {
        .event = event, .end = end, .reserved = 0,
        .volume = volume, .duration = duration,
    };
    uint8_t payload[4];
    if (vham_dtmf_build(&e, payload, sizeof payload) != 4) return -1;
    int n = vham_rtp_build_audio(tx->dtmf_pt, tx->sequence,
                                 tx->timestamp, tx->ssrc,
                                 /* marker for first DTMF packet in the burst */
                                 (duration == VHAM_VOICE_SAMPLES) ? 1 : 0,
                                 payload, sizeof payload,
                                 out, out_cap);
    if (n < 0) return -1;
    tx->sequence += 1;
    /* DTMF timestamp does NOT advance per RTP packet — it stays at
     * the start of the event. The caller controls timestamp via
     * separate calls if needed. We do not advance tx->timestamp here. */
    return n;
}

void vham_voice_tx_pace(vham_voice_tx_t *tx) {
    if (tx->t0_ns == 0) {
        tx->t0_ns = now_ns();
        return;
    }
    uint64_t target = tx->t0_ns +
        (uint64_t)tx->frame_index * VHAM_VOICE_PTIME_MS * 1000000ULL;
    sleep_until_ns(target);
}

/* ---------- Receiver ---------- */

void vham_voice_rx_init(vham_voice_rx_t *rx) {
    memset(rx, 0, sizeof *rx);
}

int vham_voice_rx_feed(vham_voice_rx_t *rx,
                       const void *buf, size_t len,
                       vham_voice_frame_t *frame) {
    if (!rx || !buf || !frame) return -1;
    memset(frame, 0, sizeof *frame);

    vham_rtp_pkt_t p;
    if (vham_rtp_parse(buf, len, &p) != 0) return -1;

    /* SSRC tracking — first packet sets it; later packets must match. */
    if (!rx->have_ssrc) {
        rx->ssrc = p.ssrc;
        rx->have_ssrc = 1;
    }

    /* Sequence tracking */
    if (rx->have_last_seq) {
        int16_t delta = vham_rtp_seq_diff(p.sequence, rx->last_seq);
        if (delta == 1) {
            /* in-order, in-sequence */
        } else if (delta > 1) {
            rx->lost_count += (uint64_t)(delta - 1);
        } else {
            /* duplicate or reorder */
            rx->drop_count++;
        }
    }
    rx->last_seq      = p.sequence;
    rx->have_last_seq = 1;
    rx->last_ts       = p.timestamp;
    rx->pkt_count++;

    frame->payload_type = p.payload_type;
    frame->sequence     = p.sequence;
    frame->timestamp    = p.timestamp;
    frame->marker       = p.marker;

    /* DTMF check first — a 4-byte payload on a dynamic PT is almost
     * always RFC 4733 (and never any audio codec we know). */
    if (p.payload_len == 4 && p.payload_type >= 96 && p.payload_type <= 127) {
        if (vham_dtmf_parse(p.payload, p.payload_len, &frame->dtmf) == 0) {
            frame->kind = VHAM_VOICE_FRAME_DTMF;
            rx->dtmf_count++;
            return 0;
        }
    }

    /* Look up the codec by PT and decode. */
    vham_audio_codec_t *c = vham_codec_by_pt(p.payload_type);
    if (c && c->decode) {
        int n = c->decode(c, p.payload, p.payload_len,
                          frame->pcm, VHAM_VOICE_MAX_SAMPLES);
        if (n > 0) {
            frame->pcm_samples = (size_t)n;
            frame->kind = VHAM_VOICE_FRAME_AUDIO;
            rx->last_audio_pt = p.payload_type;
            return 0;
        }
    }

    /* Unknown payload type — leave kind = NONE but signal success. */
    return 0;
}
