/* libvham/include/vham/voice.h — paced RTP sender/receiver.
 *
 * The sender takes 16-bit signed mono PCM at 8 kHz, encodes via
 * G.711, packetizes into 20 ms RTP packets, and emits at a real-time
 * cadence (CLOCK_MONOTONIC).
 *
 * The receiver consumes RTP packets, tracks sequence/timestamp,
 * decodes G.711 back to 16-bit PCM, and exposes RFC 4733 DTMF events
 * to the caller.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_VOICE_H
#define VHAM_VOICE_H

#include "vham/rtp.h"
#include "vham/dtmf.h"
#include "vham/codec_audio.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy 8 kHz fixed-rate constants. The voice TX/RX now picks
 * frame_samples/clock_rate from the codec dispatch table, so these
 * are only used for buffer sizing in the receive struct. */
#define VHAM_VOICE_SAMPLE_RATE   8000
#define VHAM_VOICE_PTIME_MS      20
#define VHAM_VOICE_SAMPLES       (VHAM_VOICE_SAMPLE_RATE * VHAM_VOICE_PTIME_MS / 1000)

/* Largest frame any registered codec can produce (Opus at 48 kHz / 20 ms). */
#define VHAM_VOICE_MAX_SAMPLES   960

/* ---------- Sender ---------- */
typedef struct {
    uint8_t  payload_type;   /* PCMU(0), PCMA(8), Opus(106), ... */
    uint8_t  dtmf_pt;        /* dynamic PT for telephone-event (if used) */
    uint32_t ssrc;           /* host order */
    uint16_t sequence;       /* next seq to send */
    uint32_t timestamp;      /* next ts to send */

    uint64_t t0_ns;          /* monotonic time of frame 0 (CLOCK_MONOTONIC ns) */
    uint64_t frame_index;    /* frames already sent */

    /* PTT gating. When the call is half-duplex we should only emit
     * RTP packets while we hold the mic token (`mic_held = 1`).
     * Set via vham_voice_tx_set_mic(). Default 1 (full-duplex). */
    int      mic_held;

    /* Resolved at init via the codec dispatch table. NULL means the
     * codec for `payload_type` isn't registered. */
    vham_audio_codec_t *codec;
} vham_voice_tx_t;

/* Set the mic-grant state. While `held` is 0, `vham_voice_tx_pcm_frame`
 * returns 0 (no bytes written) and `frame_index` does not advance. */
void vham_voice_tx_set_mic(vham_voice_tx_t *tx, int held);

void vham_voice_tx_init(vham_voice_tx_t *tx,
                        uint8_t payload_type, uint32_t ssrc);

/* Encode one PCM frame and emit one RTP packet. `n_samples` must
 * equal the codec's `frame_samples`. Returns bytes written, -1 on
 * error, 0 if the mic is closed. */
int vham_voice_tx_pcm_frame(vham_voice_tx_t *tx,
                            const int16_t *pcm, size_t n_samples,
                            uint8_t marker,
                            void *out, size_t out_cap);

/* Emit a DTMF event packet (RFC 4733). Caller manages "begin/middle/end"
 * by calling repeatedly with the same timestamp and incrementing
 * duration. Set `end=1` on the final packet. */
int vham_voice_tx_dtmf(vham_voice_tx_t *tx,
                       uint8_t event, uint8_t volume,
                       uint16_t duration, uint8_t end,
                       void *out, size_t out_cap);

/* Sleep until it's time to send frame N (where N = tx->frame_index).
 * Uses CLOCK_MONOTONIC pacing relative to t0_ns. Call this just
 * before emitting each frame. */
void vham_voice_tx_pace(vham_voice_tx_t *tx);

/* ---------- Receiver ---------- */
typedef struct {
    uint32_t ssrc;
    int      have_ssrc;
    uint16_t last_seq;
    int      have_last_seq;
    uint32_t last_ts;

    uint64_t pkt_count;
    uint64_t drop_count;     /* sequence gaps + reorders */
    uint64_t lost_count;     /* outright lost */
    uint64_t dtmf_count;

    /* The PT of the last decoded audio frame — used to look up the
     * codec for follow-up frames on the same SSRC. */
    uint8_t  last_audio_pt;
} vham_voice_rx_t;

void vham_voice_rx_init(vham_voice_rx_t *rx);

typedef enum {
    VHAM_VOICE_FRAME_NONE = 0,  /* not a media frame (or rejected) */
    VHAM_VOICE_FRAME_AUDIO,     /* `pcm` filled with up to 320 samples */
    VHAM_VOICE_FRAME_DTMF,      /* `dtmf` filled */
} vham_voice_frame_kind_t;

typedef struct {
    vham_voice_frame_kind_t kind;
    uint8_t          payload_type;
    uint16_t         sequence;
    uint32_t         timestamp;
    uint8_t          marker;

    /* For AUDIO: decoded PCM samples. */
    int16_t          pcm[VHAM_VOICE_MAX_SAMPLES];
    size_t           pcm_samples;

    /* For DTMF: parsed event. */
    vham_dtmf_event_t dtmf;
} vham_voice_frame_t;

/* Parse an RTP datagram and decode into `frame`. Returns 0 on success,
 * -1 on malformed. The frame's `kind` indicates audio/DTMF/none. */
int vham_voice_rx_feed(vham_voice_rx_t *rx,
                       const void *buf, size_t len,
                       vham_voice_frame_t *frame);

#ifdef __cplusplus
}
#endif

#endif
