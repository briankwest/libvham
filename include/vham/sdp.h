/* libvham/include/vham/sdp.h — SDP body encoder + decoder.
 *
 * Mirrors SrvPackSdpFunc @ 0x26589c and SrvUnpkSdpFunc @ 0x26b088.
 *
 * The result of vham_build_sdp_body() is the payload bytes of
 * IE 0x19 in CC_SETUP (and IE 0x1a, 0x57 elsewhere); the caller
 * wraps it via vham_pack_tlv_fix() inside the outer SRVMSG frame.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_SDP_H
#define VHAM_SDP_H

#include "vham/codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Limits taken verbatim from the binary's struct layout.
 *
 *   _SDP_s             — total 0x4064 bytes
 *   per-media stride   — 0xbd4 = 3028 bytes
 *   per-codec stride   — 0xbc  = 188 bytes
 *   max media          — 4   (PPackU8(media_count) checked < 5)
 *   max codecs per m   — 16  (PPackU8(codec_count) checked <= 0x10)
 */
#define VHAM_SDP_MAX_MEDIA       4
#define VHAM_SDP_MAX_CODECS     16

/* Sizes from PUnpkStr max-len arguments inside SrvUnpkSdpFunc */
#define VHAM_SDP_CODEC_NAME_MAX 23   /* 0x17 */
#define VHAM_SDP_CODEC_PARAM_A  7
#define VHAM_SDP_CODEC_PARAM_B  128  /* 0x80 */
#define VHAM_SDP_T1_UFRAG_MAX   64
#define VHAM_SDP_T1_PWD_MAX     32
#define VHAM_SDP_T1_SETUP_MAX   32
#define VHAM_SDP_T1_FP_MAX      128
#define VHAM_SDP_T1_TEXT_MAX    4096

/* media_type values */
enum vham_sdp_media_type {
    VHAM_SDP_MEDIA_AUDIO = 0,
    VHAM_SDP_MEDIA_VIDEO = 2,
};

/* transport: low nibble of the packed byte 8 (per-media) */
enum vham_sdp_transport {
    VHAM_SDP_TX_RTP_UDP  = 0,   /* RTP/AVP over UDP   — most common */
    VHAM_SDP_TX_RTP_TCP  = 1,   /* RTP/AVP over TCP   — RFC 4571 */
    VHAM_SDP_TX_TLS_UDP  = 2,   /* DTLS/SRTP          — WebRTC */
};

typedef struct {
    uint8_t  payload_type;       /* RTP PT: 0=PCMU, 8=PCMA, 98=H264, 106=Opus */
    uint8_t  encoding_param;     /* channels for audio, alignment otherwise */
    uint32_t clock_rate;         /* 8000, 16000, 48000, 90000... */
    char     name[VHAM_SDP_CODEC_NAME_MAX]; /* "PCMU", "Opus", "H264" */
    uint8_t  num_params;         /* 0..7, ignored unless you need it */
    char     param_a[VHAM_SDP_CODEC_PARAM_A];
    char     param_b[VHAM_SDP_CODEC_PARAM_B]; /* fmtp string */

    /* video-only — written only when enclosing media_type == VIDEO */
    uint32_t video_width;
    uint32_t video_height;
    uint32_t video_bitrate;
    uint32_t video_fps;
    uint32_t video_gop;
} vham_sdp_codec_t;

typedef struct {
    /* media endpoint (PIpAddr 8-byte form, all LE) */
    uint32_t ipv4;               /* convention A */
    uint16_t port;
    uint8_t  family;             /* normally 0 */
    uint8_t  pad;

    /* nibble-packed byte 8 of the per-media wire header */
    uint8_t  transport;          /* low nibble */
    uint8_t  flags;              /* high nibble */

    uint8_t  media_type;         /* VHAM_SDP_MEDIA_* */
    uint8_t  reserved;
    uint32_t bandwidth_or_flags;

    vham_sdp_codec_t codecs[VHAM_SDP_MAX_CODECS];
    uint8_t  codec_count;
} vham_sdp_media_t;

typedef struct {
    /* origin endpoint (PIpAddr 8-byte form) */
    uint32_t origin_ipv4;
    uint16_t origin_port;
    uint8_t  origin_family;
    uint8_t  origin_pad;

    /* type 0 (normal SDP) — set is_type1=0 */
    vham_sdp_media_t media[VHAM_SDP_MAX_MEDIA];
    uint8_t  media_count;

    /* type 1 (WebRTC text variant) — set is_type1=1 */
    uint8_t  is_type1;
    uint8_t  type1_bytes[4];
    char     type1_ice_ufrag[VHAM_SDP_T1_UFRAG_MAX];
    char     type1_ice_pwd  [VHAM_SDP_T1_PWD_MAX];
    char     type1_setup    [VHAM_SDP_T1_SETUP_MAX];
    char     type1_fingerprint[VHAM_SDP_T1_FP_MAX];
    char     type1_sdp_text [VHAM_SDP_T1_TEXT_MAX];
} vham_sdp_t;

/* Encode the SDP body. Returns bytes written, -1 on error. */
int vham_build_sdp_body(const vham_sdp_t *s, void *out, size_t out_cap);

/* Decode the SDP body. Returns 0 on success, -1 on malformed. */
int vham_parse_sdp_body(const void *in, size_t in_len, vham_sdp_t *s);

#ifdef __cplusplus
}
#endif

#endif
