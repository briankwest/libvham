/* libvham/src/sdp.c — SDP body encoder + decoder.
 *
 * Wire format documented in vham/sdp.h. Reverse-engineered from
 * SrvPackSdpFunc @ 0x26589c and SrvUnpkSdpFunc @ 0x26b088.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/sdp.h"
#include <string.h>

/* ---------- PIpAddr 8-byte form (all little-endian) ---------- */
static void pack_pipaddr(vham_buf_t *b,
                         uint32_t ipv4, uint16_t port,
                         uint8_t family, uint8_t pad) {
    /* IE-0x24-style: LE ipv4 + LE port + family + pad */
    vham_pack_u8(b, (uint8_t)(ipv4));
    vham_pack_u8(b, (uint8_t)(ipv4 >>  8));
    vham_pack_u8(b, (uint8_t)(ipv4 >> 16));
    vham_pack_u8(b, (uint8_t)(ipv4 >> 24));
    vham_pack_u8(b, (uint8_t)(port));
    vham_pack_u8(b, (uint8_t)(port >> 8));
    vham_pack_u8(b, family);
    vham_pack_u8(b, pad);
}

static int unpack_pipaddr(const uint8_t *p, size_t avail,
                          uint32_t *ipv4, uint16_t *port,
                          uint8_t *family, uint8_t *pad) {
    if (avail < 8) return -1;
    *ipv4   = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16)
           | ((uint32_t)p[1] <<  8) |  (uint32_t)p[0];
    *port   = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
    *family = p[6];
    *pad    = p[7];
    return 0;
}

/* ---------- ENCODER ---------- */

static int pack_codec(vham_buf_t *b, const vham_sdp_codec_t *c, int is_video) {
    if (vham_pack_u8 (b, c->payload_type))   return -1;
    if (vham_pack_u8 (b, c->encoding_param)) return -1;
    if (vham_pack_u32(b, c->clock_rate))     return -1;
    if (vham_pack_str(b, c->name))           return -1;
    if (c->num_params > 7) return -1;
    if (vham_pack_u8 (b, c->num_params))     return -1;
    if (vham_pack_str(b, c->param_a))        return -1;
    if (vham_pack_str(b, c->param_b))        return -1;
    if (is_video) {
        if (vham_pack_u32(b, c->video_width))   return -1;
        if (vham_pack_u32(b, c->video_height))  return -1;
        if (vham_pack_u32(b, c->video_bitrate)) return -1;
        if (vham_pack_u32(b, c->video_fps))     return -1;
        if (vham_pack_u32(b, c->video_gop))     return -1;
    }
    return 0;
}

static int pack_media(vham_buf_t *b, const vham_sdp_media_t *m) {
    /* 8-byte PIpAddr */
    pack_pipaddr(b, m->ipv4, m->port, m->family, m->pad);
    if (b->err) return -1;

    /* Packed nibble byte: low = transport, high = flags */
    uint8_t packed = (uint8_t)((m->transport & 0xF) | ((m->flags & 0xF) << 4));
    if (vham_pack_u8 (b, packed))                  return -1;
    if (vham_pack_u8 (b, m->media_type))           return -1;
    if (vham_pack_u8 (b, m->reserved))             return -1;
    if (vham_pack_u32(b, m->bandwidth_or_flags))   return -1;

    if (m->codec_count > VHAM_SDP_MAX_CODECS)      return -1;
    if (vham_pack_u8 (b, m->codec_count))          return -1;

    int is_video = (m->media_type == VHAM_SDP_MEDIA_VIDEO);
    for (uint8_t i = 0; i < m->codec_count; ++i) {
        if (pack_codec(b, &m->codecs[i], is_video) != 0) return -1;
    }
    return 0;
}

int vham_build_sdp_body(const vham_sdp_t *s, void *out, size_t out_cap) {
    if (!s || !out) return -1;

    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* 8-byte session origin */
    pack_pipaddr(&b, s->origin_ipv4, s->origin_port,
                 s->origin_family, s->origin_pad);
    if (b.err) return -1;

    if (s->is_type1) {
        /* Type-1 (WebRTC variant): media_count = 0, then 4 bytes
         * and 5 NUL-terminated strings. */
        if (vham_pack_u8(&b, 0))                            return -1;
        if (vham_pack_u8(&b, s->type1_bytes[0]))            return -1;
        if (vham_pack_u8(&b, s->type1_bytes[1]))            return -1;
        if (vham_pack_u8(&b, s->type1_bytes[2]))            return -1;
        if (vham_pack_u8(&b, s->type1_bytes[3]))            return -1;
        if (vham_pack_str(&b, s->type1_ice_ufrag))          return -1;
        if (vham_pack_str(&b, s->type1_ice_pwd))            return -1;
        if (vham_pack_str(&b, s->type1_setup))              return -1;
        if (vham_pack_str(&b, s->type1_fingerprint))        return -1;
        if (vham_pack_str(&b, s->type1_sdp_text))           return -1;
        return (int)b.off;
    }

    if (s->media_count > VHAM_SDP_MAX_MEDIA) return -1;
    if (vham_pack_u8(&b, s->media_count))    return -1;
    for (uint8_t i = 0; i < s->media_count; ++i) {
        if (pack_media(&b, &s->media[i]) != 0) return -1;
    }
    if (b.err) return -1;
    return (int)b.off;
}

/* ---------- DECODER ---------- */

/* tiny streaming reader */
typedef struct { const uint8_t *p; size_t off; size_t cap; } sdp_rd_t;

static int rd_u8(sdp_rd_t *r, uint8_t *o) {
    if (r->off >= r->cap) return -1;
    *o = r->p[r->off++];
    return 0;
}
static int rd_u32_be(sdp_rd_t *r, uint32_t *o) {
    if (r->cap - r->off < 4) return -1;
    *o = ((uint32_t)r->p[r->off    ] << 24)
       | ((uint32_t)r->p[r->off + 1] << 16)
       | ((uint32_t)r->p[r->off + 2] <<  8)
       |  (uint32_t)r->p[r->off + 3];
    r->off += 4;
    return 0;
}
static int rd_str(sdp_rd_t *r, char *dst, size_t dst_max) {
    if (dst_max == 0) return -1;
    size_t i = 0;
    while (r->off < r->cap) {
        uint8_t c = r->p[r->off++];
        if (c == 0) {
            if (i >= dst_max) return -1;
            dst[i] = 0;
            return 0;
        }
        if (i + 1 >= dst_max) return -1;   /* keep room for NUL */
        dst[i++] = (char)c;
    }
    return -1;
}

static int unpack_codec(sdp_rd_t *r, vham_sdp_codec_t *c, int is_video) {
    memset(c, 0, sizeof *c);
    if (rd_u8 (r, &c->payload_type))   return -1;
    if (rd_u8 (r, &c->encoding_param)) return -1;
    if (rd_u32_be(r, &c->clock_rate))  return -1;
    if (rd_str(r, c->name, sizeof c->name)) return -1;
    if (rd_u8 (r, &c->num_params))     return -1;
    if (c->num_params > 7) return -1;
    if (rd_str(r, c->param_a, sizeof c->param_a)) return -1;
    if (rd_str(r, c->param_b, sizeof c->param_b)) return -1;
    if (is_video) {
        if (rd_u32_be(r, &c->video_width))   return -1;
        if (rd_u32_be(r, &c->video_height))  return -1;
        if (rd_u32_be(r, &c->video_bitrate)) return -1;
        if (rd_u32_be(r, &c->video_fps))     return -1;
        if (rd_u32_be(r, &c->video_gop))     return -1;
    }
    return 0;
}

static int unpack_media(sdp_rd_t *r, vham_sdp_media_t *m) {
    memset(m, 0, sizeof *m);
    if (r->cap - r->off < 8) return -1;
    if (unpack_pipaddr(r->p + r->off, r->cap - r->off,
                       &m->ipv4, &m->port, &m->family, &m->pad) != 0) return -1;
    r->off += 8;

    uint8_t packed;
    if (rd_u8(r, &packed))               return -1;
    m->transport = (uint8_t)(packed & 0xF);
    m->flags     = (uint8_t)(packed >> 4);
    if (rd_u8(r, &m->media_type))        return -1;
    if (rd_u8(r, &m->reserved))          return -1;
    if (rd_u32_be(r, &m->bandwidth_or_flags)) return -1;
    if (rd_u8(r, &m->codec_count))       return -1;
    if (m->codec_count > VHAM_SDP_MAX_CODECS) return -1;

    int is_video = (m->media_type == VHAM_SDP_MEDIA_VIDEO);
    for (uint8_t i = 0; i < m->codec_count; ++i) {
        if (unpack_codec(r, &m->codecs[i], is_video) != 0) return -1;
    }
    return 0;
}

int vham_parse_sdp_body(const void *in, size_t in_len, vham_sdp_t *s) {
    if (!in || !s) return -1;
    memset(s, 0, sizeof *s);

    sdp_rd_t r = { (const uint8_t *)in, 0, in_len };

    /* 8-byte session origin */
    if (r.cap < 9) return -1;
    if (unpack_pipaddr(r.p, r.cap, &s->origin_ipv4, &s->origin_port,
                       &s->origin_family, &s->origin_pad) != 0) return -1;
    r.off = 8;

    uint8_t mc;
    if (rd_u8(&r, &mc)) return -1;

    if (mc == 0) {
        if (r.off == r.cap) {
            /* Empty SDP — valid but informational. */
            s->is_type1   = 0;
            s->media_count = 0;
            return 0;
        }
        /* Type-1 (WebRTC text): 4 bytes + 5 strings */
        s->is_type1 = 1;
        if (rd_u8(&r, &s->type1_bytes[0])) return -1;
        if (rd_u8(&r, &s->type1_bytes[1])) return -1;
        if (rd_u8(&r, &s->type1_bytes[2])) return -1;
        if (rd_u8(&r, &s->type1_bytes[3])) return -1;
        if (rd_str(&r, s->type1_ice_ufrag,  sizeof s->type1_ice_ufrag))  return -1;
        if (rd_str(&r, s->type1_ice_pwd,    sizeof s->type1_ice_pwd))    return -1;
        if (rd_str(&r, s->type1_setup,      sizeof s->type1_setup))      return -1;
        if (rd_str(&r, s->type1_fingerprint,sizeof s->type1_fingerprint))return -1;
        if (rd_str(&r, s->type1_sdp_text,   sizeof s->type1_sdp_text))   return -1;
        return 0;
    }
    if (mc > VHAM_SDP_MAX_MEDIA) return -1;
    s->media_count = mc;
    for (uint8_t i = 0; i < mc; ++i) {
        if (unpack_media(&r, &s->media[i]) != 0) return -1;
    }
    return 0;
}
