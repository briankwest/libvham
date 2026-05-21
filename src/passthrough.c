/* libvham/src/passthrough.c — MM_PASSTHROUGH encoder + parser.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "vham/codec.h"
#include "vham/passthrough.h"

/* MM/CC module ids and wMsgId for PASSTHROUGH. */
#define IE_PASSTHROUGH_EVENT 0x0049
#define IE_DISPLAY           0x0076

/* Pack the IE 0x49 event payload (compound). */
static int pack_event(vham_buf_t *b, const vham_passthrough_event_t *ev) {
    if (vham_pack_u16(b, IE_PASSTHROUGH_EVENT)) return -1;
    size_t len_off = b->off;
    if (vham_pack_u16(b, 0)) return -1;        /* placeholder */
    size_t body = b->off;

    if (vham_pack_u8 (b, ev->code))         return -1;
    if (vham_pack_u32(b, ev->type))         return -1;
    if (vham_pack_u32(b, ev->ut_sn))        return -1;
    if (vham_pack_str(b, ev->sn   ? ev->sn   : "")) return -1;
    if (vham_pack_str(b, ev->time ? ev->time : "")) return -1;
    if (vham_pack_u16(b, ev->data_len))     return -1;
    if (ev->data_len) {
        if (vham_pack_fix(b, ev->data, ev->data_len)) return -1;
    }
    if (b->err) return -1;

    uint16_t L = (uint16_t)(b->off - body);
    b->buf[len_off    ] = (uint8_t)(L >> 8);
    b->buf[len_off + 1] = (uint8_t)(L);
    return 0;
}

int vham_build_passthrough(uint32_t seq_no,
                           const char *src_num,
                           const char *dst_num,
                           const vham_passthrough_event_t *ev,
                           const char *display,
                           void *out, size_t out_cap) {
    if (!out || !ev || !dst_num) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header (class=1 MM, cmd=0x1b). */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_MM)) return -1;
    if (vham_pack_u16(&b, VHAM_MM_PASSTHROUGH)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    /* SRVMSG header. Sender uses ucDst=5 (CC), ucSrc=4 (MM). */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_CC, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_MM_PASSTHROUGH,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* IE 0x0d (destination num) — required. */
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_CC_CALLED_NUM, dst_num)) return -1;
    /* IE 0x0e (source num) — optional. */
    if (src_num && *src_num) {
        if (vham_pack_tlv_str(&b, 1, VHAM_IE_CC_CALLING_NUM, src_num))
            return -1;
    }
    /* IE 0x49 (event payload) — required. */
    if (pack_event(&b, ev)) return -1;
    /* IE 0x76 (display) — optional. */
    if (display && *display) {
        if (vham_pack_tlv_str(&b, 1, IE_DISPLAY, display)) return -1;
    }

    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}

/* Helpers for the parser. */
static int read_str_into(const uint8_t *b, size_t len, size_t *off,
                         char *dst, size_t dst_cap) {
    size_t start = *off;
    while (*off < len && b[*off] != 0) (*off)++;
    if (*off >= len) return -1;
    size_t n = *off - start;
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, b + start, n);
    dst[n] = 0;
    (*off)++;
    return 0;
}

static int parse_event(const uint8_t *body, size_t len,
                       vham_passthrough_t *out) {
    size_t i = 0;
    if (i + 1 > len) return -1;
    out->code = body[i++];
    if (i + 8 > len) return -1;
    out->type  = ((uint32_t)body[i] << 24) | ((uint32_t)body[i+1] << 16) |
                 ((uint32_t)body[i+2] <<  8) |  (uint32_t)body[i+3];      i += 4;
    out->ut_sn = ((uint32_t)body[i] << 24) | ((uint32_t)body[i+1] << 16) |
                 ((uint32_t)body[i+2] <<  8) |  (uint32_t)body[i+3];      i += 4;
    if (read_str_into(body, len, &i, out->sn,   sizeof out->sn)   != 0) return -1;
    if (read_str_into(body, len, &i, out->time, sizeof out->time) != 0) return -1;
    if (i + 2 > len) return -1;
    out->data_len = (uint16_t)((body[i] << 8) | body[i+1]); i += 2;
    if (i + out->data_len > len) return -1;
    out->data = body + i;
    out->have_event = 1;
    return 0;
}

/* Find `"YaoYun":"<int>"` inside the parsed event's data blob. */
int vham_passthrough_yaoyun_value(const vham_passthrough_t *pt) {
    if (!pt || !pt->have_event || pt->data_len == 0 || !pt->data) return -1;
    const char *needle = "\"YaoYun\":\"";
    size_t n_len = 10;
    /* Scan the data buffer for the needle (it's binary-safe). */
    for (size_t i = 0; i + n_len < pt->data_len; ++i) {
        if (memcmp(pt->data + i, needle, n_len) == 0) {
            size_t j = i + n_len;
            int v = 0; int got = 0;
            while (j < pt->data_len &&
                   pt->data[j] >= '0' && pt->data[j] <= '9') {
                v = v*10 + (pt->data[j] - '0');
                j++; got = 1;
            }
            return got ? v : -1;
        }
    }
    return -1;
}

int vham_build_yaoyun_ack(uint32_t seq_no,
                          const char *src_num, const char *dst_num,
                          const char *event_name, int yaoyun_value,
                          void *out, size_t out_cap) {
    if (!out || !dst_num) return -1;
    char json[256];
    int n = snprintf(json, sizeof json,
                     "{\"Event\":\"%s\", \"YaoYun\":\"%d\"}",
                     event_name ? event_name : "Ack", yaoyun_value);
    if (n < 0 || (size_t)n >= sizeof json) return -1;

    vham_passthrough_event_t ev = {
        .code = 0xff,                /* YaoYun event code (observed) */
        .type = 0, .ut_sn = seq_no,
        .sn   = "yaoyun", .time = "",
        .data = (const uint8_t *)json,
        .data_len = (uint16_t)n,
    };
    return vham_build_passthrough(seq_no, src_num, dst_num, &ev,
                                  NULL, out, out_cap);
}

int vham_parse_passthrough(const void *buf, size_t len,
                           vham_passthrough_t *out) {
    if (!buf || !out) return -1;
    memset(out, 0, sizeof *out);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) return -1;
    if (sh.wMsgId != VHAM_MM_PASSTHROUGH) return -1;

    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_CC_CALLED_NUM: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                strncpy(out->dst_num, s, sizeof out->dst_num - 1);
                out->have_dst = 1;
            }
            break;
        }
        case VHAM_IE_CC_CALLING_NUM: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                strncpy(out->src_num, s, sizeof out->src_num - 1);
                out->have_src = 1;
            }
            break;
        }
        case IE_PASSTHROUGH_EVENT:
            if (parse_event(ie.value, ie.len, out) != 0) return -1;
            break;
        case IE_DISPLAY: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                strncpy(out->display, s, sizeof out->display - 1);
                out->have_display = 1;
            }
            break;
        }
        default: break;
        }
    }
    return rc == 0 ? 0 : -1;
}
