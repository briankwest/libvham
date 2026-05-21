/* libvham/src/gps.c — MM_GPSREPORT encoder.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/codec.h"
#include "vham/gps.h"

/* IE 0x4e is the binary's `_TLV_GPSRECPACK_s`. We pack:
 *   u32 lat (encoded as fixed-point millionths)
 *   u32 lon
 *   u32 speed_cmh (speed * 100)
 *   u32 heading_deg
 *   u32 altitude_m
 *   u32 accuracy_m
 *   u32 satellites
 *   u32 fix_quality
 *   u32 timestamp
 *   u32 batt_pct
 */
#define IE_GPS_REC 0x004e

static void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

int vham_build_gps_report(uint32_t seq_no,
                          const char *user_num,
                          const vham_gps_report_t *gps,
                          void *out, size_t out_cap) {
    if (!out || !user_num || !gps) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_MM)) return -1;
    if (vham_pack_u16(&b, VHAM_MM_GPSREPORT)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_MM_GPSREPORT,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* IE 0x27 — user number */
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, user_num)) return -1;

    /* IE 0x4e — GPS record (40 bytes) */
    uint8_t rec[40];
    put_u32_be(rec     , (uint32_t)(gps->latitude  * 1000000.0f));
    put_u32_be(rec +  4, (uint32_t)(gps->longitude * 1000000.0f));
    put_u32_be(rec +  8, (uint32_t)(gps->speed_kph * 100.0f));
    put_u32_be(rec + 12, (uint32_t)gps->heading_deg);
    put_u32_be(rec + 16, gps->altitude_m);
    put_u32_be(rec + 20, gps->accuracy_m);
    put_u32_be(rec + 24, gps->satellites);
    put_u32_be(rec + 28, gps->fix_quality);
    put_u32_be(rec + 32, gps->timestamp);
    put_u32_be(rec + 36, gps->batt_pct);
    if (vham_pack_tlv_fix(&b, 1, IE_GPS_REC, rec, sizeof rec)) return -1;

    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}
