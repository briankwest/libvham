/* libvham/include/vham/gps.h — GPS report / subscribe.
 *
 * Mirrors `MM::GpsReport @ 0x2fe468`. The official client periodically
 * sends an MM_GPSREPORT (wMsgId 0x92) so the server can track each
 * user's position; dispatcher consoles aggregate these for map display.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_GPS_H
#define VHAM_GPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float    latitude;     /* decimal degrees, WGS-84 */
    float    longitude;
    float    speed_kph;
    float    heading_deg;
    uint32_t altitude_m;
    uint32_t accuracy_m;
    uint32_t satellites;
    uint32_t fix_quality;  /* 0=none, 1=GPS, 2=DGPS */
    uint32_t timestamp;    /* unix seconds */
    uint32_t batt_pct;
} vham_gps_report_t;

/* Build an MM_GPSREPORT frame for `user_num` carrying `gps`. */
int vham_build_gps_report(uint32_t seq_no,
                          const char *user_num,
                          const vham_gps_report_t *gps,
                          void *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_GPS_H */
