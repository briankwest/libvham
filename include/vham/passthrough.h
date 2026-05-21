/* libvham/include/vham/passthrough.h — MM_PASSTHROUGH (wMsgId 0x1b).
 *
 * A generic JSON/binary tunnel between the client and the server.
 * In the official stack it carries:
 *   - IM (text + file attachments)
 *   - "YaoYun" feature negotiation
 *   - Various IDT_SendPassThrough events
 *
 * Encoder mirrors `MM::SendPassThroughReq @ 0x2fff6c`. The server's
 * push-side (`MM::RecvPassThrough`) decodes the same IE set.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_PASSTHROUGH_H
#define VHAM_PASSTHROUGH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IE 0x49 inner event payload. Mirrors the in-memory layout of
 * `IDT_PASSTROUGH_EVENT_s` (yes, "PASSTROUGH" is the binary's spelling).
 * Total wire footprint = 1 + 4 + 4 + len(sn)+1 + len(time)+1 + 2 + data_len. */
typedef struct {
    uint8_t        code;            /* event sub-type */
    uint32_t       type;            /* type field */
    uint32_t       ut_sn;           /* user-terminal sequence */
    const char    *sn;              /* event Sn string (NULL → "") */
    const char    *time;            /* event Time string (NULL → "") */
    const uint8_t *data;            /* opaque payload bytes */
    uint16_t       data_len;
} vham_passthrough_event_t;

/* Build an MM_PASSTHROUGH datagram.
 *   seq_no    — TAP sequence
 *   src_num   — origin dispatch number (NULL → IE 0x0e omitted)
 *   dst_num   — destination dispatch number (required)
 *   ev        — the IE 0x49 event payload (required)
 *   display   — optional IE 0x76 display string (NULL → omitted)
 *
 * Returns bytes written, or -1 on error. */
int vham_build_passthrough(uint32_t seq_no,
                           const char *src_num,
                           const char *dst_num,
                           const vham_passthrough_event_t *ev,
                           const char *display,
                           void *out, size_t out_cap);

/* Parsed view of a server-pushed MM_PASSTHROUGH. Pointers reference
 * the input buffer — they are valid only as long as that buffer is. */
typedef struct {
    int      have_dst;
    char     dst_num[64];
    int      have_src;
    char     src_num[64];

    int      have_event;
    uint8_t  code;
    uint32_t type;
    uint32_t ut_sn;
    char     sn[96];
    char     time[24];
    const uint8_t *data;          /* points into the parsed buffer */
    uint16_t data_len;

    int      have_display;
    char     display[128];
} vham_passthrough_t;

int vham_parse_passthrough(const void *buf, size_t len,
                           vham_passthrough_t *out);

/* ---------- YaoYun feature negotiation ----------
 *
 * The server pushes a PASSTHROUGH event whose data field contains a
 * JSON blob `{"YaoYun":"<int>"}`. The client is expected to update
 * its local feature flag and, in some cases, echo back an Event JSON
 * `{"Event":"<name>","YaoYun":"<int>"}` via another PASSTHROUGH.
 *
 * Helpers:
 *
 *   vham_passthrough_yaoyun_value()  — extract the YaoYun int from a
 *                                       parsed PASSTHROUGH event, or
 *                                       -1 if absent.
 *
 *   vham_build_yaoyun_ack()           — build an Event/YaoYun response
 *                                       PASSTHROUGH frame to send back
 *                                       to the server.
 */
int vham_passthrough_yaoyun_value(const vham_passthrough_t *pt);

int vham_build_yaoyun_ack(uint32_t seq_no,
                          const char *src_num,
                          const char *dst_num,
                          const char *event_name,
                          int         yaoyun_value,
                          void *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_PASSTHROUGH_H */
