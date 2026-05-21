/* libvham/include/vham/im.h — Instant Messaging on top of PASSTHROUGH.
 *
 * The binary's `IDT_SendIM` / `IDT_IMSend` / `IDT_IMRecv` family carries
 * IM messages inside an `MM_PASSTHROUGH` event. The event's data field
 * is a small JSON object matching the schema:
 *
 *   {"Code":<int>,"Type":<int>,"UtSn":<int>,"Sn":"<id>","Time":"<ts>",
 *    "From":"<num>","To":"<num>","OriTo":"<num>","Txt":"<text>",
 *    "FileName":"<>","SourceFileName":"<>"}
 *
 * IM is fire-and-forget; the server delivers to the recipient (or
 * stores for later) and signals acks via another PASSTHROUGH event.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_IM_H
#define VHAM_IM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int         code;             /* 1 = text, 2 = file, 3 = location ... */
    int         type;
    uint32_t    ut_sn;
    const char *sn;               /* unique message id */
    const char *time;             /* ISO-8601 timestamp string */
    const char *from;             /* sender dispatch number */
    const char *to;               /* destination */
    const char *ori_to;           /* original "to" (for forwarded messages) */
    const char *text;             /* text body */
    const char *file_name;
    const char *source_file_name;
} vham_im_t;

/* Build an IM PASSTHROUGH frame. Returns bytes written, -1 on error. */
int vham_build_im(uint32_t seq_no, const vham_im_t *im,
                  void *out, size_t out_cap);

/* Parse a received PASSTHROUGH event back into a `vham_im_t`. String
 * fields are NUL-terminated and point into a caller-owned buffer
 * `scratch`. */
int vham_parse_im(const void *buf, size_t len,
                  vham_im_t *out,
                  char *scratch, size_t scratch_cap);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_IM_H */
