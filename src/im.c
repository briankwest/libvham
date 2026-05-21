/* libvham/src/im.c — IM build/parse on top of MM_PASSTHROUGH.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "vham/im.h"
#include "vham/passthrough.h"

#define IM_EVENT_CODE_TEXT 1

/* Tiny JSON helpers. We don't need a full parser — the IM JSON is
 * a single flat object with fixed keys and string/int values. */

static int json_emit(char *out, size_t cap, const vham_im_t *im) {
    int n = snprintf(out, cap,
        "{\"Code\":%d,\"Type\":%d,\"UtSn\":%u,"
        "\"Sn\":\"%s\",\"Time\":\"%s\","
        "\"From\":\"%s\",\"To\":\"%s\",\"OriTo\":\"%s\","
        "\"Txt\":\"%s\","
        "\"FileName\":\"%s\",\"SourceFileName\":\"%s\"}",
        im->code, im->type, im->ut_sn,
        im->sn   ? im->sn   : "",
        im->time ? im->time : "",
        im->from ? im->from : "",
        im->to   ? im->to   : "",
        im->ori_to ? im->ori_to : "",
        im->text ? im->text : "",
        im->file_name ? im->file_name : "",
        im->source_file_name ? im->source_file_name : "");
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

int vham_build_im(uint32_t seq_no, const vham_im_t *im,
                  void *out, size_t out_cap) {
    if (!im || !out || !im->to) return -1;
    char json[2048];
    int jn = json_emit(json, sizeof json, im);
    if (jn < 0) return -1;

    vham_passthrough_event_t ev = {
        .code  = (uint8_t)(im->code ? im->code : IM_EVENT_CODE_TEXT),
        .type  = (uint32_t)im->type,
        .ut_sn = im->ut_sn,
        .sn    = im->sn   ? im->sn   : "",
        .time  = im->time ? im->time : "",
        .data  = (const uint8_t *)json,
        .data_len = (uint16_t)jn,
    };
    return vham_build_passthrough(seq_no, im->from, im->to, &ev,
                                  NULL, out, out_cap);
}

/* Find a JSON string value for key `key`. Copies result into `dst`.
 * Returns 1 if found and copied, 0 otherwise. */
static int json_extract_str(const char *json, const char *key,
                            char *dst, size_t dst_cap) {
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < dst_cap) dst[n++] = *p++;
    dst[n] = 0;
    return 1;
}

static int json_extract_int(const char *json, const char *key, int *dst) {
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    int sign = 1;
    if (*p == '-') { sign = -1; p++; }
    int v = 0; int got = 0;
    while (*p >= '0' && *p <= '9') { v = v*10 + (*p++ - '0'); got = 1; }
    if (!got) return 0;
    *dst = sign * v;
    return 1;
}

int vham_parse_im(const void *buf, size_t len, vham_im_t *out,
                  char *scratch, size_t scratch_cap) {
    if (!out || !scratch || scratch_cap < 256) return -1;
    vham_passthrough_t pt;
    if (vham_parse_passthrough(buf, len, &pt) != 0) return -1;
    if (!pt.have_event || pt.data_len == 0) return -1;
    /* Copy event JSON into scratch as a NUL-terminated string. */
    size_t n = pt.data_len < scratch_cap - 1 ? pt.data_len : scratch_cap - 1;
    memcpy(scratch, pt.data, n);
    scratch[n] = 0;

    memset(out, 0, sizeof *out);
    out->code  = pt.code;
    out->type  = (int)pt.type;
    out->ut_sn = pt.ut_sn;

    /* Carve up the scratch into typed sub-buffers for the strings. */
    char *cursor = scratch + n + 1;
    if (cursor + 64 + 64 + 64 + 64 + 64 + 512 + 128 > scratch + scratch_cap)
        return -1;
    char *sn_buf  = cursor; cursor += 64;
    char *tm_buf  = cursor; cursor += 64;
    char *frm_buf = cursor; cursor += 64;
    char *to_buf  = cursor; cursor += 64;
    char *ori_buf = cursor; cursor += 64;
    char *txt_buf = cursor; cursor += 512;
    char *fn_buf  = cursor; cursor += 128;

    json_extract_str(scratch, "Sn",     sn_buf,  64);
    json_extract_str(scratch, "Time",   tm_buf,  64);
    json_extract_str(scratch, "From",   frm_buf, 64);
    json_extract_str(scratch, "To",     to_buf,  64);
    json_extract_str(scratch, "OriTo",  ori_buf, 64);
    json_extract_str(scratch, "Txt",    txt_buf, 512);
    json_extract_str(scratch, "FileName", fn_buf, 128);
    int code = 0;
    if (json_extract_int(scratch, "Code", &code)) out->code = code;
    out->sn = sn_buf;  out->time = tm_buf;
    out->from = frm_buf; out->to = to_buf; out->ori_to = ori_buf;
    out->text = txt_buf;
    out->file_name = fn_buf;
    return 0;
}
