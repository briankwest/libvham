/* libvham/src/composites.c — composite IE parsers.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/composites.h"

/* Read a NUL-terminated string from `b[*off..len]` into a fixed-size
 * destination buffer of size `dst_cap`. Always NUL-terminates `dst`.
 * Returns 0 on success, -1 if the buffer overruns before NUL. */
static int read_str(const uint8_t *b, size_t len, size_t *off,
                    char *dst, size_t dst_cap) {
    size_t start = *off;
    while (*off < len && b[*off] != 0) (*off)++;
    if (*off >= len) return -1;
    size_t n = *off - start;
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, b + start, n);
    dst[n] = 0;
    (*off)++;                              /* consume the NUL */
    return 0;
}

static int read_u16(const uint8_t *b, size_t len, size_t *off,
                    uint16_t *out) {
    if (*off + 2 > len) return -1;
    *out = (uint16_t)((b[*off] << 8) | b[*off + 1]);
    *off += 2;
    return 0;
}

static int read_u32(const uint8_t *b, size_t len, size_t *off,
                    uint32_t *out) {
    if (*off + 4 > len) return -1;
    *out = ((uint32_t)b[*off    ] << 24) |
           ((uint32_t)b[*off + 1] << 16) |
           ((uint32_t)b[*off + 2] <<  8) |
           ((uint32_t)b[*off + 3]);
    *off += 4;
    return 0;
}

static int read_u8(const uint8_t *b, size_t len, size_t *off, uint8_t *out) {
    if (*off + 1 > len) return -1;
    *out = b[*off];
    *off += 1;
    return 0;
}

int vham_parse_user_ginfo(const void *buf, size_t len,
                          vham_user_ginfo_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);

    size_t i = 0;
    if (read_u16(b, len, &i, &out->count) != 0) return -1;
    if (out->count > VHAM_GMEM_ENTRIES_MAX) return -1;

    for (uint16_t k = 0; k < out->count; ++k) {
        vham_ginfo_member_t *m = &out->entries[k];
        if (read_u8 (b, len, &i, &m->prio)               != 0) return -1;
        if (read_u8 (b, len, &i, &m->type)               != 0) return -1;
        if (read_u8 (b, len, &i, &m->ut_type)            != 0) return -1;
        if (read_u8 (b, len, &i, &m->attr)               != 0) return -1;
        if (read_str(b, len, &i, m->num,    sizeof m->num)    != 0) return -1;
        if (read_str(b, len, &i, m->name,   sizeof m->name)   != 0) return -1;
        if (read_str(b, len, &i, m->ag_num, sizeof m->ag_num) != 0) return -1;
        if (read_u8 (b, len, &i, &m->chan_num)           != 0) return -1;
        if (read_u8 (b, len, &i, &m->status)             != 0) return -1;
        if (read_u8 (b, len, &i, &m->fg_count)           != 0) return -1;
        if (m->fg_count > 0x80) return -1;                       /* binary constraint */
        if (read_str(b, len, &i, m->fg_num, sizeof m->fg_num) != 0) return -1;
    }
    return 0;
}

int vham_encode_call_userctrl(const vham_call_userctrl_t *uc,
                              void *out, size_t out_cap) {
    if (!uc || !out) return -1;
    uint8_t *b = (uint8_t *)out;
    size_t la = strlen(uc->num_a);
    size_t lb = strlen(uc->num_b);
    if (la > 31 || lb > 31) return -1;
    size_t need = (la + 1) + (lb + 1) + 1 + 4;
    if (need > out_cap) return -1;
    size_t i = 0;
    memcpy(b + i, uc->num_a, la + 1); i += la + 1;
    memcpy(b + i, uc->num_b, lb + 1); i += lb + 1;
    b[i++] = uc->action;
    memcpy(b + i, uc->extra, 4); i += 4;
    return (int)i;
}

int vham_decode_call_userctrl(const void *in, size_t len,
                              vham_call_userctrl_t *out) {
    if (!in || !out) return -1;
    const uint8_t *b = (const uint8_t *)in;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_str(b, len, &i, out->num_a, sizeof out->num_a) != 0) return -1;
    if (read_str(b, len, &i, out->num_b, sizeof out->num_b) != 0) return -1;
    if (read_u8 (b, len, &i, &out->action)               != 0) return -1;
    if (i + 4 > len) return -1;
    memcpy(out->extra, b + i, 4); i += 4;
    return 0;
}

int vham_parse_ftpinfo(const void *buf, size_t len, vham_ftpinfo_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);

    size_t i = 0;
    if (read_u32(b, len, &i, &out->ipv4) != 0) return -1;
    if (read_u16(b, len, &i, &out->port) != 0) return -1;
    if (read_str(b, len, &i, out->username, sizeof out->username) != 0) return -1;
    if (read_str(b, len, &i, out->password, sizeof out->password) != 0) return -1;
    return 0;
}

int vham_parse_watchleg(const void *buf, size_t len, vham_watchleg_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    if (len < 5) return -1;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u32(b, len, &i, &out->leg_id) != 0) return -1;
    if (read_u8 (b, len, &i, &out->flag)   != 0) return -1;
    return 0;
}

int vham_parse_legext(const void *buf, size_t len, vham_legext_t *out) {
    if (!buf || !out) return -1;
    if (len < 22) return -1;        /* binary enforces > 0x15 */
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8(b, len, &i, &out->a) != 0) return -1;
    if (read_u8(b, len, &i, &out->b) != 0) return -1;
    if (i + 8 > len) return -1;
    memcpy(&out->ts_a, b + i, 8); i += 8;     /* opaque u64 */
    if (i + 8 > len) return -1;
    memcpy(&out->ts_b, b + i, 8); i += 8;
    if (read_u32(b, len, &i, &out->value) != 0) return -1;
    return 0;
}

int vham_parse_gpsrec(const void *buf, size_t len, vham_gpsrec_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_str(b, len, &i, out->subject, sizeof out->subject) != 0) return -1;
    if (read_u8(b, len, &i, &out->type)  != 0) return -1;
    if (read_u8(b, len, &i, &out->count) != 0) return -1;
    if (out->count > VHAM_GPSREC_MAX) return -1;
    for (uint8_t k = 0; k < out->count; ++k) {
        vham_gpsrec_entry_t *e = &out->entries[k];
        if (read_u32(b, len, &i, &e->lat_e6)   != 0) return -1;
        if (read_u32(b, len, &i, &e->lon_e6)   != 0) return -1;
        if (read_u32(b, len, &i, &e->speed)    != 0) return -1;
        if (read_u32(b, len, &i, &e->heading)  != 0) return -1;
        if (i + 2 > len) return -1;
        e->altitude = (uint16_t)((b[i] << 8) | b[i + 1]); i += 2;
        if (i + 5 > len) return -1;
        memcpy(e->flags, b + i, 5); i += 5;
    }
    return 0;
}

int vham_parse_caminfo(const void *buf, size_t len, vham_caminfo_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8 (b, len, &i, &out->type)              != 0) return -1;
    if (read_str(b, len, &i, out->name,  sizeof out->name)  != 0) return -1;
    if (read_str(b, len, &i, out->desc,  sizeof out->desc)  != 0) return -1;
    if (read_u16(b, len, &i, &out->port)              != 0) return -1;
    if (read_str(b, len, &i, out->url_a, sizeof out->url_a) != 0) return -1;
    if (read_str(b, len, &i, out->url_b, sizeof out->url_b) != 0) return -1;
    if (read_u8 (b, len, &i, &out->status_a)          != 0) return -1;
    if (read_u8 (b, len, &i, &out->status_b)          != 0) return -1;
    if (read_str(b, len, &i, out->extra, sizeof out->extra) != 0) return -1;
    return 0;
}

int vham_parse_info(const void *buf, size_t len, vham_info_t *out) {
    if (!buf || !out) return -1;
    if (len < 4) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u32(b, len, &i, &out->code) != 0) return -1;
    if (len > 4) {
        if (read_str(b, len, &i, out->text, sizeof out->text) != 0) return -1;
        out->have_text = 1;
    }
    return 0;
}

int vham_parse_playinfo(const void *buf, size_t len, vham_playinfo_t *out) {
    if (!buf || !out) return -1;
    if (len < 16) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u32(b, len, &i, &out->a) != 0) return -1;
    if (read_u32(b, len, &i, &out->b) != 0) return -1;
    if (read_u32(b, len, &i, &out->c) != 0) return -1;
    if (read_u32(b, len, &i, &out->d) != 0) return -1;
    return 0;
}

int vham_parse_resreport(const void *buf, size_t len, vham_resreport_t *out) {
    if (!buf || !out) return -1;
    if (len < 8) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u32(b, len, &i, &out->a) != 0) return -1;
    if (read_u32(b, len, &i, &out->b) != 0) return -1;
    return 0;
}

int vham_parse_gmember_extinfo(const void *buf, size_t len,
                               vham_gmember_extinfo_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u16(b, len, &i, &out->count) != 0) return -1;
    if (out->count > 0x400) return -1;
    /* Cap to our static array. */
    uint16_t cap = out->count;
    if (cap > VHAM_GMEMBER_EXT_MAX) cap = VHAM_GMEMBER_EXT_MAX;
    for (uint16_t k = 0; k < cap; ++k) {
        if (read_str(b, len, &i, out->entries[k].num,
                     sizeof out->entries[k].num) != 0) return -1;
        if (read_str(b, len, &i, out->entries[k].info,
                     sizeof out->entries[k].info) != 0) return -1;
    }
    /* Skip remaining entries if any (count > cap). */
    return 0;
}

int vham_parse_callext(const void *buf, size_t len, vham_callext_t *out) {
    if (!buf || !out) return -1;
    if (len < 4) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8 (b, len, &i, &out->a)             != 0) return -1;
    if (read_u8 (b, len, &i, &out->b)             != 0) return -1;
    if (read_str(b, len, &i, out->str_a, sizeof out->str_a) != 0) return -1;
    if (read_str(b, len, &i, out->str_b, sizeof out->str_b) != 0) return -1;
    return 0;
}

int vham_parse_call_streamctrl(const void *buf, size_t len,
                               vham_call_streamctrl_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_str(b, len, &i, out->stream_id, sizeof out->stream_id) != 0)
        return -1;
    if (read_u8 (b, len, &i, &out->flag_a) != 0) return -1;
    if (read_u8 (b, len, &i, &out->flag_b) != 0) return -1;
    return 0;
}

int vham_parse_commquery(const void *buf, size_t len,
                         vham_commquery_t *out) {
    if (!buf || !out) return -1;
    if (len < 9) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8 (b, len, &i, &out->type)   != 0) return -1;
    if (read_u32(b, len, &i, &out->param1) != 0) return -1;
    if (read_u32(b, len, &i, &out->param2) != 0) return -1;
    if (read_str(b, len, &i, out->key, sizeof out->key) != 0) return -1;
    if (read_str(b, len, &i, out->val, sizeof out->val) != 0) return -1;
    return 0;
}

int vham_parse_fsmpair(const void *buf, size_t len,
                       vham_fsmpair_list_t *out) {
    if (!buf || !out) return -1;
    if (len < 4) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u32(b, len, &i, &out->count) != 0) return -1;
    if (out->count > 0x100) return -1;
    uint32_t cap = out->count;
    if (cap > VHAM_FSMPAIR_MAX) cap = VHAM_FSMPAIR_MAX;
    for (uint32_t k = 0; k < cap; ++k) {
        if (read_u32(b, len, &i, &out->pairs[k].a) != 0) return -1;
        if (read_u32(b, len, &i, &out->pairs[k].b) != 0) return -1;
    }
    return 0;
}

int vham_parse_nsqueryext(const void *buf, size_t len,
                          vham_nsqueryext_t *out) {
    if (!buf || !out) return -1;
    if (len < 9) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8 (b, len, &i, &out->type)   != 0) return -1;
    if (read_u32(b, len, &i, &out->param1) != 0) return -1;
    if (read_u32(b, len, &i, &out->param2) != 0) return -1;
    if (read_str(b, len, &i, out->s0, sizeof out->s0) != 0) return -1;
    if (read_str(b, len, &i, out->s1, sizeof out->s1) != 0) return -1;
    if (read_str(b, len, &i, out->s2, sizeof out->s2) != 0) return -1;
    if (read_str(b, len, &i, out->s3, sizeof out->s3) != 0) return -1;
    return 0;
}

int vham_parse_verinfo(const void *buf, size_t len, vham_verinfo_t *out) {
    if (!buf || !out) return -1;
    if (len < 2) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    out->major = b[0];
    out->minor = b[1];
    return 0;
}

int vham_parse_usrpos(const void *buf, size_t len, vham_usrpos_t *out) {
    if (!buf || !out) return -1;
    if (len < 11) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u8 (b, len, &i, &out->type)   != 0) return -1;
    if (read_u32(b, len, &i, &out->lat_e6) != 0) return -1;
    if (read_u32(b, len, &i, &out->lon_e6) != 0) return -1;
    if (read_u16(b, len, &i, &out->altitude) != 0) return -1;
    return 0;
}

int vham_parse_routecfg(const void *buf, size_t len, vham_routecfg_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u16(b, len, &i, &out->count) != 0) return -1;
    uint16_t cap = out->count;
    if (cap > VHAM_ROUTECFG_MAX) cap = VHAM_ROUTECFG_MAX;
    for (uint16_t k = 0; k < cap; ++k) {
        for (int f = 0; f < 11; ++f) {
            if (read_str(b, len, &i, out->entries[k].fields[f],
                         sizeof out->entries[k].fields[f]) != 0)
                return -1;
        }
    }
    return 0;
}

int vham_parse_gmem_status(const void *buf, size_t len,
                           vham_gmem_status_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);
    size_t i = 0;
    if (read_u16(b, len, &i, &out->count) != 0) return -1;
    uint16_t cap = out->count;
    if (cap > VHAM_GMEM_STATUS_MAX) cap = VHAM_GMEM_STATUS_MAX;
    for (uint16_t k = 0; k < cap; ++k) {
        vham_gmem_status_entry_t *e = &out->entries[k];
        if (read_str(b, len, &i, e->num, sizeof e->num) != 0) return -1;
        if (read_u8 (b, len, &i, &e->type)       != 0) return -1;
        if (read_u32(b, len, &i, &e->flags)      != 0) return -1;
        if (read_str(b, len, &i, e->name,   sizeof e->name)   != 0) return -1;
        if (read_str(b, len, &i, e->ag_num, sizeof e->ag_num) != 0) return -1;
    }
    return 0;
}

int vham_parse_orglist(const void *buf, size_t len, vham_orglist_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *b = (const uint8_t *)buf;
    memset(out, 0, sizeof *out);

    size_t i = 0;
    if (read_u16(b, len, &i, &out->count) != 0) return -1;
    if (out->count > VHAM_ORG_ENTRIES_MAX) return -1;

    for (uint16_t k = 0; k < out->count; ++k) {
        vham_org_entry_t *e = &out->entries[k];
        if (read_str(b, len, &i, e->num,      sizeof e->num)      != 0) return -1;
        if (read_str(b, len, &i, e->name,     sizeof e->name)     != 0) return -1;
        if (read_str(b, len, &i, e->desc,     sizeof e->desc)     != 0) return -1;
        if (read_u32(b, len, &i, &e->user_num)                    != 0) return -1;
        if (read_u32(b, len, &i, &e->ds_num)                      != 0) return -1;
        if (read_str(b, len, &i, e->ds0_num,  sizeof e->ds0_num)  != 0) return -1;
        if (read_str(b, len, &i, e->ds0_pwd,  sizeof e->ds0_pwd)  != 0) return -1;
        if (read_str(b, len, &i, e->ds_name,  sizeof e->ds_name)  != 0) return -1;
        if (read_str(b, len, &i, e->ds_icon,  sizeof e->ds_icon)  != 0) return -1;
        if (read_str(b, len, &i, e->app_name, sizeof e->app_name) != 0) return -1;
        if (read_str(b, len, &i, e->app_icon, sizeof e->app_icon) != 0) return -1;
    }
    return 0;
}
