/* libvham/src/regrsp.c — MM_REGRSP parser + tiny client state machine.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/regrsp.h"
#include <string.h>

/* Copy a NUL-terminated IE string into a fixed-size destination,
 * bounded by both the IE's length and the destination's capacity. */
static void copy_str_ie(char *dst, size_t dst_cap, const vham_ie_t *ie) {
    if (!dst || dst_cap == 0) return;
    dst[0] = 0;
    const char *s = vham_ie_get_str(ie);
    if (!s) return;
    size_t n = strlen(s);
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, s, n);
    dst[n] = 0;
}

int vham_parse_regrsp(const void *buf, size_t len, vham_regrsp_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof *out);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) return -1;
    /* Different server nodes use different (ucDst, ucSrc) pairs:
     *   port-10000 dispatcher: ucDst=API(3) ucSrc=MM(4)
     *   port-10201 signaling : ucDst=MM(4)  ucSrc=CC(5)
     *   loopback / mock      : ucDst=MM(4)  ucSrc=MM(4)
     * Identify REGRSP purely by wMsgId. */
    if (sh.wMsgId != VHAM_MM_REGRSP) return -1;

    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_SUB_OPCODE:
            if (vham_ie_get_u16(&ie, &out->sub_opcode) == 0)
                out->have_sub_opcode = 1;
            break;
        case VHAM_IE_AUTH_ALGORITHM:
            copy_str_ie(out->algorithm, sizeof out->algorithm, &ie);
            break;
        case VHAM_IE_AUTH_NONCE:
            copy_str_ie(out->nonce, sizeof out->nonce, &ie);
            break;
        case VHAM_IE_AUTH_REALM:
            copy_str_ie(out->realm, sizeof out->realm, &ie);
            break;
        case VHAM_IE_AUTH_MODE:
            if (vham_ie_get_u32(&ie, &out->auth_mode) == 0)
                out->have_auth_mode = 1;
            break;
        case VHAM_IE_DISPATCH_NUM:
            copy_str_ie(out->dispatch_num, sizeof out->dispatch_num, &ie);
            break;
        case VHAM_IE_SERVER_ADDR: {
            vham_ipaddr_t a;
            if (vham_ie_get_ipaddr(&ie, &a) == 0) {
                out->have_server_addr = 1;
                out->server_addr_ipv4 = a.ipv4;
                out->server_addr_port = a.port;
            }
            break;
        }
        case VHAM_IE_SESSION_ID:
            if (vham_ie_get_u32(&ie, &out->session_id) == 0)
                out->have_session_id = 1;
            break;
        case VHAM_IE_MEDIA_GW: {
            vham_ipaddr_t a;
            if (vham_ie_get_ipaddr6(&ie, &a) == 0) {
                out->have_media_gw = 1;
                out->media_gw_ipv4 = a.ipv4;
                out->media_gw_port = a.port;
            }
            break;
        }
        case VHAM_IE_ALT_ENDPOINT: {
            vham_ipaddr_t a;
            if (vham_ie_get_ipaddr6(&ie, &a) == 0) {
                out->have_alt_endpoint = 1;
                out->alt_ipv4 = a.ipv4;
                out->alt_port = a.port;
            }
            break;
        }
        case VHAM_IE_SYS_TIME:
            if (ie.len == 16) {
                out->have_sys_time = 1;
                out->sys_year   = vham_unpack_u16(ie.value);
                out->sys_month  = vham_unpack_u16(ie.value + 2);
                out->sys_day    = vham_unpack_u16(ie.value + 4);
                out->sys_hour   = vham_unpack_u16(ie.value + 6);
                out->sys_min    = vham_unpack_u16(ie.value + 8);
                out->sys_sec    = vham_unpack_u16(ie.value + 10);
                out->sys_subsec = vham_unpack_u16(ie.value + 12);
            }
            break;
        case VHAM_IE_FTP_SRV:
            if (ie.len <= sizeof out->ftp_blob) {
                memcpy(out->ftp_blob, ie.value, ie.len);
                out->ftp_blob_len = ie.len;
            }
            break;
        case VHAM_IE_ORG_LIST:
            if (ie.len <= sizeof out->org_blob) {
                memcpy(out->org_blob, ie.value, ie.len);
                out->org_blob_len = ie.len;
            }
            break;
        case VHAM_IE_USERGINFO_A:
        case VHAM_IE_USERGINFO_B:
            if (ie.len <= sizeof out->ginfo_blob) {
                memcpy(out->ginfo_blob, ie.value, ie.len);
                out->ginfo_blob_len = ie.len;
            }
            break;
        case VHAM_IE_CAUSE_NUM: {
            /* _TLV_NUMBER_s — a NUL-terminated decimal string */
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                long v = 0;
                for (const char *p = s; *p >= '0' && *p <= '9'; ++p)
                    v = v * 10 + (*p - '0');
                out->cause = (uint16_t)v;
                out->have_cause = 1;
            }
            break;
        }
        default:
            /* unknown IE — skip cleanly, mirroring SrvUnpkIe */
            break;
        }
    }
    return (rc == 0) ? 0 : -1;
}

/* ---------- MM_STATUSSUBS encoder ---------- */

int vham_build_status_subs_multi(uint32_t seq_no,
                                 const char *username,
                                 const vham_subs_entry_t *entries,
                                 size_t      n_entries,
                                 uint32_t    counter,
                                 void *out, size_t out_cap) {
    if (!out || !username || !entries || n_entries == 0) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_MM)) return -1;
    if (vham_pack_u16(&b, VHAM_MM_STATUSSUBS)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_MM_STATUSSUBS,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    if (vham_pack_tlv_u32(&b, 1, VHAM_IE_COUNTER, counter)) return -1;
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, username)) return -1;

    /* IE 0x4b — variable-length list of (string, level) entries
     * terminated by a single zero byte. */
    if (vham_pack_u16(&b, VHAM_IE_STATUS_SUBS)) return -1;
    size_t ie_len_off = b.off;
    if (vham_pack_u16(&b, 0)) return -1;  /* placeholder */
    size_t ie_body_start = b.off;
    for (size_t i = 0; i < n_entries; ++i) {
        if (!entries[i].target || strlen(entries[i].target) > 31) return -1;
        if (vham_pack_str(&b, entries[i].target)) return -1;
        if (vham_pack_u8 (&b, entries[i].level))   return -1;
    }
    if (vham_pack_u8(&b, 0)) return -1;     /* end-of-list */
    if (b.err) return -1;
    uint16_t ie_body_len = (uint16_t)(b.off - ie_body_start);
    b.buf[ie_len_off    ] = (uint8_t)(ie_body_len >> 8);
    b.buf[ie_len_off + 1] = (uint8_t)(ie_body_len);

    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    return (int)b.off;
}

int vham_build_status_subs(uint32_t seq_no,
                           const char *username,
                           const char *target,
                           uint8_t     level,
                           uint32_t    counter,
                           void *out, size_t out_cap) {
    vham_subs_entry_t e = { .target = target, .level = level };
    return vham_build_status_subs_multi(seq_no, username, &e, 1,
                                        counter, out, out_cap);
}

/* ---------- MM async notifications ---------- */

int vham_parse_mm_notify(const void *buf, size_t len,
                         vham_mm_notify_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof *out);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) return -1;
    if (sh.wMsgId != VHAM_MM_REGRSP) return -1;
    /* Heuristic: notifications come from CC (5) instead of MM (4),
     * and they don't include any digest-challenge IEs. */
    if (sh.ucSrc != VHAM_MOD_CC) return -1;

    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_SUB_OPCODE:
            vham_ie_get_u16(&ie, &out->sub_opcode);
            break;
        case VHAM_IE_REG_TYPE:
            vham_ie_get_u8(&ie, &out->notify_status);
            break;
        case VHAM_IE_IDENTITY_NUM: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                size_t n = strlen(s);
                if (n >= sizeof out->echoed_num)
                    n = sizeof out->echoed_num - 1;
                memcpy(out->echoed_num, s, n);
                out->echoed_num[n] = 0;
            }
            break;
        }
        default: break;
        }
    }
    if (rc != 0) return -1;
    out->have_notify = 1;
    return 0;
}

int vham_build_mm_quit(uint32_t seq_no, const char *username,
                       void *out, size_t out_cap) {
    return vham_build_mm_simple(VHAM_MM_QUIT, seq_no, username,
                                NULL, NULL, out, out_cap);
}

int vham_parse_status_notify(const void *buf, size_t len,
                             vham_status_notify_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof *out);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) return -1;
    if (sh.wMsgId != 0x0091) return -1;

    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_IDENTITY_NUM: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                strncpy(out->subject_num, s, sizeof out->subject_num - 1);
                out->have_subject = 1;
            }
            break;
        }
        case VHAM_IE_COUNTER:
            if (vham_ie_get_u32(&ie, &out->counter) == 0)
                out->have_counter = 1;
            break;
        case VHAM_IE_REG_TYPE:
            if (vham_ie_get_u8(&ie, &out->status) == 0)
                out->have_status = 1;
            break;
        case 0x006c: {                    /* peer number (PEER_NUM) */
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                strncpy(out->peer_num, s, sizeof out->peer_num - 1);
                out->have_peer = 1;
            }
            break;
        }
        default: break;
        }
    }
    return rc == 0 ? 0 : -1;
}

int vham_build_mm_simple(uint16_t wmsgid, uint32_t seq_no,
                         const char *username,
                         vham_mm_extra_pack_fn extras_fn, void *extras_ctx,
                         void *out, size_t out_cap) {
    if (!out || !username) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_MM)) return -1;
    if (vham_pack_u16(&b, wmsgid)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = wmsgid,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srv_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srv_len_off)) return -1;
    size_t srv_body_start = b.off;

    /* IE 0x27 — our username */
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, username)) return -1;

    /* Caller-supplied extras (additional IEs). */
    if (extras_fn) {
        int en = extras_fn(extras_ctx, b.buf + b.off, b.cap - b.off);
        if (en < 0) return -1;
        b.off += (size_t)en;
    }

    if (vham_patch_srvmsg_len(&b, srv_len_off, srv_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}

/* ---------- registration client ---------- */

static void copy_bounded(char *dst, size_t dst_cap, const char *src) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = 0; return; }
    size_t n = strlen(src);
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

int vham_reg_client_init(vham_reg_client_t *c,
                         const char *username,
                         const char *password,
                         uint32_t server_ipv4,
                         uint16_t server_port) {
    if (!c || !username || !password) return -1;
    memset(c, 0, sizeof *c);
    copy_bounded(c->username, sizeof c->username, username);
    copy_bounded(c->password, sizeof c->password, password);
    c->server_ipv4 = server_ipv4;
    c->server_port = server_port;
    c->seq_no      = 0;
    c->state       = VHAM_REG_INIT;
    return 0;
}

int vham_reg_client_emit(vham_reg_client_t *c,
                         void *out, size_t out_cap) {
    if (!c || !out) return -1;

    /* Initial REGREQ (no auth) */
    if (c->state == VHAM_REG_INIT) {
        c->seq_no++;
        vham_regreq_t r = {
            .seq_no       = c->seq_no,
            .reg_type     = VHAM_REGTYPE_USER,
            .username     = c->username,
            .self_num     = c->username,
            .server_ipv4  = c->server_ipv4,
            .server_port  = c->server_port,
            .feature_mask = 0x00000098u,
        };
        int n = vham_build_regreq(&r, out, out_cap);
        if (n > 0) c->state = VHAM_REG_SENT_INITIAL;
        return n;
    }

    /* Auth REGREQ — has algorithm/nonce/realm/response from saved
     * state, plus any IE 0x62/0x70 echoes the server provided. */
    if (c->state == VHAM_REG_SENT_INITIAL && c->last_response_hex[0]) {
        c->seq_no++;
        vham_regreq_t r = {
            .seq_no             = c->seq_no,
            .reg_type           = VHAM_REGTYPE_USER,
            .username           = c->username,
            .self_num           = c->username,
            .server_ipv4        = c->server_ipv4,
            .server_port        = c->server_port,
            .feature_mask       = 0x00000098u,
            .auth_algorithm     = c->last_algorithm,
            .auth_nonce         = c->last_nonce,
            .auth_realm         = c->last_realm,
            .auth_response_hex  = c->last_response_hex,
            .echo_auth_mode     = c->have_auth_mode,
            .auth_mode_value    = c->auth_mode,
            .auth_dispatch_num  = c->dispatch_num,
        };
        int n = vham_build_regreq(&r, out, out_cap);
        if (n > 0) c->state = VHAM_REG_SENT_AUTH;
        return n;
    }
    return -1;
}

vham_reg_state_t vham_reg_client_recv(vham_reg_client_t *c,
                                      const void *buf, size_t len) {
    if (!c) return VHAM_REG_FAILED;
    vham_regrsp_t r;
    if (vham_parse_regrsp(buf, len, &r) != 0) {
        c->state = VHAM_REG_FAILED;
        return c->state;
    }

    /* Dispatcher hop — when the server tells us via IE 0x24 to talk
     * to a different endpoint, update the client's target and signal
     * the caller via VHAM_REG_REDIRECT. Caller is expected to reopen
     * its socket and call vham_reg_client_emit() again to restart. */
    if (r.have_server_addr &&
        (r.server_addr_ipv4 != c->server_ipv4 ||
         r.server_addr_port != c->server_port)) {
        c->server_ipv4 = r.server_addr_ipv4;
        c->server_port = r.server_addr_port;
        c->state       = VHAM_REG_INIT;        /* re-emit phase 1 */
        c->seq_no      = 0;
        return VHAM_REG_REDIRECT;
    }

    /* Capture server-allocated echo fields regardless of opcode */
    if (r.have_auth_mode) {
        c->have_auth_mode = 1;
        c->auth_mode      = r.auth_mode;
    }
    if (r.dispatch_num[0]) {
        copy_bounded(c->dispatch_num, sizeof c->dispatch_num, r.dispatch_num);
    }

    /* Capture session fields from any REGRSP — they're only
     * populated on the final success but the parser is tolerant. */
    if (r.have_session_id) {
        c->have_session_id = 1;
        c->session_id      = r.session_id;
    }
    if (r.have_sys_time) {
        c->have_sys_time = 1;
        c->sys_year      = r.sys_year;
        c->sys_month     = r.sys_month;
        c->sys_day       = r.sys_day;
        c->sys_hour      = r.sys_hour;
        c->sys_min       = r.sys_min;
        c->sys_sec       = r.sys_sec;
        c->sys_subsec    = r.sys_subsec;
    }
    if (r.have_media_gw) {
        c->have_media_gw = 1;
        c->media_gw_ipv4 = r.media_gw_ipv4;
        c->media_gw_port = r.media_gw_port;
    }
    if (r.have_alt_endpoint) {
        c->have_alt_endpoint = 1;
        c->alt_ipv4          = r.alt_ipv4;
        c->alt_port          = r.alt_port;
    }
    if (r.org_blob_len > 0 &&
        vham_parse_orglist(r.org_blob, r.org_blob_len, &c->org) == 0) {
        c->have_org = 1;
    }
    if (r.ginfo_blob_len > 0 &&
        vham_parse_user_ginfo(r.ginfo_blob, r.ginfo_blob_len, &c->ginfo) == 0) {
        c->have_ginfo = 1;
    }
    if (r.ftp_blob_len > 0 &&
        vham_parse_ftpinfo(r.ftp_blob, r.ftp_blob_len, &c->ftp) == 0) {
        c->have_ftp = 1;
    }

    /* Auth challenge — detected by the presence of nonce or by the
     * sub_opcode being a known "challenge" code (0x53 = dispatcher
     * style, 0x19 = signaling-node style). */
    int looks_like_challenge =
            r.nonce[0] != 0 ||
            (r.have_sub_opcode &&
             (r.sub_opcode == 0x0053 || r.sub_opcode == 0x0019));
    if (looks_like_challenge) {
        if (c->state != VHAM_REG_SENT_INITIAL) {
            c->state = VHAM_REG_FAILED;
            return c->state;
        }
        copy_bounded(c->last_algorithm, sizeof c->last_algorithm, r.algorithm);
        copy_bounded(c->last_nonce,     sizeof c->last_nonce,     r.nonce);
        copy_bounded(c->last_realm,     sizeof c->last_realm,     r.realm);
        if (vham_auth_md5(c->username,
                          c->last_realm,
                          c->password,
                          "REGISTER",
                          c->last_algorithm[0] ? c->last_algorithm : "MD5",
                          c->last_nonce,
                          NULL, NULL, "0.0.0.0", NULL,
                          c->last_response_hex) != 0) {
            c->state = VHAM_REG_FAILED;
        }
        /* state stays at SENT_INITIAL; caller invokes emit() again */
        return c->state;
    }

    /* Non-challenge response: success or failure */
    if (c->state == VHAM_REG_SENT_AUTH) {
        c->state = (r.have_cause && r.cause != 0)
                 ? VHAM_REG_FAILED
                 : VHAM_REG_OK;
    } else if (c->state == VHAM_REG_SENT_INITIAL) {
        /* Server skipped the challenge (e.g. cached token). Treat as
         * either OK or FAILED based on cause. */
        c->state = (r.have_cause && r.cause != 0)
                 ? VHAM_REG_FAILED
                 : VHAM_REG_OK;
    } else {
        c->state = VHAM_REG_FAILED;
    }
    return c->state;
}
