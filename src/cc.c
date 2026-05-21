/* libvham/src/cc.c — Call Control message builders.
 *
 * Mirrors CCFsm::UserMakeOut @ libsvcapi.so 0x2ec888.
 *
 * The CC_SETUP frame structure:
 *   TAP header  (class=3 / CC, cmd=0x50 / CC_SETUP)
 *   SRVMSG hdr  (ucDst=4, ucSrc=4, dwSrcFsmId = leg_id)
 *   IE 0x0d     called party (TLV string)
 *   IE 0x0e     calling party (TLV string)
 *   IE 0x23     u32 service type (0x11 = half-duplex PTT, 0x18 = video, ...)
 *   IE 0x19     SDP block (optional in this builder)
 *
 * Real calls in production carry quite a few more IEs (CallExt,
 * CallConf, watch-leg, etc.) but these four are the minimum that
 * makes the frame parseable. The server will reject calls without
 * SDP — which is itself useful feedback for further work.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/cc.h"
#include "vham/sdp.h"
#include "vham/composites.h"
#include <stdio.h>
#include <string.h>

/* ---------- CC call state machine ---------- */

const char *vham_call_state_str(vham_call_state_t s) {
    switch (s) {
    case VHAM_CALL_IDLE:        return "IDLE";
    case VHAM_CALL_SETUP_SENT:  return "SETUP_SENT";
    case VHAM_CALL_SETUP_ACK:   return "SETUP_ACK";
    case VHAM_CALL_ALERTING:    return "ALERTING";
    case VHAM_CALL_CONNECTED:   return "CONNECTED";
    case VHAM_CALL_ACTIVE:      return "ACTIVE";
    case VHAM_CALL_RELEASING:   return "RELEASING";
    case VHAM_CALL_RELEASED:    return "RELEASED";
    case VHAM_CALL_FAILED:      return "FAILED";
    }
    return "?";
}

static void copy_short(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = 0; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

int vham_cc_call_init(vham_cc_call_t *c,
                      const char *my_num,
                      const char *peer_num,
                      uint32_t    leg_id) {
    if (!c || !my_num || !peer_num) return -1;
    memset(c, 0, sizeof *c);
    copy_short(c->my_num,   sizeof c->my_num,   my_num);
    copy_short(c->peer_num, sizeof c->peer_num, peer_num);
    c->leg_id  = leg_id;
    c->seq_no  = 0;
    c->state   = VHAM_CALL_IDLE;
    return 0;
}

/* Build a small CC frame with no IEs other than the SRVMSG header.
 * Used for CC_CONNACK and CC_RLC which carry just header + leg id. */
static int build_cc_bare(uint16_t cmd, uint32_t seq_no,
                         uint32_t src_leg, uint32_t dst_leg,
                         void *out, size_t out_cap) {
    if (out_cap < 32) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_CC)) return -1;
    if (vham_pack_u16(&b, cmd)) return -1;
    if (vham_pack_u32(&b, 16)) return -1;     /* body_len = SRVMSG hdr only */

    /* SRVMSG */
    vham_srvmsg_hdr_t sh = {
        .ucDst      = VHAM_MOD_MM,
        .ucSrc      = VHAM_MOD_MM,
        .wMsgId     = cmd,
        .dwDstFsmId = dst_leg ? dst_leg : 0xffffffff,
        .dwSrcFsmId = src_leg,
        .dwMsgLen   = 0,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    /* dwMsgLen stays 0 because we emit no IEs */
    if (b.err) return -1;
    return (int)b.off;
}

int vham_cc_call_emit(vham_cc_call_t *c,
                      const uint8_t *sdp_bytes, size_t sdp_len,
                      uint32_t service_type,
                      const char *channel_subcode,
                      const char *auth_algorithm,
                      const char *auth_nonce,
                      const char *auth_realm,
                      const char *auth_response,
                      void *out, size_t out_cap) {
    if (!c || !out) return -1;
    c->seq_no++;
    switch (c->state) {
    case VHAM_CALL_IDLE: {
        vham_cc_setup_t s = {
            .seq_no            = c->seq_no,
            .leg_id             = c->leg_id,
            .auth_algorithm     = auth_algorithm,
            .auth_nonce         = auth_nonce,
            .auth_realm         = auth_realm,
            .auth_response      = auth_response,
            .called_num         = c->peer_num,
            .calling_num        = c->my_num,
            .service_type       = service_type,
            .channel_subcode    = channel_subcode,
            .sdp_bytes          = sdp_bytes,
            .sdp_len            = sdp_len,
            .include_callconf   = 1,
            .callconf_str       = "",
            /* IE 0x76 IMType (per com.ids.idtma.util.constants.IMType).
             * The official client uses:
             *   "GROUP"                          for group calls
             *   "{\"pfCallIn\": \"HALFSINGLE\"}" for half-duplex single
             * Heuristic: a purely-numeric called_num is treated as a
             * group/channel number; user dispatch nums are alphanumeric
             * (e.g. "V1NNNNNNNNNN"). */
            .display_str        = NULL,
        };
        int peer_is_numeric = 1;
        for (const char *p = c->peer_num; *p; ++p) {
            if (*p < '0' || *p > '9') { peer_is_numeric = 0; break; }
        }
        s.display_str = peer_is_numeric ? "GROUP"
                                         : "{\"pfCallIn\": \"HALFSINGLE\"}";
        /* CallConf bytes for a half-duplex PTT call with
         * MEDIAATTR[0]=0 (the most common path through the binary). */
        if (service_type == VHAM_CALL_HALF_DUPLEX) {
            s.callconf_bytes[ 0] = 1;   /* offset 4 → byte 0 (after the 4-byte TLV-NUMBER hdr is sliced) */
            s.callconf_bytes[ 1] = 1;   /* offset 5 */
            s.callconf_bytes[ 9] = 1;   /* offset 0xd */
        }
        int n = vham_build_cc_setup(&s, out, out_cap);
        if (n > 0) c->state = VHAM_CALL_SETUP_SENT;
        return n;
    }
    case VHAM_CALL_CONNECTED: {
        int n = build_cc_bare(VHAM_CC_CONNACK, c->seq_no,
                              c->leg_id, c->remote_leg_id,
                              out, out_cap);
        if (n > 0) c->state = VHAM_CALL_ACTIVE;
        return n;
    }
    case VHAM_CALL_RELEASING: {
        /* The binary has no separate RLC msgid — `CCFsm::Rel` sends
         * a CC_REL with a cause code; the peer's CC_REL back closes
         * the leg. Re-emit CC_REL as the release-complete signal. */
        int n = build_cc_bare(VHAM_CC_REL, c->seq_no,
                              c->leg_id, c->remote_leg_id,
                              out, out_cap);
        if (n > 0) c->state = VHAM_CALL_RELEASED;
        return n;
    }
    default:
        return -1;
    }
}

vham_call_state_t vham_cc_call_recv(vham_cc_call_t *c,
                                    const void *buf, size_t len) {
    if (!c) return VHAM_CALL_FAILED;

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) {
        c->state = VHAM_CALL_FAILED;
        return c->state;
    }
    if (th.class_id != VHAM_TAP_CLASS_CC) {
        /* Not a CC frame — silently ignore (don't change state). */
        return c->state;
    }

    /* Capture the server's leg id (dwSrcFsmId) so we can address
     * subsequent acks/rels correctly. */
    if (sh.dwSrcFsmId != 0xffffffff) {
        c->have_remote_leg = 1;
        c->remote_leg_id   = sh.dwSrcFsmId;
    }

    /* Scan IEs */
    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_SESSION_ID: {
            uint32_t v;
            if (vham_ie_get_u32(&ie, &v) == 0) c->last_cause = v;
            break;
        }
        case VHAM_IE_CAUSE_NUM: {
            const char *s = vham_ie_get_str(&ie);
            if (s) {
                long v = 0;
                for (const char *p = s; *p >= '0' && *p <= '9'; ++p)
                    v = v * 10 + (*p - '0');
                c->last_cause = (uint32_t)v;
            }
            break;
        }
        case VHAM_IE_CC_SDP_A:
        case 0x001a:                   /* SDP block B (answer) */
            if (vham_parse_sdp_body(ie.value, ie.len, &c->remote_sdp) == 0)
                c->have_remote_sdp = 1;
            break;
        case VHAM_IE_CC_CALLUSERCTRL: {
            vham_call_userctrl_t uc;
            if (vham_decode_call_userctrl(ie.value, ie.len, &uc) == 0) {
                c->mic_action = uc.action;
                /* The mic holder is uc.num_a (the requesting/releasing
                 * party). Copy compactly. */
                strncpy(c->mic_holder,
                        uc.action == VHAM_USERCTRL_REQUEST ? uc.num_a : "",
                        sizeof c->mic_holder - 1);
                c->mic_holder[sizeof c->mic_holder - 1] = 0;
            }
            break;
        }
        }
    }
    if (rc != 0) {
        c->state = VHAM_CALL_FAILED;
        return c->state;
    }

    /* Transition based on the message id */
    switch (sh.wMsgId) {
    case VHAM_CC_SETUPACK:
        if (c->state == VHAM_CALL_SETUP_SENT) c->state = VHAM_CALL_SETUP_ACK;
        break;
    case VHAM_CC_ALERT:
        c->state = VHAM_CALL_ALERTING;
        break;
    case VHAM_CC_CONN:
        c->state = VHAM_CALL_CONNECTED;
        break;
    case VHAM_CC_CONNACK:
        c->state = VHAM_CALL_ACTIVE;
        break;
    case VHAM_CC_REL:
        /* First CC_REL transitions to RELEASING; a second CC_REL
         * (after we've sent our own CC_REL back) means the leg is
         * fully released. */
        c->state = (c->state == VHAM_CALL_RELEASING)
                       ? VHAM_CALL_RELEASED
                       : VHAM_CALL_RELEASING;
        break;
    default:
        /* Unknown CC msg — leave state alone */
        break;
    }
    return c->state;
}

/* Common skeleton: emit TAP + SRVMSG header for a CC frame, return
 * the buffer with offsets set so the caller can append IEs and patch.
 * On success returns 0 and writes b/srv_off/tap_len_off/body_start. */
static int cc_header_open(vham_buf_t *b, vham_cc_call_t *c,
                          uint16_t cmd,
                          size_t *tap_len_off, size_t *body_start,
                          size_t *srvmsg_len_off,
                          size_t *srvmsg_body_start) {
    if (vham_pack_u8 (b, 0x01)) return -1;
    if (vham_pack_u8 (b, 0x00)) return -1;
    if (vham_pack_u16(b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(b, c->seq_no)) return -1;
    if (vham_pack_u16(b, VHAM_TAP_CLASS_CC)) return -1;
    if (vham_pack_u16(b, cmd)) return -1;
    *tap_len_off = b->off;
    if (vham_pack_u32(b, 0)) return -1;
    *body_start = b->off;

    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_CC, .ucSrc = VHAM_MOD_CC,
        .wMsgId = cmd,
        .dwDstFsmId = c->have_remote_leg ? c->remote_leg_id : 0xffffffff,
        .dwSrcFsmId = c->leg_id,
    };
    if (vham_pack_srvmsg_header(b, &sh, srvmsg_len_off)) return -1;
    *srvmsg_body_start = b->off;
    return 0;
}

static int cc_header_close(vham_buf_t *b, vham_cc_call_t *c,
                           size_t tap_len_off, size_t body_start,
                           size_t srvmsg_len_off, size_t srvmsg_body_start) {
    if (vham_patch_srvmsg_len(b, srvmsg_len_off, srvmsg_body_start))
        return -1;
    uint32_t tap_body = (uint32_t)(b->off - body_start);
    b->buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b->buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b->buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b->buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b->err) return -1;
    c->seq_no += 1;
    return (int)b->off;
}

int vham_cc_call_release(vham_cc_call_t *c, uint32_t cause,
                         void *out, size_t out_cap) {
    if (!c || !out) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_len_off, body_start, srv_len_off, srv_body;
    if (cc_header_open(&b, c, VHAM_CC_REL, &tap_len_off, &body_start,
                       &srv_len_off, &srv_body) != 0) return -1;
    /* IE 0x40 CauseNum — decimal string */
    char cause_str[16];
    int written = snprintf(cause_str, sizeof cause_str, "%u", cause);
    if (written < 0) return -1;
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_CAUSE_NUM, cause_str)) return -1;
    int rc = cc_header_close(&b, c, tap_len_off, body_start,
                             srv_len_off, srv_body);
    if (rc > 0) c->state = VHAM_CALL_RELEASING;
    return rc;
}

int vham_cc_call_answer(vham_cc_call_t *c,
                        const uint8_t *sdp_bytes, size_t sdp_len,
                        void *out, size_t out_cap) {
    if (!c || !out || !sdp_bytes || sdp_len == 0) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_len_off, body_start, srv_len_off, srv_body;
    if (cc_header_open(&b, c, VHAM_CC_CONN, &tap_len_off, &body_start,
                       &srv_len_off, &srv_body) != 0) return -1;
    /* IE 0x19 SDP answer */
    if (vham_pack_tlv_fix(&b, 1, VHAM_IE_CC_SDP_A, sdp_bytes, sdp_len))
        return -1;
    int rc = cc_header_close(&b, c, tap_len_off, body_start,
                             srv_len_off, srv_body);
    if (rc > 0) c->state = VHAM_CALL_CONNECTED;
    return rc;
}

int vham_cc_call_setup_ack(vham_cc_call_t *c, void *out, size_t out_cap) {
    if (!c || !out) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_len_off, body_start, srv_len_off, srv_body;
    if (cc_header_open(&b, c, VHAM_CC_SETUPACK, &tap_len_off, &body_start,
                       &srv_len_off, &srv_body) != 0) return -1;
    return cc_header_close(&b, c, tap_len_off, body_start,
                           srv_len_off, srv_body);
}

int vham_cc_call_info_ack(vham_cc_call_t *c, void *out, size_t out_cap) {
    if (!c || !out) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_len_off, body_start, srv_len_off, srv_body;
    if (cc_header_open(&b, c, VHAM_CC_INFOACK, &tap_len_off, &body_start,
                       &srv_len_off, &srv_body) != 0) return -1;
    return cc_header_close(&b, c, tap_len_off, body_start,
                           srv_len_off, srv_body);
}

int vham_cc_call_mic_grant(vham_cc_call_t *c, int action,
                           void *out, size_t out_cap) {
    if (!c || !out) return -1;
    if (action != VHAM_USERCTRL_REQUEST && action != VHAM_USERCTRL_RELEASE)
        return -1;

    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_len_off, body_start, srv_len_off, srv_body;
    if (cc_header_open(&b, c, VHAM_CC_INFO, &tap_len_off, &body_start,
                       &srv_len_off, &srv_body) != 0) return -1;

    /* IE 0x27 (number) — our dispatch number, mirrored from MicCtrl. */
    if (c->my_num[0]) {
        if (vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, c->my_num))
            return -1;
    }
    /* IE 0x54 (CallUserCtrl) body. */
    vham_call_userctrl_t uc = { .action = (uint8_t)action };
    strncpy(uc.num_a, c->my_num,   sizeof uc.num_a - 1);
    strncpy(uc.num_b, c->peer_num, sizeof uc.num_b - 1);
    uint8_t ucb[80];
    int ucn = vham_encode_call_userctrl(&uc, ucb, sizeof ucb);
    if (ucn < 0) return -1;
    if (vham_pack_tlv_fix(&b, 1, VHAM_IE_CC_CALLUSERCTRL,
                          ucb, (size_t)ucn)) return -1;

    return cc_header_close(&b, c, tap_len_off, body_start,
                           srv_len_off, srv_body);
}

int vham_build_cc_setup(const vham_cc_setup_t *p, void *out, size_t out_cap) {
    if (!p || !out) return -1;
    if (!p->called_num || !p->calling_num) return -1;
    if (out_cap < 64) return -1;

    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, p->seq_no)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_CC)) return -1;
    if (vham_pack_u16(&b, VHAM_CC_SETUP)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    /* SRVMSG header. Note: CCFsm::UserMakeOut uses ucDst=ucSrc=4 (MM)
     * even for CC_SETUP — the message routes through the MM
     * dispatcher on the server side. dwSrcFsmId is the leg id. */
    vham_srvmsg_hdr_t sh = {
        .ucDst      = VHAM_MOD_MM,
        .ucSrc      = VHAM_MOD_MM,
        .wMsgId     = VHAM_CC_SETUP,
        .dwDstFsmId = 0xffffffff,
        .dwSrcFsmId = p->leg_id,
        .dwMsgLen   = 0,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* IE order follows SrvPackMsg's emission order (lowest tag first).
     *
     *   0x07 algorithm   (optional echo of MM challenge)
     *   0x09 nonce
     *   0x0a realm
     *   0x0b auth resp
     *   0x0d called num
     *   0x0e calling num
     *   0x19 SDP A
     *   0x23 service type
     *   0x76 display string (optional)
     */
    if (p->auth_algorithm && *p->auth_algorithm &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_ALGORITHM, p->auth_algorithm))
        return -1;
    if (p->auth_nonce && *p->auth_nonce &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_NONCE, p->auth_nonce))
        return -1;
    if (p->auth_realm && *p->auth_realm &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_REALM, p->auth_realm))
        return -1;
    if (p->auth_response && *p->auth_response &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_RESPONSE, p->auth_response))
        return -1;
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_CC_CALLED_NUM, p->called_num))
        return -1;
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_CC_CALLING_NUM, p->calling_num))
        return -1;
    if (p->sdp_bytes && p->sdp_len > 0 &&
        vham_pack_tlv_fix(&b, 1, VHAM_IE_CC_SDP_A,
                          p->sdp_bytes, p->sdp_len))
        return -1;
    if (vham_pack_tlv_u32(&b, 1, VHAM_IE_CC_SERVICE, p->service_type))
        return -1;
    /* IE 0x45 — channel sub-code (CTCSS-style). Emitted only if
     * the caller supplied one for the channel they're calling. */
    if (p->channel_subcode && *p->channel_subcode &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_CC_SUBCODE, p->channel_subcode))
        return -1;

    /* IE 0x53 — CallConf. Binary always emits this for CC_SETUP. */
    if (p->include_callconf) {
        const char *cc_str = p->callconf_str ? p->callconf_str : "";
        size_t cc_str_len  = strlen(cc_str);
        uint16_t total_len = (uint16_t)(11 + cc_str_len + 1);  /* 11 bytes + str + NUL */
        if (vham_pack_u16(&b, VHAM_IE_CC_CALLCONF)) return -1;
        if (vham_pack_u16(&b, total_len))           return -1;
        for (int i = 0; i < 11; ++i) {
            if (vham_pack_u8(&b, p->callconf_bytes[i])) return -1;
        }
        if (vham_pack_str(&b, cc_str)) return -1;
    }

    /* IE 0x76 — display string (optional) */
    if (p->display_str && *p->display_str &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_CC_DISPLAY, p->display_str))
        return -1;

    /* IE 0x7e — private/sub number (optional) */
    if (p->priv_num && *p->priv_num &&
        vham_pack_tlv_str(&b, 1, VHAM_IE_CC_PRIV_NUM, p->priv_num))
        return -1;

    /* Patch SRVMSG.dwMsgLen */
    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start))
        return -1;

    /* Patch TAP.body_len */
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >>  8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);

    if (b.err) return -1;
    return (int)b.off;
}
