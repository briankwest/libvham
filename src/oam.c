/* libvham/src/oam.c — OAM frame encoders.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "vham/codec.h"
#include "vham/oam.h"

/* OAM_RSP carries these IEs (decoded from live server replies). */
#define IE_RSP_STATUS   0x0002  /* u16 */
#define IE_RSP_OP       0x001b  /* u32 — echo of op code */
#define IE_RSP_COUNT    0x0021  /* u32 — entries returned */
#define IE_RSP_TARGET   0x0040  /* NUMBER — echo of target */
#define IE_RSP_USRGINFO 0x0043  /* composite — when count > 0 */
#define IE_RSP_SESSION  0x0044  /* u32 session_id */
#define IE_RSP_SENDER   0x005d  /* NUMBER — echo of sender */

/* IE tags identified from SrvPackMsg's case table. */
#define IE_NUM_GENERAL  0x0040  /* IE 0x40 at offset 0x158ccc */
#define IE_GROUP_NAME   0x0041  /* IE 0x41 at offset 0x158d10 (STR) */
#define IE_GROUP_DESC   0x0046  /* IE 0x46 at offset 0x158bf8 (STR) */
#define IE_GROUP_TYPE   0x0030  /* IE 0x30 at offset 0x8496 (u8) */
#define IE_USERGINFO    0x0043  /* IE 0x43 at offset 0x2dbac (composite) */
#define IE_OAM_OP_CODE  0x001b  /* IE 0x1b at offset 0x834c (u32) */
#define IE_DW_SN        0x0042  /* IE 0x42 at offset 0x158d98 (u32) */
#define IE_QUERY_EXT    0x0091  /* IE 0x91 at offset 0x19f64c — QueryExt 16B */
#define IE_SENDER_NUM   0x005d  /* IE 0x5d at offset 0x17d328 (NUMBER) */

int vham_build_oam_gqueryu(uint32_t seq_no,
                           const char *sender_num,
                           const char *target_num,
                           uint32_t    dw_sn,
                           const vham_query_ext_t *q,
                           void *out, size_t out_cap) {
    if (!out || !sender_num || !target_num) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq_no)) return -1;
    if (vham_pack_u16(&b, 4)) return -1;                 /* class = 4 (OAM) */
    if (vham_pack_u16(&b, VHAM_OAM_REQ)) return -1;      /* cmd = 0x70 */
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    /* SRVMSG header (ucDst=CC=5, ucSrc=MA=6, FsmIds = -1) */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_CC, .ucSrc = VHAM_MOD_MA,
        .wMsgId = VHAM_OAM_REQ,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off)) return -1;
    size_t srvmsg_body_start = b.off;

    /* IE 0x40 — target group / user number to query */
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL, target_num)) return -1;

    /* IE 0x1b — OAM_OP_CODE (u32) = 12 (GQueryU) */
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GQUERYU)) return -1;

    /* IE 0x42 — dwSn (u32, scope flag) */
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;

    /* IE 0x91 — QueryExt (16-byte composite) */
    vham_query_ext_t z = {0};
    if (!q) q = &z;
    uint8_t qb[16];
    qb[0] = q->uc_all;
    qb[1] = q->uc_group;
    qb[2] = q->uc_user;
    qb[3] = q->uc_order;
    qb[4]  = (uint8_t)(q->dw_page >> 24);
    qb[5]  = (uint8_t)(q->dw_page >> 16);
    qb[6]  = (uint8_t)(q->dw_page >> 8);
    qb[7]  = (uint8_t)(q->dw_page);
    qb[8]  = (uint8_t)(q->dw_count >> 24);
    qb[9]  = (uint8_t)(q->dw_count >> 16);
    qb[10] = (uint8_t)(q->dw_count >> 8);
    qb[11] = (uint8_t)(q->dw_count);
    qb[12] = (uint8_t)(q->dw_total >> 24);
    qb[13] = (uint8_t)(q->dw_total >> 16);
    qb[14] = (uint8_t)(q->dw_total >> 8);
    qb[15] = (uint8_t)(q->dw_total);
    if (vham_pack_tlv_fix(&b, 1, IE_QUERY_EXT, qb, sizeof qb)) return -1;

    /* IE 0x5d — sender's dispatch number */
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;

    if (vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start))
        return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}

/* Pack a 1-entry UsrGInfo IE body. The entry describes the user we
 * want to add: we fill the bare-minimum fields. */
static int pack_userginfo_one(vham_buf_t *b, const char *user_num) {
    /* IE 0x43 header */
    if (vham_pack_u16(b, IE_USERGINFO)) return -1;
    size_t len_off = b->off;
    if (vham_pack_u16(b, 0)) return -1;            /* placeholder */
    size_t body = b->off;

    /* count = 1 */
    if (vham_pack_u16(b, 1)) return -1;
    /* prio, type, ut_type, attr */
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    /* Num */
    if (vham_pack_str(b, user_num)) return -1;
    /* Name */
    if (vham_pack_str(b, "")) return -1;
    /* AGNum */
    if (vham_pack_str(b, "")) return -1;
    /* chan_num, status, fg_count */
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    /* FGNum */
    if (vham_pack_str(b, "")) return -1;

    if (b->err) return -1;
    uint16_t L = (uint16_t)(b->off - body);
    b->buf[len_off    ] = (uint8_t)(L >> 8);
    b->buf[len_off + 1] = (uint8_t)(L);
    return 0;
}

int vham_parse_oam_rsp(const void *buf, size_t len, vham_oam_rsp_t *out) {
    if (!buf || !out) return -1;
    memset(out, 0, sizeof *out);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    if (vham_parse_packet(buf, len, &th, &sh, &rd) != 0) return -1;
    if (th.class_id != 4 || th.cmd != 0x0071) return -1;

    out->session_id = 0;
    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case IE_RSP_STATUS:
            if (vham_ie_get_u16(&ie, &out->status) == 0) out->have_status = 1;
            break;
        case IE_RSP_OP:
            if (vham_ie_get_u32(&ie, &out->op_code) == 0) out->have_op = 1;
            break;
        case IE_RSP_COUNT:
            if (vham_ie_get_u32(&ie, &out->count) == 0) out->have_count = 1;
            break;
        case IE_RSP_TARGET: {
            const char *s = vham_ie_get_str(&ie);
            if (s) strncpy(out->target_num, s, sizeof out->target_num - 1);
            break;
        }
        case IE_RSP_SENDER: {
            const char *s = vham_ie_get_str(&ie);
            if (s) strncpy(out->echoed_num, s, sizeof out->echoed_num - 1);
            break;
        }
        case IE_RSP_SESSION:
            if (vham_ie_get_u32(&ie, &out->session_id) == 0)
                out->have_session_id = 1;
            break;
        case IE_RSP_USRGINFO:
            if (vham_parse_user_ginfo(ie.value, ie.len, &out->ginfo) == 0)
                out->have_ginfo = 1;
            break;
        default: break;
        }
    }
    return rc == 0 ? 0 : -1;
}

/* Shared OAM_REQ skeleton: TAP+SRVMSG header. */
static int oam_open(vham_buf_t *b, uint32_t seq_no,
                    size_t *tap_len_off, size_t *body_start,
                    size_t *srv_len_off, size_t *srv_body) {
    if (vham_pack_u8 (b, 0x01)) return -1;
    if (vham_pack_u8 (b, 0x00)) return -1;
    if (vham_pack_u16(b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(b, seq_no)) return -1;
    if (vham_pack_u16(b, 4)) return -1;
    if (vham_pack_u16(b, VHAM_OAM_REQ)) return -1;
    *tap_len_off = b->off;
    if (vham_pack_u32(b, 0)) return -1;
    *body_start = b->off;
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_CC, .ucSrc = VHAM_MOD_MA,
        .wMsgId = VHAM_OAM_REQ,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    if (vham_pack_srvmsg_header(b, &sh, srv_len_off)) return -1;
    *srv_body = b->off;
    return 0;
}

static int oam_close(vham_buf_t *b, size_t tap_len_off, size_t body_start,
                     size_t srv_len_off, size_t srv_body) {
    if (vham_patch_srvmsg_len(b, srv_len_off, srv_body)) return -1;
    uint32_t tap_body = (uint32_t)(b->off - body_start);
    b->buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b->buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b->buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b->buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b->err) return -1;
    return (int)b->off;
}

int vham_build_oam_gaddu(uint32_t seq_no,
                         const char *sender_num,
                         const char *target_num,
                         uint32_t    dw_sn,
                         void *out, size_t out_cap) {
    if (!out || !sender_num || !target_num) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_off, body, srv_off, srv_body;
    if (oam_open(&b, seq_no, &tap_off, &body, &srv_off, &srv_body)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL, target_num)) return -1;
    if (pack_userginfo_one(&b, sender_num)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GADDU)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;
    return oam_close(&b, tap_off, body, srv_off, srv_body);
}

int vham_build_oam_gdelu(uint32_t seq_no,
                         const char *sender_num,
                         const char *target_num,
                         uint32_t    dw_sn,
                         void *out, size_t out_cap) {
    if (!out || !sender_num || !target_num) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_off, body, srv_off, srv_body;
    if (oam_open(&b, seq_no, &tap_off, &body, &srv_off, &srv_body)) return -1;
    /* IE 0x40 group num + IE 0x27 user-to-delete (NOT a UsrGInfo block —
     * GDelU is leaner than GAddU). */
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL,    target_num)) return -1;
    if (vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, sender_num)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GDELU)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;
    return oam_close(&b, tap_off, body, srv_off, srv_body);
}

/* Pack a 1-entry UsrGInfo IE with explicit prio + name. (Currently
 * unused — kept for future GModify variants that may need it.) */
__attribute__((unused))
static int pack_userginfo_explicit(vham_buf_t *b, const char *user_num,
                                   const char *name, uint8_t prio) {
    if (vham_pack_u16(b, IE_USERGINFO)) return -1;
    size_t len_off = b->off;
    if (vham_pack_u16(b, 0)) return -1;
    size_t body = b->off;
    if (vham_pack_u16(b, 1)) return -1;        /* count */
    if (vham_pack_u8(b, prio)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_str(b, user_num ? user_num : "")) return -1;
    if (vham_pack_str(b, name     ? name     : "")) return -1;
    if (vham_pack_str(b, "")) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_u8(b, 0)) return -1;
    if (vham_pack_str(b, "")) return -1;
    if (b->err) return -1;
    uint16_t L = (uint16_t)(b->off - body);
    b->buf[len_off    ] = (uint8_t)(L >> 8);
    b->buf[len_off + 1] = (uint8_t)(L);
    return 0;
}

int vham_build_oam_gmodify(uint32_t seq_no,
                           const char *sender_num,
                           const char *target_num,
                           const char *name,
                           uint8_t     prio,
                           uint32_t    dw_sn,
                           void *out, size_t out_cap) {
    if (!out || !sender_num || !target_num) return -1;
    (void)prio;     /* IE 0x30 carries group TYPE, not prio — for now ignore */
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_off, body, srv_off, srv_body;
    if (oam_open(&b, seq_no, &tap_off, &body, &srv_off, &srv_body)) return -1;
    /* Match OAM::GModify @ 0x30a8bc: IE 0x40 num + 0x41 name + 0x46 desc
     * + IE 0x30 group_type (we keep type=7 as a reasonable default). */
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL,  target_num)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_GROUP_NAME, name ? name : "")) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_GROUP_DESC, "")) return -1;
    if (vham_pack_tlv_u8 (&b, 1, IE_GROUP_TYPE, 7)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GMODIFY)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;
    return oam_close(&b, tap_off, body, srv_off, srv_body);
}

int vham_build_oam_gadd(uint32_t seq_no, const char *sender_num,
                        const char *group_num, const char *name,
                        const char *desc, uint8_t gtype,
                        uint32_t dw_sn,
                        void *out, size_t out_cap) {
    if (!out || !sender_num || !group_num) return -1;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_off, body, srv_off, srv_body;
    if (oam_open(&b, seq_no, &tap_off, &body, &srv_off, &srv_body)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL, group_num)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_GROUP_NAME, name ? name : "")) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_GROUP_DESC, desc ? desc : "")) return -1;
    if (vham_pack_tlv_u8 (&b, 1, IE_GROUP_TYPE, gtype)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GADD)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;
    return oam_close(&b, tap_off, body, srv_off, srv_body);
}

/* Pack a 1-entry UsrGInfo with the caller-specified attrs. */
static int pack_userginfo_full(vham_buf_t *b, const char *user_num,
                               const vham_gmodifyu_attrs_t *a) {
    if (vham_pack_u16(b, IE_USERGINFO)) return -1;
    size_t len_off = b->off;
    if (vham_pack_u16(b, 0)) return -1;
    size_t body = b->off;
    if (vham_pack_u16(b, 1)) return -1;                  /* count */
    if (vham_pack_u8(b, a->prio))    return -1;
    if (vham_pack_u8(b, a->type))    return -1;
    if (vham_pack_u8(b, a->ut_type)) return -1;
    if (vham_pack_u8(b, a->attr))    return -1;
    if (vham_pack_str(b, user_num))           return -1;
    if (vham_pack_str(b, a->name   ? a->name   : "")) return -1;
    if (vham_pack_str(b, a->ag_num ? a->ag_num : "")) return -1;
    if (vham_pack_u8(b, a->chan_num)) return -1;
    if (vham_pack_u8(b, a->status))   return -1;
    if (vham_pack_u8(b, 0))           return -1;          /* fg_count */
    if (vham_pack_str(b, ""))         return -1;          /* fg_num */
    if (b->err) return -1;
    uint16_t L = (uint16_t)(b->off - body);
    b->buf[len_off    ] = (uint8_t)(L >> 8);
    b->buf[len_off + 1] = (uint8_t)(L);
    return 0;
}

int vham_build_oam_gmodifyu(uint32_t seq_no,
                            const char *sender_num,
                            const char *target_num,
                            const char *user_num,
                            const vham_gmodifyu_attrs_t *attrs,
                            uint32_t    dw_sn,
                            void *out, size_t out_cap) {
    if (!out || !sender_num || !target_num || !user_num) return -1;
    vham_gmodifyu_attrs_t defaults = {
        .prio = 7, .type = 2, .ut_type = 2, .attr = 0,
        .chan_num = 0, .status = 1,
        .name = NULL, .ag_num = NULL,
    };
    if (!attrs) attrs = &defaults;
    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);
    size_t tap_off, body, srv_off, srv_body;
    if (oam_open(&b, seq_no, &tap_off, &body, &srv_off, &srv_body)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_NUM_GENERAL, target_num)) return -1;
    if (pack_userginfo_full(&b, user_num, attrs)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_OAM_OP_CODE,
                          (uint32_t)VHAM_OAM_OP_GMODIFYU)) return -1;
    if (vham_pack_tlv_u32(&b, 1, IE_DW_SN, dw_sn)) return -1;
    if (vham_pack_tlv_str(&b, 1, IE_SENDER_NUM, sender_num)) return -1;
    return oam_close(&b, tap_off, body, srv_off, srv_body);
}
