/* libvham — open-source, wire-compatible reimplementation of
 * libsvcapi.so's IDS-IDTMA protocol stack.
 *
 * This header is the public API for the TLV/SRVMSG/TAP codec.
 * All integers on the wire are big-endian unless explicitly named
 * `intel_*`.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_CODEC_H
#define VHAM_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Module ids (SRVMSG.ucDst/ucSrc) ---------- */
enum vham_module {
    VHAM_MOD_OAM = 2,
    VHAM_MOD_API = 3,  /* in-process only */
    VHAM_MOD_MM  = 4,
    VHAM_MOD_CC  = 5,
    VHAM_MOD_MA  = 6,
};

/* OAM operation codes — value of the inner OAM_OP u32 IE that
 * discriminates which operation an OAM_REQ frame is requesting. */
enum vham_oam_op {
    VHAM_OAM_OP_UADD      = 1,
    VHAM_OAM_OP_UDEL      = 2,
    VHAM_OAM_OP_UMODIFY   = 3,
    VHAM_OAM_OP_UQUERY    = 4,
    VHAM_OAM_OP_GADD      = 5,
    VHAM_OAM_OP_GMODIFY   = 7,
    VHAM_OAM_OP_GADDU     = 9,
    VHAM_OAM_OP_GDELU     = 10,
    VHAM_OAM_OP_GMODIFYU  = 11,
    VHAM_OAM_OP_GQUERYU   = 12,
    VHAM_OAM_OP_UQUERYG   = 13,
};

/* ---------- MM message ids ---------- */
enum vham_mm_msgid {
    VHAM_MM_REGREQ      = 0x0010,
    VHAM_MM_REGRSP      = 0x0011,
    VHAM_MM_PASSTHROUGH = 0x001b,
    VHAM_MM_STATUSSUBS  = 0x0090,
    VHAM_MM_ACCREQ       = 0x0012,
    VHAM_MM_ACCRSP       = 0x0013,
    VHAM_MM_ROUTEREQ     = 0x0014,
    VHAM_MM_ROUTERSP     = 0x0015,
    VHAM_MM_PROFREQ      = 0x0016,
    VHAM_MM_PROFRSP      = 0x0017,
    VHAM_MM_QUIT         = 0x0018,
    VHAM_MM_MODREQ       = 0x0019,
    VHAM_MM_MODRSP       = 0x001a,
    VHAM_MM_PROXYREGREQ  = 0x001c,
    VHAM_MM_PROXYREGRSP  = 0x001d,
    VHAM_MM_NAT_REQ      = 0x001e,
    VHAM_MM_NATT_PROB    = 0x001f,
    VHAM_MM_GPSREPORT    = 0x0092,
};

/* ---------- CC message ids ---------- */
enum vham_cc_msgid {
    /* CC wMsgIds — confirmed against CC::RecvTapMsgProc dispatch table
     * (Ghidra @ 0x2f6c78) and outgoing CCFsm::* senders. */
    VHAM_CC_HB        = 0x0002,  /* heartbeat */
    VHAM_CC_SETUP     = 0x0050,
    VHAM_CC_SETUPACK  = 0x0051,
    VHAM_CC_ALERT     = 0x0052,
    VHAM_CC_CONN      = 0x0053,  /* also outbound from CCFsm::UserAnswer */
    VHAM_CC_CONNACK   = 0x0054,
    VHAM_CC_INFO      = 0x0055,  /* carries MicCtrl (IE 0x54) + DTMF */
    VHAM_CC_INFOACK   = 0x0056,
    VHAM_CC_MODIFY    = 0x0057,
    VHAM_CC_MODIFYACK = 0x0058,
    VHAM_CC_REL       = 0x0059,  /* CCFsm::Rel — initial release request */
    VHAM_CC_RLC       = 0x005a,  /* CC_RLC — release complete (per GetSrvMsgStr) */
    VHAM_CC_USERCTRL  = 0x005b,  /* CC::UserCtrl */
    VHAM_CC_STREAMCTRL= 0x005c,  /* CCFsm::UserStreamCtrl */
    VHAM_CC_CONFSTATUSREQ = 0x005d,
    VHAM_CC_CONFSTATUSRSP = 0x005e,

    /* OAM wMsgIds (TAP class = 4). All OAM_REQ frames share cmd 0x70;
     * the operation is discriminated by the inner OAM_OP u32 IE. */
    VHAM_OAM_REQ      = 0x0070,
    VHAM_OAM_RSP      = 0x0071,
    VHAM_OAM_NOTIFY   = 0x0072,
    VHAM_OAM_CTRL     = 0x0073,
    VHAM_OAM_SETID    = 0x0074,
};

/* ---------- TAP class values ---------- */
enum vham_tap_class {
    VHAM_TAP_CLASS_MM = 1,
    VHAM_TAP_CLASS_CC = 3,
};

/* ---------- IE tags (selected; see protocol-spec/05-ie-inventory.md) ---------- */
enum vham_ie_tag {
    VHAM_IE_AUTH_ALGORITHM = 0x0007, /* str */
    VHAM_IE_AUTH_NONCE     = 0x0009, /* str */
    VHAM_IE_AUTH_REALM     = 0x000a, /* str */
    VHAM_IE_AUTH_RESPONSE  = 0x000b, /* str (32-char hex) */
    VHAM_IE_REG_TYPE       = 0x001d, /* u8  */
    VHAM_IE_SUB_OPCODE     = 0x001e, /* u16 (0x53 = auth challenge) */
    VHAM_IE_SERVER_ADDR    = 0x0024, /* PIpAddr 8B */
    VHAM_IE_IDENTITY_NUM   = 0x0027, /* TLV_NUMBER */
    VHAM_IE_FEATURE_MASK   = 0x0037, /* u32 */
    VHAM_IE_CAUSE_NUM      = 0x0040, /* TLV_NUMBER */
    VHAM_IE_AUTH_MODE      = 0x0062, /* u32 — server-provided auth-mode flag */
    VHAM_IE_DISPATCH_NUM   = 0x0070, /* TLV_NUMBER — server-allocated dispatch num */
    VHAM_IE_SELF_NUM       = 0x0085, /* TLV_NUMBER */
    /* MM/CC misc */
    VHAM_IE_COUNTER        = 0x0021, /* u32 — generic seq/counter (e.g. STATUSSUBS) */
    VHAM_IE_STATUS_SUBS    = 0x004b, /* nested _TLV_STATUSSUBS_s */
    VHAM_IE_USERGINFO_A    = 0x002d, /* nested _TLV_USERGINFO_s — variant 1 */
    VHAM_IE_USERGINFO_B    = 0x0043, /* nested _TLV_USERGINFO_s — variant 2 */
    /* Session fields seen in success REGRSP */
    VHAM_IE_SESSION_ID     = 0x0044, /* u32 */
    VHAM_IE_FTP_SRV        = 0x0059, /* nested _TLV_FTPSERVERINFO_s */
    VHAM_IE_MEDIA_GW       = 0x005a, /* 6-byte PIpAddr (LE ip + LE port) */
    VHAM_IE_ORG_LIST       = 0x005c, /* nested _TLV_ORGLIST_s */
    VHAM_IE_ALT_ENDPOINT   = 0x0084, /* 6-byte PIpAddr */
    VHAM_IE_SYS_TIME       = 0x008c, /* 16-byte P_TIME (8x BE u16) */

    /* Call-control IEs (CC_SETUP and friends) */
    /* The binary's CCFsm::UserMakeOut copies the CALLER's number into
     * IE 0x0d (offset 0x1d8) and the CALLEE/peer into IE 0x0e (offset
     * 0x21c) — the opposite of common SIP convention. Confirmed via
     * static analysis vs SrvPackMsg's `SrvPackNum(_, 0xd, ...)` and
     * `SrvPackNum(_, 0xe, ...)` calls. */
    VHAM_IE_CC_CALLING_NUM = 0x000d, /* TLV_NUMBER — caller (us) */
    VHAM_IE_CC_CALLED_NUM  = 0x000e, /* TLV_NUMBER — peer / channel */
    VHAM_IE_CC_SDP_A       = 0x0019, /* nested _TLV_SDP_s (offer) */
    VHAM_IE_CC_SERVICE     = 0x0023, /* u32 — call service type */
    VHAM_IE_CC_SUBCODE     = 0x0045, /* TLV_NUMBER — channel sub-code (CTCSS-like "Password" on vham.net) */
    VHAM_IE_CC_CALL_EXTNUM = 0x0047, /* TLV_NUMBER — extended called (when '*' present) */
    VHAM_IE_CC_CALLUSERCTRL= 0x0054, /* _TLV_CALLUSERCTRL_s — PTT mic grant payload */
    /* IE 0x15 carries CC_INFO action (CCFsm::MicCtrl @ 0x2f19f8, decoded
     * by CCFsm::RecvInfoProc @ 0x2f3bc4): u32 action + optional str.
     * action: 1=MicReq, 2=MicRel, 5=TalkingID, 0xf=SDP-modify, 0x14=Info. */
    VHAM_IE_INFO           = 0x0015,
    VHAM_IE_CC_MIC_ACTION  = 0x0063, /* u32 — legacy slot; binary uses IE 0x15 */
    VHAM_IE_CC_MIC_IMTYPE  = 0x0064, /* str — legacy slot; binary uses IE 0x15 */
    VHAM_IE_CC_CALLSTREAMCTRL = 0x0055, /* _TLV_CALLSTREAMCTRL_s */
    VHAM_IE_CC_CALLCONF    = 0x0053, /* CallConf: 11×u8 + NUL-string */
    VHAM_IE_CC_CAMINFO     = 0x002e, /* SrvPackCamInfo — 17-byte composite */
    VHAM_IE_CC_GROUPFLAG   = 0x0030, /* u8 — set to 1 for channel/group calls */
    VHAM_IE_CC_BANDWIDTH   = 0x0036, /* u32 — channel/call bandwidth (binary uses 64) */
    VHAM_IE_CC_CHAN_NAME   = 0x0046, /* str — channel display name (= channel ID) */
    VHAM_IE_CC_CHAN_NUM2   = 0x0047, /* TLV_NUMBER — channel as Num */
    VHAM_IE_CC_DISPLAY     = 0x0076, /* str — display name / route info */
    VHAM_IE_CC_CHAN_FLAG   = 0x007a, /* u8 — flag (radio sends 2 for channel TX) */
    VHAM_IE_CC_PRIV_NUM    = 0x007e, /* TLV_NUMBER — private/sub number */
};

/* Call service-type values (CCFsm::UserMakeOut param_5) */
enum vham_call_service {
    VHAM_CALL_FULL_DUPLEX = 0x12,
    VHAM_CALL_HALF_DUPLEX = 0x11,
    VHAM_CALL_VIDEO       = 0x18,
    VHAM_CALL_CONF        = 0x15,
};

enum vham_reg_type {
    VHAM_REGTYPE_USER  = 1,
    VHAM_REGTYPE_PROXY = 2,
};

/* ---------- Encoder buffer ---------- */
typedef struct {
    uint8_t *buf;       /* caller-supplied scratch */
    size_t   cap;       /* total bytes available */
    size_t   off;       /* current write offset; updated in place */
    int      err;       /* sticky: 0 on success, -1 once overflow seen */
} vham_buf_t;

static inline void vham_buf_init(vham_buf_t *b, void *p, size_t cap) {
    b->buf = (uint8_t *)p;
    b->cap = cap;
    b->off = 0;
    b->err = 0;
}

/* ---------- Atomic encoders (matches libsvcapi PPack* exactly) ---------- */
int vham_pack_u8 (vham_buf_t *b, uint8_t  v);
int vham_pack_u16(vham_buf_t *b, uint16_t v);  /* big-endian */
int vham_pack_u24(vham_buf_t *b, uint32_t v);  /* big-endian (low 24 bits) */
int vham_pack_u32(vham_buf_t *b, uint32_t v);  /* big-endian */
int vham_pack_intel_u16(vham_buf_t *b, uint16_t v); /* little-endian */
int vham_pack_intel_u32(vham_buf_t *b, uint32_t v); /* little-endian */
int vham_pack_str    (vham_buf_t *b, const char *s);    /* NUL-terminated */
int vham_pack_str_no0(vham_buf_t *b, const void *p, size_t n);
int vham_pack_fix    (vham_buf_t *b, const void *p, size_t n);

/* ---------- TLV emitters (presence flag suppresses emit) ---------- */
int vham_pack_tlv_u8 (vham_buf_t *b, int present, uint16_t tag, uint8_t  v);
int vham_pack_tlv_u16(vham_buf_t *b, int present, uint16_t tag, uint16_t v);
int vham_pack_tlv_u32(vham_buf_t *b, int present, uint16_t tag, uint32_t v);
int vham_pack_tlv_str(vham_buf_t *b, int present, uint16_t tag, const char *s);
int vham_pack_tlv_fix(vham_buf_t *b, int present, uint16_t tag,
                      const void *p, size_t n);

/* ---------- Frame headers ---------- */
typedef struct {
    uint8_t  ver_hi;    /* always 0x01 */
    uint8_t  ver_lo;    /* always 0x00 */
    uint16_t flags;     /* 0x0000 normal CMD/RSP, 0x0001 = TAP ACK */
    uint32_t seq_no;    /* set by the TAP transmit layer */
    uint16_t class_id;
    uint16_t cmd;       /* == SRVMSG.wMsgId (or original cmd for ACKs) */
    uint32_t body_len;  /* 0 for ACKs */
} vham_tap_hdr_t;

enum {
    VHAM_TAP_FLAG_NORMAL = 0x0000,
    VHAM_TAP_FLAG_ACK    = 0x0001,
};

typedef struct {
    uint8_t  ucDst;
    uint8_t  ucSrc;
    uint16_t wMsgId;
    uint32_t dwDstFsmId;
    uint32_t dwSrcFsmId;
    uint32_t dwMsgLen;  /* IE list length; computed automatically */
} vham_srvmsg_hdr_t;

/* Write a 16-byte TAP header at b->off. body_len is the length that
 * follows on the wire (SRVMSG header + IEs). */
int vham_pack_tap_header(vham_buf_t *b, const vham_tap_hdr_t *h);

/* Build a 16-byte TAP-level ACK acknowledging a received frame.
 *
 *   wire layout: ver=01 00 | flags=0x0001 | seq | class | cmd | len=0
 *
 * `seq`, `class_id`, `cmd` echo the values of the frame being ACKed.
 * Returns 16 on success, -1 if the buffer is too small. */
int vham_build_tap_ack(uint32_t seq, uint16_t class_id, uint16_t cmd,
                       void *out, size_t out_cap);

/* Build a 3-byte NAT keepalive ping. Sent periodically (every
 * NATTIME=30000ms in the official client) to maintain the server-side
 * NAT mapping for our UDP socket. Without this, the server cannot
 * deliver incoming CMD packets after the NAT idle timeout.
 *
 * Wire: 0xff 0xd3 0xf1
 *
 * Reverse-engineered from TAP::SendShortNat2Mc @ 0x310b1c. Returns 3
 * on success, -1 if buffer too small. */
int vham_build_nat_ping(void *out, size_t out_cap);

/* Build the 8-byte NAT setup packet from MM::TmNat @ 0x2fca38.
 * Wire: 0xff 0xd3 0x01 0x00 0x00 0x00 0x00 0x00. Sent at session
 * start and when establishing initial NAT mapping. Returns 8. */
int vham_build_nat_setup(void *out, size_t out_cap);

/* Detect whether a received datagram is one of the NAT-plane messages
 * (magic 0xff 0xd3 ...). Returns 1 if NAT, 0 otherwise. */
int vham_is_nat_packet(const void *buf, size_t len);

/* Write the SRVMSG header. Caller must call vham_patch_srvmsg_len()
 * after the IEs are emitted so dwMsgLen reflects the body length.
 * Returns the offset at which dwMsgLen lives (for the patch step). */
int vham_pack_srvmsg_header(vham_buf_t *b, const vham_srvmsg_hdr_t *h,
                            size_t *out_len_offset);
int vham_patch_srvmsg_len(vham_buf_t *b, size_t len_offset,
                          size_t body_start);

/* ---------- Decoder primitives ---------- */
/* Big-endian unpack helpers mirroring PUnpkU{8,16,24,32}. */
static inline uint8_t  vham_unpack_u8 (const uint8_t *p) { return p[0]; }
static inline uint16_t vham_unpack_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t vham_unpack_u24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}
static inline uint32_t vham_unpack_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/* TLV iterator. Tag and len fields are decoded big-endian; the value
 * pointer is a zero-copy view into the caller-supplied buffer.
 *
 * Lifetime: vham_ie_t.value is valid only as long as the source
 *           buffer passed to vham_parse_packet (or assigned to
 *           vham_reader_t directly) is live. */
typedef struct {
    const uint8_t *buf;
    size_t         cap;
    size_t         off;
} vham_reader_t;

typedef struct {
    uint16_t       tag;
    uint16_t       len;
    const uint8_t *value;     /* points into reader.buf */
} vham_ie_t;

/* Returns:
 *    1  → ie filled with the next IE; reader advanced past it.
 *    0  → end of buffer reached (no more IEs).
 *   -1  → malformed (truncated TLV header or value).
 */
int vham_next_ie(vham_reader_t *r, vham_ie_t *ie);

/* Typed accessors. Each returns 0 on success, -1 on length mismatch. */
int vham_ie_get_u8 (const vham_ie_t *ie, uint8_t  *out);
int vham_ie_get_u16(const vham_ie_t *ie, uint16_t *out);
int vham_ie_get_u32(const vham_ie_t *ie, uint32_t *out);

/* Zero-copy string accessor: returns the IE's NUL-terminated UTF-8
 * pointer, NULL if the value is not NUL-terminated or empty. */
const char *vham_ie_get_str(const vham_ie_t *ie);

/* Parse a full datagram (TAP + SRVMSG headers + IE list). Any of
 * the out-parameters may be NULL if the caller doesn't need that
 * field. Returns 0 on success, -1 on malformed input.
 *
 * On success `iter_out` is positioned at the first IE; the caller
 * walks it with vham_next_ie(). */
int vham_parse_packet(const void *buf, size_t len,
                      vham_tap_hdr_t   *tap_out,
                      vham_srvmsg_hdr_t *srvmsg_out,
                      vham_reader_t    *iter_out);

/* Decode a PIpAddr (IE 0x24-style 8-byte payload) into host order.
 * Returns 0 on success, -1 if the IE has the wrong length. */
typedef struct {
    uint32_t ipv4;       /* host order */
    uint16_t port;       /* host order */
    uint8_t  family;     /* normally 0x02 (AF_INET) */
    uint8_t  pad;
} vham_ipaddr_t;
int vham_ie_get_ipaddr(const vham_ie_t *ie, vham_ipaddr_t *out);

/* 6-byte PIpAddr variant seen in IE 0x5a / 0x84 — LE ip + LE port, no
 * family/pad bytes. */
int vham_ie_get_ipaddr6(const vham_ie_t *ie, vham_ipaddr_t *out);

/* ---------- Authentication ---------- */
/* RFC 2617 HTTP Digest, as implemented by IDS_AuthMD5_Calc.
 *
 * Pass NULL for cnonce/nc/qop to select the non-qop branch
 * (which is what this build of MM::RecvTapMsgProc does).
 *
 * response_out must point to at least 33 bytes; on success it is
 * a NUL-terminated 32-char lower-case hex digest. */
int vham_auth_md5(const char *username,
                  const char *realm,
                  const char *password,
                  const char *method,        /* "REGISTER" */
                  const char *algorithm,     /* "MD5" or "md5-sess" */
                  const char *nonce,
                  const char *cnonce,        /* NULL ok */
                  const char *nc,            /* NULL ok */
                  const char *uri,           /* "0.0.0.0" */
                  const char *qop,           /* NULL ok */
                  char       *response_out);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_CODEC_H */
