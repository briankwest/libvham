/* libvham/include/vham/composites.h — Structured parsers for the
 * composite IEs in SRVMSG bodies (OrgList, UsrGInfo, FtpServerInfo,
 * ...). Each one matches an `SrvUnpk*` function in libsvcapi.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_COMPOSITES_H
#define VHAM_COMPOSITES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- IE 0x5c — `_TLV_ORGLIST_s` (Tap variant) ----------
 *
 * One org entry, as decoded by `SrvUnpkOrgListTap @ 0x26d19c`.
 * On the wire after the 4-byte IE header:
 *
 *   u16              count
 *   for each entry:
 *     str            Num         (companyId, e.g. "20220609122881752")
 *     str            Name        (e.g. "HAM")
 *     str            Desc        (often empty)
 *     u32 BE         UserNum     (total users registered to org)
 *     u32 BE         DsNum       (number of dispatch slots)
 *     str            DS0Num      (default dispatch slot number)
 *     str            DS0Pwd      (default dispatch slot password)
 *     str            DSName      (dispatch system name — i18n)
 *     str            DsIcon      (dispatch icon URL — often empty)
 *     str            AppName     (app brand name — i18n)
 *     str            AppIcon     (app icon URL path)
 *
 * Note the Tap variant omits the segment ranges (USegStart, GSegStart,
 * ...) that appear in IE 0x61 (the full / Ws variant). Those segment
 * ranges are what would let us know which channel numbers are valid
 * for the org; the server only sends them over the WebSocket
 * protocol, not over TAP.
 */

#define VHAM_ORG_NAME_MAX    64
#define VHAM_ORG_NUM_MAX     32
#define VHAM_ORG_DESC_MAX   128
#define VHAM_ORG_ICON_MAX   128
#define VHAM_ORG_ENTRIES_MAX 4

typedef struct {
    char     num    [VHAM_ORG_NUM_MAX];
    char     name   [VHAM_ORG_NAME_MAX];
    char     desc   [VHAM_ORG_DESC_MAX];
    uint32_t user_num;
    uint32_t ds_num;
    char     ds0_num [VHAM_ORG_NUM_MAX];
    char     ds0_pwd [VHAM_ORG_NUM_MAX];
    char     ds_name [VHAM_ORG_NAME_MAX];
    char     ds_icon [VHAM_ORG_ICON_MAX];
    char     app_name[VHAM_ORG_NAME_MAX];
    char     app_icon[VHAM_ORG_ICON_MAX];
} vham_org_entry_t;

typedef struct {
    uint16_t          count;            /* observed entries (<= entries_cap) */
    vham_org_entry_t  entries[VHAM_ORG_ENTRIES_MAX];
} vham_orglist_t;

/* Parse the IE 0x5c body into `out`. `buf`/`len` must be the IE's
 * VALUE bytes only — without the 4-byte IE header. Returns 0 on
 * success, -1 on truncation or count overflow. */
int vham_parse_orglist(const void *buf, size_t len, vham_orglist_t *out);

/* ---------- IE 0x43 / 0x2d — `_TLV_USERGINFO_s` (Tap variant) ----
 *
 * One group-membership entry, decoded per `SrvUnpkUsrGInfoTap @
 * 0x26b578`. Carries the list of groups this user belongs to.
 *
 * Wire format (after the IE 0x43/0x2d header):
 *
 *   u16            count
 *   for each entry:
 *     u8           prio
 *     u8           type
 *     u8           ut_type      (user-terminal type)
 *     u8           attr         (attribute bitmask)
 *     str          num          (group number, max 32)
 *     str          name         (group name, max 64)
 *     str          ag_num       (associated group number, max 64)
 *     u8           chan_num
 *     u8           status
 *     u8           fg_count     (number of feature groups, max 0x80)
 *     str          fg_num       (comma-sep feature-group nums, max 1024)
 *
 * Field names follow the 11-field JSON schema observed in the binary.
 */

#define VHAM_GMEM_NUM_MAX     32
#define VHAM_GMEM_NAME_MAX    64
#define VHAM_GMEM_AGNUM_MAX   64
#define VHAM_GMEM_FGNUM_MAX   1024
#define VHAM_GMEM_ENTRIES_MAX 16

typedef struct {
    uint8_t prio;
    uint8_t type;
    uint8_t ut_type;
    uint8_t attr;
    char    num     [VHAM_GMEM_NUM_MAX];
    char    name    [VHAM_GMEM_NAME_MAX];
    char    ag_num  [VHAM_GMEM_AGNUM_MAX];
    uint8_t chan_num;
    uint8_t status;
    uint8_t fg_count;
    char    fg_num  [VHAM_GMEM_FGNUM_MAX];
} vham_ginfo_member_t;

typedef struct {
    uint16_t            count;
    vham_ginfo_member_t entries[VHAM_GMEM_ENTRIES_MAX];
} vham_user_ginfo_t;

/* Parse IE 0x43 or 0x2d body (the Tap variant). Returns 0 on success,
 * -1 on overflow or truncation. */
int vham_parse_user_ginfo(const void *buf, size_t len,
                          vham_user_ginfo_t *out);

/* ---------- IE 0x59 — `_TLV_FTPSERVERINFO_s` ----------
 *
 * FTP credentials the server hands to the client at registration.
 * Used for uploading IM file attachments and similar. Decoded per
 * `SrvUnpkFtpServerInfo @ 0x26cca0`.
 *
 * Wire format (after the IE header):
 *
 *   u32 BE    server_ipv4         (big-endian — unlike IE 0x5a)
 *   u16 BE    port
 *   str       username  (max 32)
 *   str       password  (max 32)
 */

typedef struct {
    uint32_t ipv4;                 /* host order */
    uint16_t port;
    char     username[32];
    char     password[32];
} vham_ftpinfo_t;

int vham_parse_ftpinfo(const void *buf, size_t len, vham_ftpinfo_t *out);

/* ---------- IE 0x54 — `_TLV_CALLUSERCTRL_s` ----------
 *
 * The PTT mic-grant carrier IE. Lives inside a CC_INFO frame and
 * carries: who is requesting/releasing, which call leg, and the
 * action (request vs release).
 *
 * Wire format (after the IE header):
 *
 *   str       num_a       (max 32) — typically the requesting user
 *   str       num_b       (max 32) — typically the call peer
 *   u8        action      1=request, 2=release
 *   u8[4]     extra       (timestamp or reserved)
 *
 * From `SrvPackCallUserCtrl @ 0x267a90` and `SrvUnpkCallUserCtrl
 * @ 0x26c7e8`. */

enum vham_userctrl_action {
    VHAM_USERCTRL_REQUEST = 1,
    VHAM_USERCTRL_RELEASE = 2,
};

typedef struct {
    char    num_a[32];
    char    num_b[32];
    uint8_t action;
    uint8_t extra[4];
} vham_call_userctrl_t;

/* Encode the IE body (just the inner bytes — caller wraps with IE
 * header tag=0x54). Returns bytes written, -1 on overflow. */
int vham_encode_call_userctrl(const vham_call_userctrl_t *uc,
                              void *out, size_t out_cap);

/* Decode the IE body. */
int vham_decode_call_userctrl(const void *in, size_t len,
                              vham_call_userctrl_t *out);

/* ---------- IE 0x33 — `_TLV_WATCHLEG_s` ----------
 *
 * Tells the dispatcher which call leg the user is monitoring (5 bytes
 * on the wire). `SrvUnpkWatchLeg @ 0x26c994`. */
typedef struct {
    uint32_t leg_id;
    uint8_t  flag;
} vham_watchleg_t;

int vham_parse_watchleg(const void *buf, size_t len, vham_watchleg_t *out);

/* ---------- IE 0x75 — `_TLV_LEGEXT_s` ----------
 *
 * Extended call-leg attributes. 22-byte minimum body. `SrvUnpkLegExt
 * @ 0x26e018`. Two u64s in the middle are opaque counters/timestamps
 * we don't yet have field names for. */
typedef struct {
    uint8_t  a, b;
    uint64_t ts_a;
    uint64_t ts_b;
    uint32_t value;
} vham_legext_t;

int vham_parse_legext(const void *buf, size_t len, vham_legext_t *out);

/* ---------- IE 0x4e — `_TLV_GPSRECPACK_s` ----------
 *
 * Server-pushed GPS history for a subject. `SrvUnpkGpsRec @ 0x26c070`.
 * Multiple records inside one packet (count ≤ 24). */
#define VHAM_GPSREC_MAX 24

typedef struct {
    uint32_t lat_e6;     /* latitude * 1e6 */
    uint32_t lon_e6;
    uint32_t speed;
    uint32_t heading;
    uint16_t altitude;
    uint8_t  flags[5];
} vham_gpsrec_entry_t;

typedef struct {
    char     subject[32];
    uint8_t  type;
    uint8_t  count;
    vham_gpsrec_entry_t entries[VHAM_GPSREC_MAX];
} vham_gpsrec_t;

int vham_parse_gpsrec(const void *buf, size_t len, vham_gpsrec_t *out);

/* ---------- IE 0x2e — `_TLV_CAMINFO_s` ----------
 *
 * Camera/stream descriptor used by video and watch flows.
 * `SrvUnpkCamInfo @ 0x26bd1c`. */
typedef struct {
    uint8_t  type;
    char     name [32];
    char     desc [64];
    uint16_t port;
    char     url_a[64];
    char     url_b[64];
    uint8_t  status_a;
    uint8_t  status_b;
    char     extra[32];
} vham_caminfo_t;

int vham_parse_caminfo(const void *buf, size_t len, vham_caminfo_t *out);

/* ---------- IE 0x15 — `_TLV_INFO_s` ----------
 *
 * Generic info carrier: u32 code + optional string (≤1024 bytes).
 * `SrvUnpkInfo @ 0x26cbec`. When the IE length is 4 the string is
 * absent. */
typedef struct {
    uint32_t code;
    int      have_text;
    char     text[1024];
} vham_info_t;

int vham_parse_info(const void *buf, size_t len, vham_info_t *out);

/* ---------- IE 0x03 — `_TLV_PLAYINFO_s` ----------
 *
 * Four u32 fields. `SrvUnpkPlayInfo @ 0x26dd40`. Field meanings
 * inferred from context: typically (id, type, action, param). */
typedef struct {
    uint32_t a, b, c, d;
} vham_playinfo_t;

int vham_parse_playinfo(const void *buf, size_t len, vham_playinfo_t *out);

/* ---------- IE 0x72 / 0x8a — `_TLV_RESREPORT_s` ----------
 *
 * Two u32 fields. `SrvUnpkResReport @ 0x26df68`. Used in resource
 * reports. */
typedef struct {
    uint32_t a, b;
} vham_resreport_t;

int vham_parse_resreport(const void *buf, size_t len, vham_resreport_t *out);

/* ---------- IE 0x71 — `_TLV_GMEMBER_EXTINFO_s` ----------
 *
 * Group-member extended info: u16 count + list of (string-32, string-512)
 * pairs. `SrvUnpkGMemberExtInfo @ 0x26d4f0`. */
#define VHAM_GMEMBER_EXT_MAX  8
typedef struct {
    char num [32];     /* member dispatch number */
    char info[512];    /* free-form ext info */
} vham_gmember_ext_entry_t;

typedef struct {
    uint16_t count;
    vham_gmember_ext_entry_t entries[VHAM_GMEMBER_EXT_MAX];
} vham_gmember_extinfo_t;

int vham_parse_gmember_extinfo(const void *buf, size_t len,
                               vham_gmember_extinfo_t *out);

/* ---------- IE 0x50 — `_TLV_CALLEXT_s` ----------
 *
 * Call extension flags + two strings. `SrvUnpkCallExt @ 0x26c5a0`. */
typedef struct {
    uint8_t a, b;
    char    str_a[32];
    char    str_b[64];
} vham_callext_t;

int vham_parse_callext(const void *buf, size_t len, vham_callext_t *out);

/* ---------- IE 0x55 — `_TLV_CALLSTREAMCTRL_s` ----------
 *
 * String (the call's stream ID) + two flag bytes.
 * `SrvUnpkCallStreamCtrl @ 0x26c8d4`. */
typedef struct {
    char    stream_id[32];
    uint8_t flag_a, flag_b;
} vham_call_streamctrl_t;

int vham_parse_call_streamctrl(const void *buf, size_t len,
                               vham_call_streamctrl_t *out);

/* ---------- IE 0x4f / 0x79 — `_TLV_COMM_QUERY_s` ----------
 *
 * Generic "query something" form. `SrvUnpkCommQueryExt @ 0x26c4a4`.
 *
 *   u8         type
 *   u32        param1
 *   u32        param2
 *   str(32)    key
 *   str(32)    val
 */
typedef struct {
    uint8_t  type;
    uint32_t param1, param2;
    char     key[32];
    char     val[32];
} vham_commquery_t;

int vham_parse_commquery(const void *buf, size_t len,
                         vham_commquery_t *out);

/* ---------- IE 0x73 — `_TLV_FSMPAIR_s` ----------
 *
 * u32 count + N×(u32, u32) pairs (max 0x100 pairs).
 * `SrvUnpkFsmPair @ 0x26d61c`. */
#define VHAM_FSMPAIR_MAX 16
typedef struct {
    uint32_t a, b;
} vham_fsmpair_t;

typedef struct {
    uint32_t       count;
    vham_fsmpair_t pairs[VHAM_FSMPAIR_MAX];
} vham_fsmpair_list_t;

int vham_parse_fsmpair(const void *buf, size_t len,
                       vham_fsmpair_list_t *out);

/* ---------- IE 0x81 — `_TLV_NS_QUERYEXT_s` ----------
 *
 * NS-layer query extension. Same shape as CommQuery with two extra
 * strings tacked on. `SrvUnpkNsQueryExt @ 0x26db1c`. */
typedef struct {
    uint8_t  type;
    uint32_t param1, param2;
    char     s0[32], s1[32], s2[32], s3[32];
} vham_nsqueryext_t;

int vham_parse_nsqueryext(const void *buf, size_t len,
                          vham_nsqueryext_t *out);

/* ---------- IE 0x06 — `_TLV_VERINFO_s` ----------
 *
 * App version: two bytes (major/minor or version/build).
 * `SrvUnpkApVer @ 0x26defc`. */
typedef struct {
    uint8_t major;
    uint8_t minor;
} vham_verinfo_t;

int vham_parse_verinfo(const void *buf, size_t len, vham_verinfo_t *out);

/* ---------- IE 0x05 / 0x29 / 0x92 — `_TLV_USRPOS_s` ----------
 *
 * User position record. `SrvUnpkApPos @ 0x26de20`.
 *
 *   u8      type
 *   u32 BE  lat (e6)
 *   u32 BE  lon (e6)
 *   u16     altitude
 */
typedef struct {
    uint8_t  type;
    uint32_t lat_e6;
    uint32_t lon_e6;
    uint16_t altitude;
} vham_usrpos_t;

int vham_parse_usrpos(const void *buf, size_t len, vham_usrpos_t *out);

/* ---------- IE 0x78 — `_TLV_ROUTECFG_s` ----------
 *
 * Route configuration: u16 count + N entries, each ~11 strings of
 * 32 bytes each (route name, source, destination, gateways, etc.).
 * `SrvUnpkRouteCfg @ 0x26d71c`. Limited to a few entries to keep
 * memory bounded. */
#define VHAM_ROUTECFG_MAX  4
typedef struct {
    char fields[11][32];
} vham_routecfg_entry_t;

typedef struct {
    uint16_t              count;
    vham_routecfg_entry_t entries[VHAM_ROUTECFG_MAX];
} vham_routecfg_t;

int vham_parse_routecfg(const void *buf, size_t len, vham_routecfg_t *out);

/* ---------- IE 0x4d — `_TLV_GMEMBERSTATUS_s` ----------
 *
 * Per-group member status: u16 count + per-entry (number, status u8,
 * presence u32, name, ag_num). Schema based on `SrvUnpkGMemStatus
 * @ 0x26ca80`. Bound to small N to keep parser simple. */
#define VHAM_GMEM_STATUS_MAX 16
typedef struct {
    char     num [32];
    uint8_t  type;
    uint32_t flags;
    char     name   [32];
    char     ag_num [64];
} vham_gmem_status_entry_t;

typedef struct {
    uint16_t                 count;
    vham_gmem_status_entry_t entries[VHAM_GMEM_STATUS_MAX];
} vham_gmem_status_t;

int vham_parse_gmem_status(const void *buf, size_t len,
                           vham_gmem_status_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_COMPOSITES_H */
