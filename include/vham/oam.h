/* libvham/include/vham/oam.h — OAM (operations / admin) frames.
 *
 * TAP class = 4, wMsgId = 0x70 (OAM_REQ). The operation is
 * discriminated by IE 0x1b (u32 OAM_OP_CODE).
 *
 * Operations identified from `OAM::*` symbols in libsvcapi:
 *
 *    op 1  UAdd      op 7  GModify     op 11 GModifyU
 *    op 2  UDel      op 9  GAddU       op 12 GQueryU
 *    op 3  UModify   op 10 GDelU       op 13 UQueryG
 *    op 4  UQuery    op 5  GAdd
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_OAM_H
#define VHAM_OAM_H

#include <stddef.h>
#include <stdint.h>
#include "vham/composites.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QueryExt — 16-byte payload of IE 0x91. Mirrors
 * `SrvPackQueryExt @ 0x269b1c`. */
typedef struct {
    uint8_t  uc_all;       /* "list everything" flag */
    uint8_t  uc_group;     /* filter by group */
    uint8_t  uc_user;      /* filter by user */
    uint8_t  uc_order;     /* ordering hint */
    uint32_t dw_page;
    uint32_t dw_count;
    uint32_t dw_total;
} vham_query_ext_t;

/* Build an `OAM_REQ` frame for GQueryU — "query a group's members".
 *
 *   seq_no      TAP sequence
 *   sender_num  our dispatch number (echoed back by server)
 *   target_num  the group number to query (e.g. our own user num for
 *               IDT_GQueryU(100L, our_num, ...) semantics)
 *   dw_sn       scope flag — 100 = own groups, 200 = related,
 *               900 = user group, 1200 = add-group, etc.
 *   q           query-ext params (NULL → all-zeros default)
 *
 * Returns bytes written, or -1 on error. */
int vham_build_oam_gqueryu(uint32_t seq_no,
                           const char *sender_num,
                           const char *target_num,
                           uint32_t    dw_sn,
                           const vham_query_ext_t *q,
                           void *out, size_t out_cap);

/* Build an `OAM_REQ` frame for GAddU — "add user (us) to a group".
 *
 *   seq_no      TAP sequence
 *   sender_num  our dispatch number (also the user being added)
 *   target_num  the group number to join
 *   dw_sn       scope/sequence flag
 *
 * The frame carries a 1-entry `_TLV_USERGINFO_s` payload describing
 * the user being added.
 *
 * Server-side policy normally requires admin credentials to do this
 * for arbitrary users on arbitrary groups. We try it because some
 * PoC servers permit self-add to "open" channels. */
int vham_build_oam_gaddu(uint32_t seq_no,
                         const char *sender_num,
                         const char *target_num,
                         uint32_t    dw_sn,
                         void *out, size_t out_cap);

/* Remove a user (us) from a group — op 10 GDelU. Same shape as GAddU. */
int vham_build_oam_gdelu(uint32_t seq_no,
                         const char *sender_num,
                         const char *target_num,
                         uint32_t    dw_sn,
                         void *out, size_t out_cap);

/* Modify a group entry — op 7 GModify. Carries the new group attrs.
 * `name`, `prio` describe the new attributes. */
int vham_build_oam_gmodify(uint32_t seq_no,
                           const char *sender_num,
                           const char *target_num,
                           const char *name,
                           uint8_t     prio,
                           uint32_t    dw_sn,
                           void *out, size_t out_cap);

/* Modify a user-in-group — op 11 GModifyU.
 *
 * **Server-side admin-gated.** Empirical testing on the live LinkPoon
 * server shows the wire format is byte-for-byte identical to GAddU
 * (op 9, which works for non-admin self-add), but the server returns
 * `parameter error (0x28)` for non-admin accounts on op-code 0x0b
 * regardless of payload contents. So this encoder is correct but
 * only succeeds when the sender has admin role.
 *
 * `attrs` controls the new user record. Pass NULL for sensible
 * defaults (prio=7 type=2 status=1). */
typedef struct {
    uint8_t prio;       /* 1..10 */
    uint8_t type;       /* 2=personal, 7=talk, 8=conf, ... */
    uint8_t ut_type;
    uint8_t attr;
    uint8_t chan_num;
    uint8_t status;     /* 1 = active */
    const char *name;
    const char *ag_num;
} vham_gmodifyu_attrs_t;

int vham_build_oam_gmodifyu(uint32_t seq_no,
                            const char *sender_num,
                            const char *target_num,
                            const char *user_num,
                            const vham_gmodifyu_attrs_t *attrs,
                            uint32_t    dw_sn,
                            void *out, size_t out_cap);

/* Create a new group — op 5 GAdd. Mirrors `OAM::GAdd @ 0x309910`.
 *
 *   group_num   the new group's number
 *   name        display name
 *   desc        description string
 *   gtype       group type — 0 = personal/list, 7 = talk-group,
 *               8 = conference, etc. (observed values)
 *
 * NOTE: most servers require admin creds for GAdd. */
int vham_build_oam_gadd(uint32_t seq_no,
                        const char *sender_num,
                        const char *group_num,
                        const char *name,
                        const char *desc,
                        uint8_t     gtype,
                        uint32_t    dw_sn,
                        void *out, size_t out_cap);

/* ---------- OAM_RSP parsing ----------
 *
 * The server replies to an OAM_REQ with TAP class=4, wMsgId=0x71.
 * Common IEs:
 *
 *   IE 0x02 — `status` (u16). Values observed on live test:
 *               0x002b = empty result / not authorized
 *               0       = success (presumed)
 *   IE 0x1b — `op_code` (u32) — echo of the request op (1 .. 13)
 *   IE 0x21 — `count` (u32)  — number of UsrGInfo entries returned
 *   IE 0x40 — target group number (echo)
 *   IE 0x43 — _TLV_USERGINFO_s payload (when count > 0)
 *   IE 0x44 — session_id (u32)
 *   IE 0x5d — sender's dispatch number (echo)
 */

typedef struct {
    int      have_status;
    uint16_t status;
    int      have_op;
    uint32_t op_code;
    int      have_count;
    uint32_t count;
    int      have_session_id;
    uint32_t session_id;
    char     echoed_num [64];
    char     target_num [32];

    /* If the response includes UsrGInfo (IE 0x43), it's parsed here. */
    int               have_ginfo;
    vham_user_ginfo_t ginfo;
} vham_oam_rsp_t;

/* Parse an OAM_RSP frame. Returns 0 on success, -1 if `buf` isn't a
 * well-formed OAM_RSP. */
int vham_parse_oam_rsp(const void *buf, size_t len, vham_oam_rsp_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_OAM_H */
