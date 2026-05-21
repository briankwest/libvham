/* libvham/include/vham/regreq.h — MM_REGREQ builder.
 *
 * Layered on top of codec.h. Produces a full UDP datagram (TAP +
 * SRVMSG + IEs) ready to send to a registration server.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_REGREQ_H
#define VHAM_REGREQ_H

#include "vham/codec.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Caller-filled parameters. NULL/empty strings → IE omitted. */
typedef struct {
    /* TAP layer */
    uint32_t seq_no;                 /* sender's retransmit counter */

    /* SRVMSG layer */
    uint8_t  reg_type;               /* 1 = user, 2 = proxy */

    /* identity (IE 0x27 — UTNUM/account) */
    const char *username;

    /* self-num (IE 0x85) */
    const char *self_num;

    /* server endpoint (IE 0x24 — PIpAddr 8B) */
    uint32_t server_ipv4;            /* host order; e.g. 0xc0a80101 */
    uint16_t server_port;            /* host order */

    /* feature mask (IE 0x37). 0 = use observed default 0x98. */
    uint32_t feature_mask;

    /* auth fields — set after a REGRSP with IE 0x1e=0x53 is received.
     * If `response_hex` is non-NULL, the algorithm/nonce/realm IEs
     * are echoed back along with the response (IE 0x0b). */
    const char *auth_algorithm;      /* IE 0x07 */
    const char *auth_nonce;          /* IE 0x09 */
    const char *auth_realm;          /* IE 0x0a */
    const char *auth_response_hex;   /* IE 0x0b (32-char MD5 hex) */

    /* IE 0x62 echo — server-sent auth-mode/state flag. Set
     * `echo_auth_mode != 0` to include it. The binary client stores
     * this in this[0x21bb0] from the REGRSP and emits it on the
     * next REGREQ regardless of phase. */
    int        echo_auth_mode;       /* 1 = include IE 0x62 */
    uint32_t   auth_mode_value;      /* value to send */

    /* IE 0x70 echo — server-allocated dispatch number. */
    const char *auth_dispatch_num;   /* NULL or empty → skip IE 0x70 */
} vham_regreq_t;

/* Encode a REGREQ datagram. Returns bytes written, or -1 on error. */
int vham_build_regreq(const vham_regreq_t *p, void *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
