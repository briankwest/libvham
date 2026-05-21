/* libvham/src/account.c — silent-activation account derivation.
 *
 * Mirrors d1.e0.n() / d1.e0.o() in com.linkpoon.ham (see
 * extracted/jadx/sources/d1/e0.java lines 623-696).
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/account.h"
#include <string.h>

int vham_account_from_id(const char *id, char *out, size_t out_cap) {
    if (!id || !out || out_cap < 11) return -1;
    if (strlen(id) < 14) return -1;

    /* substring(4, 14) — 10 chars */
    memcpy(out, id + 4, 10);
    out[10] = '\0';

    /* Leading '0' → 'L' */
    if (out[0] == '0') {
        out[0] = 'L';
    }
    return 0;
}

const char *vham_region_prefix(const char *server_ip) {
    if (!server_ip) return NULL;
    /* IPs and known hostnames per LinkPoon's regional infrastructure. */
    if (strcmp(server_ip, "47.253.13.238") == 0 ||
        strcmp(server_ip, "us.vham.net")   == 0) return "V1";
    if (strcmp(server_ip, "8.213.196.104") == 0 ||
        strcmp(server_ip, "th.vham.net")   == 0) return "V2";
    if (strcmp(server_ip, "8.129.216.91")  == 0 ||
        strcmp(server_ip, "linkpoon.com")  == 0) return "V3";
    return NULL;
}

int vham_silent_account(const char *imei, const char *server_ip,
                        char *out, size_t out_cap) {
    if (!imei || !out) return -1;
    const char *prefix = vham_region_prefix(server_ip);
    size_t plen = prefix ? strlen(prefix) : 0;
    if (out_cap < plen + 11) return -1;

    if (plen) memcpy(out, prefix, plen);

    char tail[16];
    if (vham_account_from_id(imei, tail, sizeof tail) != 0) return -1;

    memcpy(out + plen, tail, 11);          /* 10 chars + NUL */
    return 0;
}
