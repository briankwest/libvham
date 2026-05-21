/* libvham/include/vham/account.h — silent-activation account derivation.
 *
 * Mirrors d1.e0.n() and d1.e0.o() in com.linkpoon.ham, which together
 * turn an IMEI into the account string the silent path logs in with.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_ACCOUNT_H
#define VHAM_ACCOUNT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Take a digit string (typically an IMEI of 14-15 chars). Returns the
 * 10-char substring [chars 5..14], with a leading '0' rewritten to
 * 'L'. Writes a NUL-terminated string into out (must be >= 12 bytes).
 *
 * Returns:
 *    0 on success,
 *   -1 if the input is shorter than 14 chars or out_cap < 11.
 *
 * Mirrors d1.e0.n(java.lang.String).
 */
int vham_account_from_id(const char *id, char *out, size_t out_cap);

/* Returns the server-region prefix to prepend when deriving the
 * silent-activation account. NULL → no prefix.
 *
 * Mirrors d1.e0.o(java.lang.String).
 */
const char *vham_region_prefix(const char *server_ip);

/* Compose: vham_region_prefix(server_ip) + vham_account_from_id(imei).
 *
 * Writes the result into out (>= 16 bytes recommended). Returns 0 on
 * success, -1 on bounds/input failure. */
int vham_silent_account(const char *imei, const char *server_ip,
                        char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
