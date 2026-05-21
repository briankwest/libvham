/* libvham/include/vham/tokenstore.h — registration token persistence.
 *
 * The binary saves `{Reg, LastRegTime, Token, YaoYun}` to disk after
 * successful login and reuses the token to skip the digest handshake
 * on subsequent connections.
 *
 * We persist the same shape as a flat-key file (one `key=value` per
 * line) under `$XDG_CONFIG_HOME/vham/<user>.token` (or
 * `$HOME/.vham/<user>.token`). This is just enough to support
 * fast re-auth without depending on a JSON library.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_TOKENSTORE_H
#define VHAM_TOKENSTORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     user [64];
    char     token[128];      /* server-issued token from REGRSP */
    uint64_t last_reg_unix;
    char     yaoyun[64];      /* feature negotiation value */
} vham_token_t;

/* Save the token under the per-user file. Returns 0 on success. */
int vham_token_save(const vham_token_t *t);

/* Load by `user`. Returns 0 if found, -1 if absent. */
int vham_token_load(const char *user, vham_token_t *out);

/* Forget a stored token. */
int vham_token_clear(const char *user);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_TOKENSTORE_H */
