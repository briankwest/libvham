/* libvham/include/vham/envcfg.h — environment-based configuration.
 *
 * Tools should never hardcode credentials. They look up values via
 * `vham_env()`, which checks (in order):
 *
 *   1. an actual environment variable (e.g. `VHAM_USER`),
 *   2. a `KEY=value` line in `./.env` (current working directory),
 *   3. a `KEY=value` line in `$HOME/.vham/env`,
 *   4. the caller-supplied `default_value` (NULL → returns NULL).
 *
 * The on-disk files are parsed once on first call. Comments (`#`)
 * and blank lines are ignored. Values may be optionally quoted with
 * single or double quotes.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_ENVCFG_H
#define VHAM_ENVCFG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Look up a configuration value. Returns a pointer to a static
 * string owned by the loader (don't free). Returns `default_value`
 * (which may be NULL) if no source has the key. */
const char *vham_env(const char *key, const char *default_value);

/* Force a re-read of .env files (rarely needed — first vham_env()
 * call auto-loads). */
void vham_env_reload(void);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_ENVCFG_H */
