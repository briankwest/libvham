/* libvham/src/tokenstore.c — per-user token persistence.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "vham/tokenstore.h"

/* Resolve the directory holding our token files. Prefers
 *   $XDG_CONFIG_HOME/vham/
 * then
 *   $HOME/.vham/
 */
static int store_dir(char *out, size_t cap) {
    const char *base = getenv("XDG_CONFIG_HOME");
    const char *sub  = "vham";
    if (!base || !*base) {
        base = getenv("HOME");
        sub  = ".vham";
        if (!base || !*base) return -1;
    }
    int n = snprintf(out, cap, "%s/%s", base, sub);
    if (n < 0 || (size_t)n >= cap) return -1;
    mkdir(out, 0700);   /* best-effort */
    return 0;
}

static int store_path(const char *user, char *out, size_t cap) {
    char dir[512];
    if (store_dir(dir, sizeof dir)) return -1;
    int n = snprintf(out, cap, "%s/%s.token", dir, user);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int vham_token_save(const vham_token_t *t) {
    if (!t || !t->user[0]) return -1;
    char path[768];
    if (store_path(t->user, path, sizeof path)) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "user=%s\n", t->user);
    fprintf(f, "token=%s\n", t->token);
    fprintf(f, "last_reg=%llu\n", (unsigned long long)t->last_reg_unix);
    fprintf(f, "yaoyun=%s\n", t->yaoyun);
    int rc = ferror(f) ? -1 : 0;
    fclose(f);
    if (rc == 0) chmod(path, 0600);
    return rc;
}

static void copy_value(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n && src[n-1] == '\n') n--;
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

int vham_token_load(const char *user, vham_token_t *out) {
    if (!user || !out) return -1;
    char path[768];
    if (store_path(user, path, sizeof path)) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(out, 0, sizeof *out);
    strncpy(out->user, user, sizeof out->user - 1);
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *val = eq + 1;
        if (!strcmp(line, "token"))      copy_value(out->token,  sizeof out->token,  val);
        else if (!strcmp(line, "yaoyun"))copy_value(out->yaoyun, sizeof out->yaoyun, val);
        else if (!strcmp(line, "last_reg")) out->last_reg_unix = strtoull(val, NULL, 10);
    }
    fclose(f);
    return 0;
}

int vham_token_clear(const char *user) {
    if (!user) return -1;
    char path[768];
    if (store_path(user, path, sizeof path)) return -1;
    return unlink(path) == 0 ? 0 : -1;
}
