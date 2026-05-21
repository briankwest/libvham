/* libvham/src/envcfg.c — .env loader.
 *
 * SPDX-License-Identifier: MIT
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vham/envcfg.h"

#define KV_MAX_ENTRIES   64
#define KV_KEY_MAX       64
#define KV_VAL_MAX       256

typedef struct {
    char key[KV_KEY_MAX];
    char val[KV_VAL_MAX];
} env_entry_t;

static env_entry_t  g_entries[KV_MAX_ENTRIES];
static int          g_count;
static int          g_loaded;

/* Strip leading/trailing whitespace in-place. Returns the new start. */
static char *strip(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return s;
}

static void unquote(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n-1] == '"') ||
                   (s[0] == '\'' && s[n-1] == '\''))) {
        memmove(s, s + 1, n - 2);
        s[n - 2] = 0;
    }
}

static void load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *p = strip(line);
        if (*p == 0 || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = strip(p);
        char *v = strip(eq + 1);
        unquote(v);
        if (!*k) continue;
        if (g_count >= KV_MAX_ENTRIES) break;
        snprintf(g_entries[g_count].key, KV_KEY_MAX, "%s", k);
        snprintf(g_entries[g_count].val, KV_VAL_MAX, "%s", v);
        g_count++;
    }
    fclose(f);
}

static void load_all(void) {
    if (g_loaded) return;
    g_loaded = 1;
    g_count  = 0;
    /* Look first in CWD, then $HOME/.vham/env. Earlier wins. */
    load_file("./.env");
    const char *home = getenv("HOME");
    if (home) {
        char path[768];
        snprintf(path, sizeof path, "%s/.vham/env", home);
        load_file(path);
    }
}

void vham_env_reload(void) {
    g_loaded = 0;
    g_count  = 0;
}

const char *vham_env(const char *key, const char *default_value) {
    if (!key) return default_value;
    /* 1. Real environment variable. */
    const char *v = getenv(key);
    if (v && *v) return v;
    /* 2/3. .env files. */
    load_all();
    for (int i = 0; i < g_count; ++i) {
        if (!strcmp(g_entries[i].key, key)) return g_entries[i].val;
    }
    return default_value;
}
