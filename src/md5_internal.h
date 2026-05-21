/* SPDX-License-Identifier: CC0-1.0 OR Unlicense */
#ifndef VHAM_MD5_INTERNAL_H
#define VHAM_MD5_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   bufn;
} vham_md5_ctx_t;

void vham_md5_init  (vham_md5_ctx_t *c);
void vham_md5_update(vham_md5_ctx_t *c, const void *data, size_t len);
void vham_md5_final (vham_md5_ctx_t *c, uint8_t out[16]);
void vham_md5       (const void *data, size_t len, uint8_t out[16]);
void vham_md5_hex   (const uint8_t in[16], char out[33]);

#endif
