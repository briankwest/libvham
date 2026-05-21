/* Tiny MD5 implementation (RFC 1321) used by vham_auth_md5.
 *
 * Public domain, derived from Colin Plumb's reference code.
 * SPDX-License-Identifier: CC0-1.0 OR Unlicense
 */
#include "md5_internal.h"
#include <string.h>

static uint32_t le32(const uint8_t *p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define F(x,y,z)  (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z)  (((x) & (z)) | ((y) & ~(z)))
#define H(x,y,z)  ((x) ^ (y) ^ (z))
#define I(x,y,z)  ((y) ^ ((x) | ~(z)))
#define ROL(x,n)  (((x) << (n)) | ((x) >> (32 - (n))))

#define STEP(f,a,b,c,d,x,t,s) \
    (a) += f((b),(c),(d)) + (x) + (uint32_t)(t); \
    (a) = ROL((a),(s)); \
    (a) += (b)

static void md5_block(uint32_t s[4], const uint8_t blk[64]) {
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = le32(blk + i*4);

    STEP(F, a, b, c, d, x[ 0], 0xd76aa478, 7);
    STEP(F, d, a, b, c, x[ 1], 0xe8c7b756, 12);
    STEP(F, c, d, a, b, x[ 2], 0x242070db, 17);
    STEP(F, b, c, d, a, x[ 3], 0xc1bdceee, 22);
    STEP(F, a, b, c, d, x[ 4], 0xf57c0faf, 7);
    STEP(F, d, a, b, c, x[ 5], 0x4787c62a, 12);
    STEP(F, c, d, a, b, x[ 6], 0xa8304613, 17);
    STEP(F, b, c, d, a, x[ 7], 0xfd469501, 22);
    STEP(F, a, b, c, d, x[ 8], 0x698098d8, 7);
    STEP(F, d, a, b, c, x[ 9], 0x8b44f7af, 12);
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17);
    STEP(F, b, c, d, a, x[11], 0x895cd7be, 22);
    STEP(F, a, b, c, d, x[12], 0x6b901122, 7);
    STEP(F, d, a, b, c, x[13], 0xfd987193, 12);
    STEP(F, c, d, a, b, x[14], 0xa679438e, 17);
    STEP(F, b, c, d, a, x[15], 0x49b40821, 22);

    STEP(G, a, b, c, d, x[ 1], 0xf61e2562, 5);
    STEP(G, d, a, b, c, x[ 6], 0xc040b340, 9);
    STEP(G, c, d, a, b, x[11], 0x265e5a51, 14);
    STEP(G, b, c, d, a, x[ 0], 0xe9b6c7aa, 20);
    STEP(G, a, b, c, d, x[ 5], 0xd62f105d, 5);
    STEP(G, d, a, b, c, x[10], 0x02441453, 9);
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14);
    STEP(G, b, c, d, a, x[ 4], 0xe7d3fbc8, 20);
    STEP(G, a, b, c, d, x[ 9], 0x21e1cde6, 5);
    STEP(G, d, a, b, c, x[14], 0xc33707d6, 9);
    STEP(G, c, d, a, b, x[ 3], 0xf4d50d87, 14);
    STEP(G, b, c, d, a, x[ 8], 0x455a14ed, 20);
    STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5);
    STEP(G, d, a, b, c, x[ 2], 0xfcefa3f8, 9);
    STEP(G, c, d, a, b, x[ 7], 0x676f02d9, 14);
    STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20);

    STEP(H, a, b, c, d, x[ 5], 0xfffa3942, 4);
    STEP(H, d, a, b, c, x[ 8], 0x8771f681, 11);
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16);
    STEP(H, b, c, d, a, x[14], 0xfde5380c, 23);
    STEP(H, a, b, c, d, x[ 1], 0xa4beea44, 4);
    STEP(H, d, a, b, c, x[ 4], 0x4bdecfa9, 11);
    STEP(H, c, d, a, b, x[ 7], 0xf6bb4b60, 16);
    STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23);
    STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4);
    STEP(H, d, a, b, c, x[ 0], 0xeaa127fa, 11);
    STEP(H, c, d, a, b, x[ 3], 0xd4ef3085, 16);
    STEP(H, b, c, d, a, x[ 6], 0x04881d05, 23);
    STEP(H, a, b, c, d, x[ 9], 0xd9d4d039, 4);
    STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11);
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16);
    STEP(H, b, c, d, a, x[ 2], 0xc4ac5665, 23);

    STEP(I, a, b, c, d, x[ 0], 0xf4292244, 6);
    STEP(I, d, a, b, c, x[ 7], 0x432aff97, 10);
    STEP(I, c, d, a, b, x[14], 0xab9423a7, 15);
    STEP(I, b, c, d, a, x[ 5], 0xfc93a039, 21);
    STEP(I, a, b, c, d, x[12], 0x655b59c3, 6);
    STEP(I, d, a, b, c, x[ 3], 0x8f0ccc92, 10);
    STEP(I, c, d, a, b, x[10], 0xffeff47d, 15);
    STEP(I, b, c, d, a, x[ 1], 0x85845dd1, 21);
    STEP(I, a, b, c, d, x[ 8], 0x6fa87e4f, 6);
    STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
    STEP(I, c, d, a, b, x[ 6], 0xa3014314, 15);
    STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21);
    STEP(I, a, b, c, d, x[ 4], 0xf7537e82, 6);
    STEP(I, d, a, b, c, x[11], 0xbd3af235, 10);
    STEP(I, c, d, a, b, x[ 2], 0x2ad7d2bb, 15);
    STEP(I, b, c, d, a, x[ 9], 0xeb86d391, 21);

    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

void vham_md5_init(vham_md5_ctx_t *c) {
    c->state[0] = 0x67452301;
    c->state[1] = 0xefcdab89;
    c->state[2] = 0x98badcfe;
    c->state[3] = 0x10325476;
    c->bits = 0;
    c->bufn = 0;
}

void vham_md5_update(vham_md5_ctx_t *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    c->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t want = 64 - c->bufn;
        size_t take = (len < want) ? len : want;
        memcpy(c->buf + c->bufn, p, take);
        c->bufn += take; p += take; len -= take;
        if (c->bufn == 64) {
            md5_block(c->state, c->buf);
            c->bufn = 0;
        }
    }
}

void vham_md5_final(vham_md5_ctx_t *c, uint8_t out[16]) {
    static const uint8_t pad[64] = { 0x80, 0 };
    uint64_t bits = c->bits;
    uint8_t lenbuf[8];
    put_le32(lenbuf,     (uint32_t)(bits));
    put_le32(lenbuf + 4, (uint32_t)(bits >> 32));

    size_t padlen = (c->bufn < 56) ? (56 - c->bufn) : (120 - c->bufn);
    vham_md5_update(c, pad, padlen);
    vham_md5_update(c, lenbuf, 8);

    put_le32(out,      c->state[0]);
    put_le32(out + 4,  c->state[1]);
    put_le32(out + 8,  c->state[2]);
    put_le32(out + 12, c->state[3]);
}

void vham_md5(const void *data, size_t len, uint8_t out[16]) {
    vham_md5_ctx_t c;
    vham_md5_init(&c);
    vham_md5_update(&c, data, len);
    vham_md5_final(&c, out);
}

void vham_md5_hex(const uint8_t in[16], char out[33]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        out[i*2]   = hex[(in[i] >> 4) & 0xf];
        out[i*2+1] = hex[(in[i])      & 0xf];
    }
    out[32] = 0;
}
