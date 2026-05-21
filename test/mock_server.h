/* libvham/test/mock_server.h — tiny in-process VHAM registration
 * server used for round-trip tests. Not part of libvham proper.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_TEST_MOCK_SERVER_H
#define VHAM_TEST_MOCK_SERVER_H

#include "vham/codec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     username[64];
    char     password[64];
    char     realm   [64];
    char     nonce   [64];

    /* Bookkeeping so the test can assert sequencing */
    int      saw_initial_regreq;
    int      saw_auth_regreq;
    int      regreqs_received;
} mock_srv_t;

/* Initialize. The realm + nonce are what the server will send on the
 * auth challenge. */
void mock_srv_init(mock_srv_t *s,
                   const char *username,
                   const char *password,
                   const char *realm,
                   const char *nonce);

/* Process an incoming REGREQ datagram. Writes a REGRSP into `out`,
 * returns its length. Returns -1 on parse error. */
int mock_srv_handle(mock_srv_t *s,
                    const void *in_buf, size_t in_len,
                    void *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
