/* libvham/src/nat.c — NAT and STUN helpers extracted from vham-cli.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/nat.h"
#include "vham/codec.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

int vham_stun_discover(int fd,
                       const char *stun_host, uint16_t stun_port,
                       int timeout_ms,
                       uint32_t *out_ip, uint16_t *out_port) {
    if (fd < 0 || !stun_host || !out_ip || !out_port) return -1;

    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)stun_port);

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *ai = NULL;
    if (getaddrinfo(stun_host, port_str, &hints, &ai) != 0 || !ai) return -1;

    /* RFC 5389 §6: Binding Request. 20-byte fixed header, no attrs. */
    uint8_t req[20];
    req[0] = 0x00; req[1] = 0x01;       /* type = Binding Request */
    req[2] = 0x00; req[3] = 0x00;       /* attrs length = 0 */
    req[4] = 0x21; req[5] = 0x12;       /* magic cookie */
    req[6] = 0xa4; req[7] = 0x42;
    for (int i = 8; i < 20; ++i)        /* transaction id */
        req[i] = (uint8_t)(rand() & 0xff);

    ssize_t sn = sendto(fd, req, sizeof req, 0, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    if (sn != (ssize_t)sizeof req) return -1;

    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t rsp[512];
    ssize_t rn = recv(fd, rsp, sizeof rsp, 0);
    if (rn < 20)                         return -1;
    if (rsp[0] != 0x01 || rsp[1] != 0x01) return -1;   /* not Binding Success */

    /* Walk attributes for XOR-MAPPED-ADDRESS (type 0x0020). */
    size_t off = 20;
    while (off + 4 <= (size_t)rn) {
        uint16_t atype = (uint16_t)((rsp[off] << 8) | rsp[off+1]);
        uint16_t alen  = (uint16_t)((rsp[off+2] << 8) | rsp[off+3]);
        if (off + 4 + alen > (size_t)rn) break;
        if (atype == 0x0020 && alen >= 8) {
            /* XOR-MAPPED-ADDRESS: pad(1) | family(1) | xport(2) | xip(4) */
            uint16_t xp = (uint16_t)((rsp[off+6] << 8) | rsp[off+7]);
            uint32_t xa = ((uint32_t)rsp[off+8]  << 24)
                        | ((uint32_t)rsp[off+9]  << 16)
                        | ((uint32_t)rsp[off+10] << 8)
                        |  (uint32_t)rsp[off+11];
            *out_port = (uint16_t)(xp ^ 0x2112);
            *out_ip   = xa ^ 0x2112a442u;
            return 0;
        }
        off += 4 + alen + ((alen % 4) ? (4 - alen % 4) : 0);
    }
    return -1;
}

int vham_tap_build_ack_for(const void *recv_buf, size_t recv_len,
                           void *ack_out, size_t ack_cap) {
    if (!recv_buf || recv_len < 12 || !ack_out) return -1;
    if (ack_cap < 16) return -1;
    const uint8_t *r = (const uint8_t *)recv_buf;
    /* TAP header bytes: ver_hi(1) ver_lo(1) flags(2 BE) seq(4 BE)
     *                   class(2 BE) cmd(2 BE) body_len(4 BE). */
    uint16_t flags = (uint16_t)((r[2] << 8) | r[3]);
    if (flags == VHAM_TAP_FLAG_ACK) return 0;       /* already an ACK */
    uint32_t seq   = ((uint32_t)r[4] << 24) | ((uint32_t)r[5] << 16)
                   | ((uint32_t)r[6] << 8)  |  (uint32_t)r[7];
    uint16_t cls   = (uint16_t)((r[8]  << 8) | r[9]);
    uint16_t cmd   = (uint16_t)((r[10] << 8) | r[11]);
    return vham_build_tap_ack(seq, cls, cmd, ack_out, ack_cap);
}

/* ---------- media-channel NAT sentinel ---------- */

static uint64_t monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

#define VHAM_MEDIA_NAT_INTERVAL_US 2000000ULL   /* 2 s, per CMediaTrans::Scan */

static int media_nat_send(vham_media_nat_t *s) {
    /* CMediaTrans::SendNat @ 0x277d30: raw 3-byte FF D3 01 to peer. */
    static const uint8_t sentinel[3] = { 0xFF, 0xD3, 0x01 };
    struct sockaddr_in dst = { 0 };
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = s->peer_ip_be;
    dst.sin_port        = s->peer_port_be;
    ssize_t n = sendto(s->fd, sentinel, sizeof sentinel, 0,
                       (struct sockaddr *)&dst, sizeof dst);
    return (n == (ssize_t)sizeof sentinel) ? 0 : -1;
}

int vham_media_nat_open(vham_media_nat_t *s, int fd,
                        uint32_t peer_ip_host, uint16_t peer_port_host) {
    if (!s || fd < 0) return -1;
    s->fd            = fd;
    s->peer_ip_be    = htonl(peer_ip_host);
    s->peer_port_be  = htons(peer_port_host);
    /* SetSendNat(true) @ 0x277fd8 sends 3 sentinels back-to-back to
     * register the endpoint with the media controller. */
    for (int i = 0; i < 3; ++i) {
        if (media_nat_send(s) != 0) return -1;
    }
    s->next_send_us = monotonic_us() + VHAM_MEDIA_NAT_INTERVAL_US;
    return 0;
}

int vham_media_nat_tick(vham_media_nat_t *s) {
    if (!s || s->fd < 0) return -1;
    uint64_t now = monotonic_us();
    if (now < s->next_send_us) return 0;
    if (media_nat_send(s) != 0) return -1;
    s->next_send_us = now + VHAM_MEDIA_NAT_INTERVAL_US;
    return 1;
}
