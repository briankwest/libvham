/* tools/vham-login.c — drive the libvham registration state machine
 * over real UDP, optionally against a live VHAM signaling server.
 *
 * Default mode is dry-run: build the initial REGREQ, print it, exit.
 * Pass --send to open a UDP socket and run the full handshake.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/codec.h"
#include "vham/envcfg.h"
#include "vham/regreq.h"
#include "vham/regrsp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Default. Override via VHAM_SERVER env / .env or --server. */
#define DEFAULT_SERVER      "us.vham.net"
#define DEFAULT_PORT        10000
#define DEFAULT_TIMEOUT_S   5
#define DEFAULT_RETRIES     3

static void usage(const char *argv0) {
    fprintf(stderr,
        "vham-login — drive the libvham reg state machine over UDP\n"
        "\n"
        "Usage: %s --user <num> --pass <pw> [options]\n"
        "\n"
        "Options:\n"
        "  --user <num>         account number (default: VHAM_USER from .env)\n"
        "  --pass <pw>          account password (default: VHAM_PASS from .env)\n"
        "  --server <ip>        server IP (default: %s)\n"
        "  --port <port>        UDP port (default: %d)\n"
        "  --timeout-s <n>      receive timeout per RTT (default: %d)\n"
        "  --retries <n>        retransmits per phase (default: %d)\n"
        "  --send               actually open a socket and send\n"
        "                       (default: dry-run, print first REGREQ and exit)\n"
        "  -h, --help           show this help\n",
        argv0, DEFAULT_SERVER, DEFAULT_PORT,
        DEFAULT_TIMEOUT_S, DEFAULT_RETRIES);
}

static void hexdump(const char *prefix, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < n; i += 16) {
        fprintf(stderr, "  %s %04zx  ", prefix, i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) fprintf(stderr, "%02x ", p[i + j]);
            else           fprintf(stderr, "   ");
            if (j == 7) fprintf(stderr, " ");
        }
        fprintf(stderr, " |");
        for (size_t j = 0; j < 16 && i + j < n; ++j) {
            uint8_t c = p[i + j];
            fputc((c >= 32 && c < 127) ? c : '.', stderr);
        }
        fprintf(stderr, "|\n");
    }
}

static uint16_t peek_tap_cmd(const uint8_t *buf, size_t len) {
    if (len < 16) return 0;
    return ((uint16_t)buf[10] << 8) | buf[11];
}

static const char *state_str(vham_reg_state_t s) {
    switch (s) {
    case VHAM_REG_INIT:           return "INIT";
    case VHAM_REG_SENT_INITIAL:   return "SENT_INITIAL";
    case VHAM_REG_SENT_AUTH:      return "SENT_AUTH";
    case VHAM_REG_OK:             return "OK";
    case VHAM_REG_FAILED:         return "FAILED";
    case VHAM_REG_REDIRECT:       return "REDIRECT";
    }
    return "?";
}

/* Open a UDP socket and connect() it to the server. connect() on a
 * SOCK_DGRAM is just a filter — recv() returns only packets from the
 * connected peer. */
/* libvham IP convention: convention A — top octet of the
 * dotted-quad in the highest byte of the u32.
 *   47.253.13.238 ↔ 0x2ffd0dee
 *
 * To talk to BSD sockets on a little-endian host we need .s_addr in
 * memory-byte order [47, 253, 13, 238], which on LE is u32 value
 * 0xee0dfd2f — i.e. htonl(0x2ffd0dee). So convert via htonl on input
 * and ntohl on output. */
static int open_udp_host(uint32_t ipv4_convA, uint16_t port, int timeout_s) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(ipv4_convA);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "udp connect: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int open_udp(const char *ip, int port, int timeout_s) {
    struct in_addr ina;
    if (inet_pton(AF_INET, ip, &ina) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        return -1;
    }
    return open_udp_host(ntohl(ina.s_addr), (uint16_t)port, timeout_s);
}

/* Send a TAP-level ACK for a received CMD/RSP frame. We extract seq,
 * class, cmd from the header at offset 4/8/10 and bounce them back. */
static void send_tap_ack(int fd, const uint8_t *frame, size_t frame_len) {
    if (frame_len < 16) return;
    uint32_t seq      = ((uint32_t)frame[4] << 24) | ((uint32_t)frame[5] << 16)
                      | ((uint32_t)frame[6] << 8)  | (uint32_t)frame[7];
    uint16_t class_id = ((uint16_t)frame[8] << 8)  | (uint16_t)frame[9];
    uint16_t cmd      = ((uint16_t)frame[10] << 8) | (uint16_t)frame[11];
    uint8_t  ack[16];
    int n = vham_build_tap_ack(seq, class_id, cmd, ack, sizeof ack);
    if (n != 16) return;
    fprintf(stderr, "[net] ACK >>> 16 bytes (seq=0x%08x cmd=0x%04x)\n",
            seq, cmd);
    (void)send(fd, ack, (size_t)n, 0);
}

static uint16_t peek_tap_flags(const uint8_t *buf, size_t len) {
    if (len < 16) return 0;
    return ((uint16_t)buf[2] << 8) | buf[3];
}

/* Send a buffer and wait for one reply that has the given wMsgId.
 *
 * We ACK every CMD/RSP we receive (per the TAP transport protocol),
 * and drop TAP-level ACKs that the server sends back for our REGREQ.
 *
 * Returns the recv length of the matching frame, or -1 on timeout. */
static int rpc_send_recv(int fd,
                         const uint8_t *send_buf, size_t send_len,
                         uint8_t *recv_buf, size_t recv_cap,
                         uint16_t expect_cmd,
                         int retries) {
    for (int attempt = 0; attempt <= retries; ++attempt) {
        if (attempt > 0) {
            fprintf(stderr, "[net] retransmit (attempt %d)\n", attempt + 1);
        }
        fprintf(stderr, "[net] >>> %zu bytes\n", send_len);
        hexdump(">>", send_buf, send_len);
        ssize_t w = send(fd, send_buf, send_len, 0);
        if (w != (ssize_t)send_len) {
            fprintf(stderr, "[net] send failed: %s\n", strerror(errno));
            return -1;
        }

        for (int spurious_guard = 0; spurious_guard < 8; ++spurious_guard) {
            ssize_t r = recv(fd, recv_buf, recv_cap, 0);
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                fprintf(stderr, "[net] recv failed: %s\n", strerror(errno));
                return -1;
            }
            fprintf(stderr, "[net] <<< %zd bytes\n", r);
            hexdump("<<", recv_buf, (size_t)r);
            uint16_t flags = peek_tap_flags(recv_buf, (size_t)r);
            uint16_t cmd   = peek_tap_cmd  (recv_buf, (size_t)r);
            if (flags == VHAM_TAP_FLAG_ACK) {
                fprintf(stderr,
                    "[net] (TAP ACK for our send, cmd=0x%04x — keep waiting)\n",
                    cmd);
                continue;
            }
            /* CMD/RSP: ACK it back to the server. */
            send_tap_ack(fd, recv_buf, (size_t)r);
            if (cmd == expect_cmd) {
                return (int)r;
            }
            fprintf(stderr,
                "[net] ignoring frame (cmd=0x%04x, expected 0x%04x)\n",
                cmd, expect_cmd);
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    const char *user      = vham_env("VHAM_USER",   NULL);
    const char *pass      = vham_env("VHAM_PASS",   NULL);
    const char *server    = vham_env("VHAM_SERVER", DEFAULT_SERVER);
    int port              = DEFAULT_PORT;
    int timeout_s         = DEFAULT_TIMEOUT_S;
    int retries           = DEFAULT_RETRIES;
    int send_for_real     = 0;
    int plain_auth        = 0;     /* override IE 0x0b with plaintext pw */
    int no_echo           = 0;     /* skip IE 0x62/0x70 echo */

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "--user") && i + 1 < argc)     { user = argv[++i]; }
        else if (!strcmp(a, "--pass") && i + 1 < argc)     { pass = argv[++i]; }
        else if (!strcmp(a, "--server") && i + 1 < argc)   { server = argv[++i]; }
        else if (!strcmp(a, "--port") && i + 1 < argc)     { port = atoi(argv[++i]); }
        else if (!strcmp(a, "--timeout-s") && i + 1 < argc){ timeout_s = atoi(argv[++i]); }
        else if (!strcmp(a, "--retries") && i + 1 < argc)  { retries = atoi(argv[++i]); }
        else if (!strcmp(a, "--send"))                     { send_for_real = 1; }
        else if (!strcmp(a, "--plain-auth"))               { plain_auth = 1; }
        else if (!strcmp(a, "--no-echo"))                  { no_echo = 1; }
        else { fprintf(stderr, "unknown arg: %s\n\n", a); usage(argv[0]); return 1; }
    }
    if (!user || !pass) {
        fprintf(stderr, "error: --user and --pass are required\n\n");
        usage(argv[0]);
        return 1;
    }

    /* libvham IP convention A: 47.253.13.238 → 0x2ffd0dee. */
    struct in_addr ina;
    if (inet_pton(AF_INET, server, &ina) != 1) {
        fprintf(stderr, "bad ip: %s\n", server);
        return 1;
    }
    uint32_t server_ipv4 = ntohl(ina.s_addr);

    vham_reg_client_t cli;
    if (vham_reg_client_init(&cli, user, pass,
                             server_ipv4, (uint16_t)port) != 0) {
        fprintf(stderr, "vham_reg_client_init failed\n");
        return 1;
    }

    /* Always print the first REGREQ in human form, both dry-run and live */
    uint8_t initial[1500];
    int n = vham_reg_client_emit(&cli, initial, sizeof initial);
    if (n <= 0) {
        fprintf(stderr, "could not build initial REGREQ\n");
        return 1;
    }

    printf("=== vham-login ===\n");
    printf("  server    : %s:%d (UDP)\n", server, port);
    printf("  user      : %s\n", user);
    printf("  pass      : %s\n", pass);
    printf("  REGREQ #1 : %d bytes\n", n);
    hexdump("  ", initial, (size_t)n);
    printf("\n");

    if (!send_for_real) {
        printf("(dry-run; pass --send to open a UDP socket and run the handshake)\n");
        return 0;
    }

    /* --- live path --- */
    int fd = open_udp(server, port, timeout_s);
    if (fd < 0) return 2;

    uint8_t resp[2048];
    int rn = 0;
    vham_reg_state_t st = VHAM_REG_INIT;

    /* Phase 1: send initial REGREQ → expect REGRSP. The first reply
     * may be from a dispatcher node that redirects us via IE 0x24
     * to the actual signaling endpoint. Follow up to 3 redirects. */
    for (int hop = 0; hop < 3; ++hop) {
        rn = rpc_send_recv(fd, initial, (size_t)n, resp, sizeof resp,
                           VHAM_MM_REGRSP, retries);
        if (rn < 0) {
            fprintf(stderr, "[!] no REGRSP (timeout)\n");
            close(fd);
            return 3;
        }

        st = vham_reg_client_recv(&cli, resp, (size_t)rn);
        if (st == VHAM_REG_REDIRECT) {
            /* Library already updated cli.server_ipv4/port. */
            char ipbuf[INET_ADDRSTRLEN];
            struct in_addr a = { .s_addr = htonl(cli.server_ipv4) };
            inet_ntop(AF_INET, &a, ipbuf, sizeof ipbuf);
            fprintf(stderr, "[hop] dispatcher redirected to %s:%u\n",
                    ipbuf, cli.server_port);
            close(fd);
            fd = open_udp_host(cli.server_ipv4, cli.server_port, timeout_s);
            if (fd < 0) return 2;
            n = vham_reg_client_emit(&cli, initial, sizeof initial);
            if (n <= 0) { close(fd); return 5; }
            continue;
        }
        fprintf(stderr, "[sm] phase-1 state: %s\n", state_str(st));
        break;
    }

    if (st == VHAM_REG_OK) {
        printf("\nlogin OK without challenge (cached token?)\n");
        close(fd);
        return 0;
    }
    if (st == VHAM_REG_FAILED) {
        printf("\nlogin FAILED after phase 1\n");
        close(fd);
        return 4;
    }

    /* Phase 2: emit REGREQ with auth → expect REGRSP (success or cause).
     *
     * If --plain-auth was set, overwrite the computed digest with the
     * plaintext password as a quick experiment to see whether the
     * server uses a different auth scheme. If --no-echo, also clear
     * the IE 0x62/0x70 echo. */
    if (plain_auth) {
        snprintf(cli.last_response_hex, sizeof cli.last_response_hex,
                 "%s", pass);
        fprintf(stderr, "[sm] plain-auth: IE 0x0b = '%s'\n",
                cli.last_response_hex);
    }
    if (no_echo) {
        cli.have_auth_mode = 0;
        cli.dispatch_num[0] = 0;
        fprintf(stderr, "[sm] no-echo: skipping IE 0x62 and IE 0x70\n");
    }
    uint8_t reg2[1500];
    n = vham_reg_client_emit(&cli, reg2, sizeof reg2);
    if (n <= 0) {
        fprintf(stderr, "could not build auth REGREQ\n");
        close(fd);
        return 5;
    }
    fprintf(stderr, "[sm] computed response: %s\n", cli.last_response_hex);
    fprintf(stderr, "[sm] echoing  algorithm=%s nonce=%s realm=%s\n",
            cli.last_algorithm, cli.last_nonce, cli.last_realm);

    rn = rpc_send_recv(fd, reg2, (size_t)n, resp, sizeof resp,
                       VHAM_MM_REGRSP, retries);
    if (rn < 0) {
        fprintf(stderr, "[!] no REGRSP after phase 2 (timeout)\n");
        close(fd);
        return 6;
    }

    st = vham_reg_client_recv(&cli, resp, (size_t)rn);
    fprintf(stderr, "[sm] phase-2 state: %s\n", state_str(st));

    if (st == VHAM_REG_OK) {
        printf("\nfinal: OK\n");
        printf("\n=== session ===\n");
        printf("  dispatch_num : %s\n",
               cli.dispatch_num[0] ? cli.dispatch_num : "(none)");
        if (cli.have_session_id)
            printf("  session_id   : 0x%08x\n", cli.session_id);
        if (cli.have_sys_time)
            printf("  server time  : %04u-%02u-%02u %02u:%02u:%02u.%03u\n",
                   cli.sys_year, cli.sys_month, cli.sys_day,
                   cli.sys_hour, cli.sys_min, cli.sys_sec, cli.sys_subsec);
        if (cli.have_media_gw) {
            struct in_addr a = { .s_addr = htonl(cli.media_gw_ipv4) };
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, buf, sizeof buf);
            printf("  media gw     : %s:%u\n", buf, cli.media_gw_port);
        }
        if (cli.have_alt_endpoint) {
            struct in_addr a = { .s_addr = htonl(cli.alt_ipv4) };
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, buf, sizeof buf);
            printf("  alt endpoint : %s:%u\n", buf, cli.alt_port);
        }
    } else {
        printf("\nfinal: %s\n", state_str(st));
    }
    close(fd);
    return (st == VHAM_REG_OK) ? 0 : 7;
}
