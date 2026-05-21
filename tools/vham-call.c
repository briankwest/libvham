/* tools/vham-call.c — emit a CC_SETUP frame and (optionally) send it.
 *
 * NB: this is a dry-run-by-default tool. Live sending is gated on
 * --send. To even have a chance of the server accepting the call,
 * you'd need an active signaling session — but this tool does not
 * yet attach to a running vham-login session, so live mode will
 * just produce a transport-level ACK + an immediate CC_REL (call
 * release) with a "no session" cause. That's still useful for
 * exercising the frame format.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/cc.h"
#include "vham/codec.h"
#include "vham/envcfg.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void usage(const char *argv0) {
    fprintf(stderr,
        "vham-call — emit a CC_SETUP frame\n"
        "\n"
        "Usage: %s --from <num> --to <num> [options]\n"
        "\n"
        "Options:\n"
        "  --from <num>      calling party (your dispatch number)\n"
        "  --to   <num>      called party (destination)\n"
        "  --service <hex>   service type (default 0x11 = half-duplex PTT)\n"
        "                     0x11 = half-duplex (PTT)\n"
        "                     0x12 = full-duplex\n"
        "                     0x18 = video call\n"
        "                     0x15 = conference\n"
        "  --leg <id>        leg id (dwSrcFsmId) (default 1)\n"
        "  --seq <n>         TAP seq_no (default 1)\n"
        "  --server <ip>     server IP/host for --send (default: VHAM_SERVER or us.vham.net)\n"
        "  --port <port>     UDP port (default 10201)\n"
        "  --send            actually transmit (dry-run by default)\n"
        "  -h, --help        show this help\n",
        argv0);
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

int main(int argc, char **argv) {
    const char *from      = NULL;
    const char *to        = NULL;
    uint32_t    service   = VHAM_CALL_HALF_DUPLEX;
    uint32_t    leg_id    = 1;
    uint32_t    seq_no    = 1;
    const char *server    = vham_env("VHAM_SERVER", "us.vham.net");
    int         port      = 10201;
    int         send_for_real = 0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "--from") && i + 1 < argc)    { from = argv[++i]; }
        else if (!strcmp(a, "--to") && i + 1 < argc)      { to = argv[++i]; }
        else if (!strcmp(a, "--service") && i + 1 < argc) { service = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--leg") && i + 1 < argc)     { leg_id = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--seq") && i + 1 < argc)     { seq_no = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--server") && i + 1 < argc)  { server = argv[++i]; }
        else if (!strcmp(a, "--port") && i + 1 < argc)    { port = atoi(argv[++i]); }
        else if (!strcmp(a, "--send"))                    { send_for_real = 1; }
        else { fprintf(stderr, "unknown arg: %s\n\n", a); usage(argv[0]); return 1; }
    }
    if (!from || !to) {
        fprintf(stderr, "error: --from and --to are required\n\n");
        usage(argv[0]);
        return 1;
    }

    vham_cc_setup_t s = {
        .seq_no       = seq_no,
        .leg_id       = leg_id,
        .called_num   = to,
        .calling_num  = from,
        .service_type = service,
        .sdp_bytes    = NULL,    /* TODO: pass real SDP for usable calls */
        .sdp_len      = 0,
    };

    uint8_t buf[1500];
    int n = vham_build_cc_setup(&s, buf, sizeof buf);
    if (n <= 0) { fprintf(stderr, "build failed\n"); return 1; }

    printf("=== vham-call (CC_SETUP) ===\n");
    printf("  from         : %s\n", from);
    printf("  to           : %s\n", to);
    printf("  service      : 0x%02x\n", service);
    printf("  leg_id       : %u\n", leg_id);
    printf("  seq          : %u\n", seq_no);
    printf("  frame length : %d bytes\n", n);
    hexdump("  ", buf, (size_t)n);

    if (!send_for_real) {
        printf("\n(dry-run; pass --send to transmit)\n");
        return 0;
    }

    /* Live send (single-shot, expect CC_REL because no session). */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 2; }
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad ip %s\n", server);
        close(fd);
        return 2;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("connect"); close(fd); return 2;
    }

    fprintf(stderr, "\n[net] >>> %d bytes to %s:%d\n", n, server, port);
    if (send(fd, buf, (size_t)n, 0) != (ssize_t)n) {
        fprintf(stderr, "send failed\n"); close(fd); return 2;
    }

    uint8_t resp[2048];
    for (int i = 0; i < 6; ++i) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r <= 0) break;
        fprintf(stderr, "[net] <<< %zd bytes\n", r);
        hexdump("<<", resp, (size_t)r);
    }
    close(fd);
    return 0;
}
