/* tools/vham-activate.c — emulates the Flow A (silent) account
 * activation HTTP request that the official VHAM/LinkPoon Android
 * app sends.
 *
 * Mirrors com.linkpoon.ham.activity.ActivateAccountV2Activity (which
 * dispatches into a1.i via HttpEngine.sendGetRequest). The exact URL
 * built by the official client is:
 *
 *   http://<server>:8081/online/alarm/CGI!addUDevice.action
 *     ?token=rhs52da318rg2a85se2h
 *     &companyId=2022060912281752
 *     &deviceId=<imei>
 *     &num=<derived-account>
 *     &MC_SRV_ID=...
 *
 * Defaults are deliberately conservative: dry-run unless --send.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/account.h"
#include "vham/envcfg.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Hardcoded values lifted verbatim from the APK
 * (a1/i.smali:279, decompiled/ActivateAccountV2Activity.java:112).
 * These are not secrets — they're embedded in the public APK. */
#define VHAM_HARDCODED_TOKEN     "rhs52da318rg2a85se2h"
#define VHAM_HARDCODED_COMPANYID "2022060912281752"
#define VHAM_DEFAULT_HTTP_PORT   8081
/* Override via VHAM_SERVER env / .env or --server. */
#define VHAM_DEFAULT_SERVER      "us.vham.net"      /* US */

static void usage(const char *argv0) {
    fprintf(stderr,
        "vham-activate — emulate the Flow A account-activation HTTP GET\n"
        "\n"
        "Usage: %s --imei <imei> [options]\n"
        "\n"
        "Options:\n"
        "  --imei <imei>        device IMEI (14-15 digits) [REQUIRED]\n"
        "  --server <ip>        server IP (default: %s)\n"
        "  --port <port>        TCP port (default: %d)\n"
        "  --mc-srv-id <s>      MC_SRV_ID query param (default: empty)\n"
        "  --send               actually send the request\n"
        "                       (default is dry-run: print URL, exit)\n"
        "  --timeout-s <n>      socket timeout in seconds (default: 10)\n"
        "  -h, --help           show this help\n"
        "\n"
        "Without --send the program prints the exact request it would\n"
        "send and exits without touching the network.\n",
        argv0, VHAM_DEFAULT_SERVER, VHAM_DEFAULT_HTTP_PORT);
}

static int build_path(char *out, size_t cap,
                      const char *imei,
                      const char *account,
                      const char *mc_srv_id) {
    int n = snprintf(out, cap,
        "/online/alarm/CGI!addUDevice.action"
        "?token=%s"
        "&companyId=%s"
        "&deviceId=%s"
        "&num=%s"
        "&MC_SRV_ID=%s",
        VHAM_HARDCODED_TOKEN,
        VHAM_HARDCODED_COMPANYID,
        imei, account,
        mc_srv_id ? mc_srv_id : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

static int http_get(const char *ip, int port, const char *path,
                    int timeout_s, FILE *out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        close(fd);
        return -1;
    }

    fprintf(stderr, "[net] connecting to %s:%d ...\n", ip, port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "[net] connect failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    fprintf(stderr, "[net] connected\n");

    char req[2048];
    int rn = snprintf(req, sizeof req,
        "GET %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: vham-activate/0.1 (libvham)\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, ip, port);
    if (rn < 0 || (size_t)rn >= sizeof req) {
        fprintf(stderr, "request too long\n");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[net] >>> %d bytes\n%.*s",
            rn, rn, req);

    ssize_t sent = 0;
    while (sent < rn) {
        ssize_t w = send(fd, req + sent, (size_t)(rn - sent), 0);
        if (w <= 0) {
            fprintf(stderr, "[net] send failed: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        sent += w;
    }

    fprintf(stderr, "[net] <<< response:\n");
    char buf[4096];
    ssize_t total = 0;
    while (1) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r <= 0) break;
        fwrite(buf, 1, (size_t)r, out);
        total += r;
    }
    fputc('\n', out);
    fprintf(stderr, "[net] read %zd bytes total\n", total);

    close(fd);
    return total > 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *imei      = NULL;
    const char *server    = vham_env("VHAM_SERVER", VHAM_DEFAULT_SERVER);
    const char *mc_srv_id = "";
    int port              = VHAM_DEFAULT_HTTP_PORT;
    int timeout_s         = 10;
    int send_for_real     = 0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "--imei") && i + 1 < argc)     { imei      = argv[++i]; }
        else if (!strcmp(a, "--server") && i + 1 < argc)   { server    = argv[++i]; }
        else if (!strcmp(a, "--port") && i + 1 < argc)     { port      = atoi(argv[++i]); }
        else if (!strcmp(a, "--mc-srv-id") && i + 1 < argc){ mc_srv_id = argv[++i]; }
        else if (!strcmp(a, "--timeout-s") && i + 1 < argc){ timeout_s = atoi(argv[++i]); }
        else if (!strcmp(a, "--send"))                     { send_for_real = 1; }
        else { fprintf(stderr, "unknown arg: %s\n\n", a); usage(argv[0]); return 1; }
    }

    if (!imei) {
        fprintf(stderr, "error: --imei is required\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Derive the account name from the IMEI, using the region prefix
     * that corresponds to the chosen server. */
    char account[32];
    if (vham_silent_account(imei, server, account, sizeof account) != 0) {
        fprintf(stderr, "error: vham_silent_account failed "
                "(IMEI must be 14-15 digits)\n");
        return 1;
    }
    const char *prefix = vham_region_prefix(server);

    char path[1024];
    if (build_path(path, sizeof path, imei, account, mc_srv_id) < 0) {
        fprintf(stderr, "error: path too long\n");
        return 1;
    }

    /* Always print the derivation + URL — both dry-run and live. */
    printf("=== vham-activate ===\n");
    printf("  imei         : %s\n", imei);
    printf("  server       : %s:%d\n", server, port);
    printf("  region prefix: %s\n", prefix ? prefix : "(none)");
    printf("  account      : %s\n", account);
    printf("  request URL  : http://%s:%d%s\n", server, port, path);
    printf("\n");

    if (!send_for_real) {
        printf("(dry-run; pass --send to actually issue this request)\n");
        return 0;
    }

    fprintf(stderr, "\n[net] SENDING LIVE REQUEST\n\n");
    int rc = http_get(server, port, path, timeout_s, stdout);
    return rc == 0 ? 0 : 2;
}
