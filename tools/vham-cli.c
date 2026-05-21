/* tools/vham-cli.c — unified VHAM client CLI.
 *
 * Single binary that combines:
 *
 *   vham-cli activate ...   — HTTP Flow-A account creation
 *   vham-cli login    ...   — log in, print session, exit
 *   vham-cli query    ...   — log in, run IDT_GQueryU
 *   vham-cli join     ...   — log in, send IDT_GAddU
 *   vham-cli im       ...   — log in, send a text IM, exit
 *   vham-cli gps      ...   — log in, send a GPS report, exit
 *   vham-cli call     ...   — log in, place a PTT call
 *   vham-cli listen   ...   — log in, idle as callee
 *
 * Compared to the individual `vham-*` tools each subcommand calls the
 * same underlying libvham primitives — this is the one-stop user CLI.
 *
 * SPDX-License-Identifier: MIT
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "vham/cc.h"
#include "vham/codec.h"
#include "vham/gps.h"
#include "vham/im.h"
#include "vham/oam.h"
#include "vham/causes.h"
#include "vham/envcfg.h"
#include "vham/passthrough.h"
#include "vham/regreq.h"
#include "vham/regrsp.h"
#include "vham/tokenstore.h"

static int usage(void) {
    fprintf(stderr,
"vham-cli — unified VHAM PTT client\n"
"\n"
"Usage:\n"
"  vham-cli login    --user U --pass P [--server IP:PORT]\n"
"  vham-cli logout   --user U --pass P\n"
"  vham-cli list     --user U --pass P                 (groups from REGRSP)\n"
"  vham-cli query    --user U --pass P [--group G] [--scope N]\n"
"                                  scope: 100=own 200=related 900=user-group\n"
"                                         1200=add-group  (default 100)\n"
"  vham-cli join     --user U --pass P --group G\n"
"  vham-cli leave    --user U --pass P --group G\n"
"  vham-cli gadd     --user U --pass P --group G [--name N] [--gtype T]\n"
"  vham-cli gmodify  --user U --pass P --group G [--name N] [--gtype T] [--prio N]\n"
"  vham-cli gmodifyu --user U --pass P --group G --to NUM\n"
"  vham-cli im       --user U --pass P --to NUM --text \"...\"\n"
"  vham-cli gps      --user U --pass P --lat F --lon F\n"
"  vham-cli call     --user U --pass P --to CHANNEL_OR_NUM [--wait SEC]\n"
"  vham-cli listen   --user U --pass P [--tune CHANNEL] [--wait SEC]\n"
"  vham-cli passthrough --user U --pass P --to NUM --code N [--type N] [--data \"...\"]\n"
"  vham-cli mm       <profreq|modreq|routereq|accreq|nattprob> --user U --pass P\n"
"  vham-cli talkgroup --user U --pass P --group G [--name N]\n"
"                                  Create a real talk-group (type=7) and join it.\n"
"                                  Server admin-only — non-admins always get\n"
"                                  type=2 personal even with --gtype 7.\n"
"  vham-cli token    show|clear --user U\n"
"\n");
    return 2;
}

/* ---------- shared helpers ---------- */

static int open_socket(uint32_t ip_be, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = ip_be,
    };
    if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(fd); return -1;
    }
    return fd;
}

/* Drive the reg state machine to completion. Returns 0 on OK, -1 otherwise.
 * Library reports VHAM_REG_REDIRECT for the dispatcher hop; we just
 * reopen the socket. */
static int do_login(const char *user, const char *pass,
                    uint32_t server_ip_be, uint16_t server_port,
                    int *out_fd, vham_reg_client_t *cli) {
    int fd = open_socket(server_ip_be, server_port);
    if (fd < 0) { perror("socket"); return -1; }

    if (vham_reg_client_init(cli, user, pass,
                             ntohl(server_ip_be), server_port) != 0) {
        close(fd); return -1;
    }
    uint8_t buf[2048], resp[2048];
    int n = vham_reg_client_emit(cli, buf, sizeof buf);
    if (n <= 0) { close(fd); return -1; }

    for (int round = 0; round < 8; ++round) {
        if (send(fd, buf, (size_t)n, 0) < 0) { close(fd); return -1; }
        ssize_t r;
        while ((r = recv(fd, resp, sizeof resp, 0)) > 0) {
            uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
            if (flags == VHAM_TAP_FLAG_ACK) continue;

            vham_reg_state_t st = vham_reg_client_recv(cli, resp, (size_t)r);
            if (st == VHAM_REG_OK)     { *out_fd = fd; return 0; }
            if (st == VHAM_REG_FAILED) { close(fd); return -1; }
            if (st == VHAM_REG_REDIRECT) {
                /* Server told us to hop. The library already updated
                 * cli->server_ipv4 / port and reset state to INIT. */
                close(fd);
                fd = open_socket(htonl(cli->server_ipv4), cli->server_port);
                if (fd < 0) return -1;
            }
            n = vham_reg_client_emit(cli, buf, sizeof buf);
            if (n <= 0) { close(fd); return -1; }
            break;
        }
        if (r < 0) { fprintf(stderr, "recv timeout\n"); close(fd); return -1; }
    }
    close(fd);
    return -1;
}

/* ---------- arg parsing ---------- */

typedef struct {
    const char *user;
    const char *pass;
    const char *server;
    const char *to;
    const char *group;
    const char *name;
    const char *text;
    const char *tune;
    double      lat;
    double      lon;
    int         gtype;
    int         scope;
    int         prio;
    int         wait_sec;
    int         code;
    int         type;
    const char *data;
} args_t;

static int parse_args(int argc, char **argv, args_t *a) {
    memset(a, 0, sizeof *a);
    /* Defaults pulled from env / .env. CLI flags override below. */
    a->user   = vham_env("VHAM_USER",   NULL);
    a->pass   = vham_env("VHAM_PASS",   NULL);
    a->server = vham_env("VHAM_SERVER", NULL);
    a->to     = vham_env("VHAM_TO",     NULL);
    a->tune   = vham_env("VHAM_TUNE",   NULL);
    a->group  = vham_env("VHAM_GROUP",  NULL);
    if (!a->server) a->server = "us.vham.net:10000";
    for (int i = 2; i < argc; ++i) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if      (!strcmp(k, "--user")   && v) { a->user   = v; i++; }
        else if (!strcmp(k, "--pass")   && v) { a->pass   = v; i++; }
        else if (!strcmp(k, "--server") && v) { a->server = v; i++; }
        else if (!strcmp(k, "--to")     && v) { a->to     = v; i++; }
        else if (!strcmp(k, "--group")  && v) { a->group  = v; i++; }
        else if (!strcmp(k, "--name")   && v) { a->name   = v; i++; }
        else if (!strcmp(k, "--gtype")  && v) { a->gtype  = atoi(v); i++; }
        else if (!strcmp(k, "--scope")  && v) { a->scope  = atoi(v); i++; }
        else if (!strcmp(k, "--prio")   && v) { a->prio   = atoi(v); i++; }
        else if (!strcmp(k, "--wait")   && v) { a->wait_sec = atoi(v); i++; }
        else if (!strcmp(k, "--code")   && v) { a->code   = atoi(v); i++; }
        else if (!strcmp(k, "--type")   && v) { a->type   = atoi(v); i++; }
        else if (!strcmp(k, "--data")   && v) { a->data   = v; i++; }
        else if (!strcmp(k, "--text")   && v) { a->text   = v; i++; }
        else if (!strcmp(k, "--tune")   && v) { a->tune   = v; i++; }
        else if (!strcmp(k, "--lat")    && v) { a->lat = atof(v); i++; }
        else if (!strcmp(k, "--lon")    && v) { a->lon = atof(v); i++; }
        else { fprintf(stderr, "unknown arg: %s\n", k); return -1; }
    }
    return 0;
}

static int parse_server(const char *s, uint32_t *ip_be, uint16_t *port) {
    char host[256]; int p = 0;
    if (sscanf(s, "%255[^:]:%d", host, &p) != 2) return -1;
    /* Try literal IP first. */
    struct in_addr a;
    if (inet_aton(host, &a) != 0) {
        *ip_be = a.s_addr;
        *port  = (uint16_t)p;
        return 0;
    }
    /* Fall through to DNS resolution. */
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *ip_be = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    *port  = (uint16_t)p;
    freeaddrinfo(res);
    return 0;
}

/* ---------- subcommands ---------- */

static int cmd_login(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) {
        fprintf(stderr, "login failed\n"); return 1;
    }
    printf("OK  session=0x%08x", cli.session_id);
    if (cli.have_media_gw) {
        struct in_addr m = { .s_addr = htonl(cli.media_gw_ipv4) };
        printf("  media_gw=%s:%u", inet_ntoa(m), cli.media_gw_port);
    }
    if (cli.have_org && cli.org.count > 0)
        printf("  org=%s/%s", cli.org.entries[0].num, cli.org.entries[0].name);
    printf("\n");
    /* Persist the session token if available. */
    if (cli.last_response_hex[0]) {
        vham_token_t t = { 0 };
        strncpy(t.user, a->user, sizeof t.user - 1);
        strncpy(t.token, cli.last_response_hex, sizeof t.token - 1);
        t.last_reg_unix = (uint64_t)time(NULL);
        vham_token_save(&t);
    }
    close(fd);
    return 0;
}

/* List groups directly from REGRSP — no extra request needed. */
static int cmd_list(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;

    if (cli.have_org && cli.org.count > 0) {
        printf("org: %s  (%s)\n",
               cli.org.entries[0].num, cli.org.entries[0].name);
    }
    if (!cli.have_ginfo || cli.ginfo.count == 0) {
        printf("(no group memberships)\n");
        close(fd); return 0;
    }
    printf("groups (%u):\n", cli.ginfo.count);
    for (uint16_t k = 0; k < cli.ginfo.count; ++k) {
        const vham_ginfo_member_t *m = &cli.ginfo.entries[k];
        const char *type_label =
            m->type == 2 ? "personal" :
            m->type == 7 ? "talk"     :
            m->type == 8 ? "conf"     : "?";
        printf("  %-10s  %-20s  type=%u(%s) prio=%u chan=%u status=%u",
               m->num, m->name, m->type, type_label, m->prio,
               m->chan_num, m->status);
        if (m->ag_num[0]) printf("  ag=%s", m->ag_num);
        if (m->fg_count)  printf("  fg(%u)=%s", m->fg_count, m->fg_num);
        printf("\n");
    }
    close(fd);
    return 0;
}

static int cmd_query(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;

    /* `--group` selects what to ask about; default is our own number. */
    const char *target = a->group ? a->group : a->user;
    uint32_t scope = a->scope ? (uint32_t)a->scope : 100;

    cli.seq_no += 1;
    uint8_t buf[256];
    vham_query_ext_t qe = { .uc_all = 1 };
    int n = vham_build_oam_gqueryu(cli.seq_no, a->user, target,
                                   scope, &qe, buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s) count=%u target=%s scope=%u\n",
                   rsp.op_code, rsp.status,
                   vham_cause_name(rsp.status), rsp.count,
                   target, scope);
            for (uint16_t k = 0; k < rsp.ginfo.count; ++k)
                printf("  %s = %s\n",
                       rsp.ginfo.entries[k].num,
                       rsp.ginfo.entries[k].name);
            break;
        }
    }
    close(fd);
    return 0;
}

static int cmd_join(args_t *a) {
    if (!a->user || !a->pass || !a->group) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_oam_gaddu(cli.seq_no, a->user, a->group, 100,
                                 buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);
    return 0;
}

static int cmd_leave(args_t *a) {
    if (!a->user || !a->pass || !a->group) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_oam_gdelu(cli.seq_no, a->user, a->group, 100,
                                 buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);
    return 0;
}

static int cmd_gadd(args_t *a) {
    if (!a->user || !a->pass || !a->group) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    uint8_t gt = (uint8_t)(a->gtype ? a->gtype : 7);
    int n = vham_build_oam_gadd(cli.seq_no, a->user, a->group,
                                a->name ? a->name : a->group,
                                "", gt, 100, buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);
    return 0;
}

static int cmd_im(args_t *a) {
    if (!a->user || !a->pass || !a->to || !a->text) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    char sn[32]; snprintf(sn, sizeof sn, "vham-cli-%u", cli.seq_no);
    char ts[32]; time_t now = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    vham_im_t im = {
        .code = 1, .ut_sn = cli.seq_no,
        .sn = sn, .time = ts,
        .from = a->user, .to = a->to, .ori_to = a->to,
        .text = a->text,
    };
    uint8_t buf[2048];
    int n = vham_build_im(cli.seq_no, &im, buf, sizeof buf);
    if (n > 0) {
        send(fd, buf, (size_t)n, 0);
        printf("IM sent: %s -> %s : %.40s\n", a->user, a->to, a->text);
    }
    close(fd);
    return 0;
}

static int cmd_gps(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    vham_gps_report_t g = {
        .latitude  = (float)a->lat,
        .longitude = (float)a->lon,
        .timestamp = (uint32_t)time(NULL),
        .satellites = 8, .fix_quality = 1, .batt_pct = 80,
    };
    uint8_t buf[256];
    int n = vham_build_gps_report(cli.seq_no, a->user, &g, buf, sizeof buf);
    if (n > 0) {
        send(fd, buf, (size_t)n, 0);
        printf("GPS sent: %.6f,%.6f\n", a->lat, a->lon);
    }
    close(fd);
    return 0;
}

/* ---------- logout (MM_QUIT) ---------- */
static int cmd_logout(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[128];
    int n = vham_build_mm_quit(cli.seq_no, a->user, buf, sizeof buf);
    if (n > 0) {
        send(fd, buf, (size_t)n, 0);
        printf("logout sent (%d bytes)\n", n);
    }
    vham_token_clear(a->user);
    close(fd);
    return 0;
}

/* ---------- gmodify (OAM op 7) ---------- */
static int cmd_gmodify(args_t *a) {
    if (!a->user || !a->pass || !a->group) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_oam_gmodify(cli.seq_no, a->user, a->group,
                                   a->name ? a->name : a->group,
                                   (uint8_t)(a->prio ? a->prio : 7),
                                   100, buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);
    return 0;
}

/* ---------- gmodifyu (OAM op 11) ---------- */
static int cmd_gmodifyu(args_t *a) {
    if (!a->user || !a->pass || !a->group || !a->to) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_oam_gmodifyu(cli.seq_no, a->user, a->group,
                                    a->to, NULL, 100, buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);
    return 0;
}

/* ---------- call (one-shot CC_SETUP) ---------- */
static int cmd_call(args_t *a) {
    if (!a->user || !a->pass || !a->to) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;

    /* Build SDP describing where we'd receive media. */
    vham_sdp_t s = {
        .origin_ipv4 = 0x7f000001u,
        .media_count = 1,
        .media = {{
            .media_type = 0, .transport = 0,
            .ipv4 = 0x7f000001u, .port = 10001,
            .codec_count = 1,
            .codecs = {{ .payload_type = 0, .encoding_param = 1,
                         .clock_rate = 8000, .name = "PCMU" }},
        }},
    };
    uint8_t sdp[1024];
    int sdp_n = vham_build_sdp_body(&s, sdp, sizeof sdp);
    if (sdp_n <= 0) { close(fd); return 1; }

    vham_cc_call_t call;
    vham_cc_call_init(&call, a->user, a->to, 1);
    uint8_t buf[2048];
    int n = vham_cc_call_emit(&call, sdp, (size_t)sdp_n,
                              VHAM_CALL_HALF_DUPLEX, NULL,
                              cli.last_algorithm, cli.last_nonce,
                              cli.last_realm, cli.last_response_hex,
                              buf, sizeof buf);
    if (n <= 0) { close(fd); return 1; }
    if (send(fd, buf, (size_t)n, 0) != (ssize_t)n) {
        perror("send"); close(fd); return 1;
    }
    printf("CC_SETUP sent (%d bytes) to %s\n", n, a->to);

    /* Watch for ACK + any CC frames for up to wait_sec. */
    int wait_s = a->wait_sec ? a->wait_sec : 5;
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    time_t deadline = time(NULL) + wait_s;
    uint8_t resp[2048];
    int got_ack = 0;
    while (time(NULL) < deadline) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) continue;
        uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
        uint16_t cmd   = (uint16_t)((resp[10] << 8) | resp[11]);
        if (flags == VHAM_TAP_FLAG_ACK) { got_ack = 1; printf("server TAP-ACK\n"); continue; }
        if (cmd == VHAM_CC_SETUPACK) { printf("CC_SETUPACK\n"); }
        else if (cmd == VHAM_CC_ALERT)   { printf("CC_ALERT\n"); }
        else if (cmd == VHAM_CC_CONN)    { printf("CC_CONN (call connected)\n"); break; }
        else if (cmd == VHAM_CC_REL)     {
            vham_cc_call_recv(&call, resp, (size_t)r);
            printf("CC_REL cause=0x%x (%s)\n",
                   call.last_cause, vham_cause_name((uint16_t)call.last_cause));
            break;
        }
    }
    if (!got_ack) printf("(no server ACK within %ds)\n", wait_s);
    close(fd);
    return 0;
}

/* ---------- listen (wait briefly for an incoming call) ---------- */
static int cmd_listen(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;

    /* Subscribe to "###" plus optionally an explicit channel. */
    const char *targets[2] = { "###", a->tune };
    size_t n_t = a->tune ? 2 : 1;
    for (size_t i = 0; i < n_t; ++i) {
        cli.seq_no += 1;
        uint8_t sb[256];
        int sn = vham_build_status_subs(cli.seq_no, a->user, targets[i],
                                        VHAM_SUBS_DETAILED, 1, sb, sizeof sb);
        if (sn > 0) send(fd, sb, (size_t)sn, 0);
    }
    printf("listening as %s on %s%s for %ds...\n",
           a->user, a->tune ? "channel " : "###",
           a->tune ? a->tune : "", a->wait_sec ? a->wait_sec : 30);

    int wait_s = a->wait_sec ? a->wait_sec : 30;
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    time_t deadline = time(NULL) + wait_s;
    uint8_t resp[2048];
    while (time(NULL) < deadline) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) continue;
        uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
        if (flags == VHAM_TAP_FLAG_ACK) continue;
        uint16_t cls = (uint16_t)((resp[8] << 8) | resp[9]);
        uint16_t cmd = (uint16_t)((resp[10] << 8) | resp[11]);

        if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_REGRSP) {
            vham_mm_notify_t n;
            if (vham_parse_mm_notify(resp, (size_t)r, &n) == 0 && n.have_notify) {
                printf("notify: sub=0x%04x status=0x%02x for=%s\n",
                       n.sub_opcode, n.notify_status, n.echoed_num);
            }
        } else if (cls == VHAM_TAP_CLASS_CC && cmd == VHAM_CC_SETUP) {
            printf("incoming CC_SETUP\n");
        } else if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_PASSTHROUGH) {
            vham_passthrough_t p;
            if (vham_parse_passthrough(resp, (size_t)r, &p) == 0)
                printf("passthrough code=0x%x from=%s\n",
                       p.code, p.have_src ? p.src_num : "?");
        } else {
            printf("rx cls=0x%04x cmd=0x%04x len=%zd\n", cls, cmd, r);
        }
    }
    close(fd);
    return 0;
}

/* ---------- passthrough (raw MM_PASSTHROUGH) ---------- */
static int cmd_passthrough(args_t *a) {
    if (!a->user || !a->pass || !a->to) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    char sn[24]; snprintf(sn, sizeof sn, "cli-%u", cli.seq_no);
    char ts[24]; time_t now = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    vham_passthrough_event_t ev = {
        .code  = (uint8_t)(a->code ? a->code : 1),
        .type  = (uint32_t)a->type,
        .ut_sn = cli.seq_no,
        .sn = sn, .time = ts,
        .data = (const uint8_t *)(a->data ? a->data : ""),
        .data_len = (uint16_t)(a->data ? strlen(a->data) : 0),
    };
    uint8_t buf[2048];
    int n = vham_build_passthrough(cli.seq_no, a->user, a->to, &ev,
                                   NULL, buf, sizeof buf);
    if (n > 0) {
        send(fd, buf, (size_t)n, 0);
        printf("passthrough sent (%d bytes) code=%u type=0x%x\n",
               n, ev.code, ev.type);
    }
    close(fd);
    return 0;
}

/* ---------- talkgroup — create type=7 talk-group + self-join ----------
 *
 * Bundles `gadd --gtype 7` + `join`. Verifies the resulting type
 * actually came back as 7 (talk-group, routable) — server admin
 * policy means non-admins will see type=2 (personal, not routable)
 * regardless of what we asked for. */
static int cmd_talkgroup(args_t *a) {
    if (!a->user || !a->pass || !a->group) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;

    /* GAdd with type=7 (talk-group). */
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_oam_gadd(cli.seq_no, a->user, a->group,
                                a->name ? a->name : a->group,
                                "vham-cli talkgroup", 7, 100,
                                buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    uint8_t resp[2048];
    int gadd_status = -1;
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("gadd op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            gadd_status = rsp.status;
            break;
        }
    }
    if (gadd_status != 0) { close(fd); return 1; }

    /* GAddU to join. */
    cli.seq_no += 1;
    n = vham_build_oam_gaddu(cli.seq_no, a->user, a->group, 100,
                             buf, sizeof buf);
    if (n > 0) send(fd, buf, (size_t)n, 0);
    for (int g = 0; g < 4; ++g) {
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) break;
        if ((resp[2] << 8 | resp[3]) == VHAM_TAP_FLAG_ACK) continue;
        vham_oam_rsp_t rsp;
        if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
            printf("join op=0x%x status=0x%04x (%s)\n",
                   rsp.op_code, rsp.status, vham_cause_name(rsp.status));
            break;
        }
    }
    close(fd);

    /* Re-login to see what type the server actually stored. */
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    if (cli.have_ginfo) {
        for (uint16_t k = 0; k < cli.ginfo.count; ++k) {
            const vham_ginfo_member_t *m = &cli.ginfo.entries[k];
            if (!strcmp(m->num, a->group)) {
                const char *label =
                    m->type == 7 ? "talk-group (routes calls)" :
                    m->type == 2 ? "personal (DOES NOT route — admin gate)" :
                                   "unknown";
                printf("\nresult: group %s -> type=%u  %s\n",
                       m->num, m->type, label);
                break;
            }
        }
    }
    close(fd);
    return 0;
}

/* ---------- mm <op> — generic MM op sender ---------- */
static int cmd_mm(args_t *a, const char *op) {
    if (!a->user || !a->pass || !op) return usage();
    uint16_t wmsg = 0;
    if      (!strcmp(op, "profreq"))   wmsg = VHAM_MM_PROFREQ;
    else if (!strcmp(op, "modreq"))    wmsg = VHAM_MM_MODREQ;
    else if (!strcmp(op, "routereq"))  wmsg = VHAM_MM_ROUTEREQ;
    else if (!strcmp(op, "accreq"))    wmsg = VHAM_MM_ACCREQ;
    else if (!strcmp(op, "nattprob"))  wmsg = VHAM_MM_NATT_PROB;
    else if (!strcmp(op, "quit"))      wmsg = VHAM_MM_QUIT;
    else { fprintf(stderr, "unknown mm op: %s\n", op); return 2; }

    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int fd;
    if (do_login(a->user, a->pass, ip_be, port, &fd, &cli) != 0) return 1;
    cli.seq_no += 1;
    uint8_t buf[256];
    int n = vham_build_mm_simple(wmsg, cli.seq_no, a->user, NULL, NULL,
                                 buf, sizeof buf);
    if (n > 0) {
        send(fd, buf, (size_t)n, 0);
        printf("MM_%s (0x%04x) sent (%d bytes)\n", op, wmsg, n);
        /* Drain any immediate response. */
        struct timeval tv = { .tv_sec = 2 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        uint8_t resp[2048];
        for (int g = 0; g < 3; ++g) {
            ssize_t r = recv(fd, resp, sizeof resp, 0);
            if (r < 0) break;
            uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
            uint16_t cmd   = (uint16_t)((resp[10] << 8) | resp[11]);
            if (flags == VHAM_TAP_FLAG_ACK) {
                printf("  TAP-ACK (cmd=0x%04x)\n", cmd);
            } else {
                printf("  <- cmd=0x%04x len=%zd\n", cmd, r);
            }
        }
    }
    close(fd);
    return 0;
}

/* ---------- token show / clear ---------- */
static int cmd_token(args_t *a, const char *action) {
    if (!a->user) return usage();
    if (!strcmp(action, "clear")) {
        int rc = vham_token_clear(a->user);
        printf("token clear: %s\n", rc == 0 ? "ok" : "not present");
        return rc == 0 ? 0 : 1;
    }
    /* default: show */
    vham_token_t t;
    if (vham_token_load(a->user, &t) != 0) {
        printf("no token cached for %s\n", a->user);
        return 1;
    }
    printf("user=%s\ntoken=%s\nyaoyun=%s\nlast_reg=%llu\n",
           t.user, t.token, t.yaoyun,
           (unsigned long long)t.last_reg_unix);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *sub = argv[1];
    const char *token_action = "show";
    const char *mm_op = NULL;

    /* `vham-cli token show|clear ...` and `vham-cli mm <op> ...` have
     * a positional action at argv[2]. Lift it out before parse_args(). */
    if (!strcmp(sub, "token") && argc >= 3 &&
        (!strcmp(argv[2], "show") || !strcmp(argv[2], "clear"))) {
        token_action = argv[2];
        for (int i = 2; i + 1 < argc; ++i) argv[i] = argv[i + 1];
        argc--;
    } else if (!strcmp(sub, "mm") && argc >= 3 && argv[2][0] != '-') {
        mm_op = argv[2];
        for (int i = 2; i + 1 < argc; ++i) argv[i] = argv[i + 1];
        argc--;
    }

    args_t a;
    if (parse_args(argc, argv, &a) != 0) return usage();
    if (!strcmp(sub, "login")) return cmd_login(&a);
    if (!strcmp(sub, "list"))  return cmd_list(&a);
    if (!strcmp(sub, "query")) return cmd_query(&a);
    if (!strcmp(sub, "join"))     return cmd_join(&a);
    if (!strcmp(sub, "leave"))    return cmd_leave(&a);
    if (!strcmp(sub, "gadd"))     return cmd_gadd(&a);
    if (!strcmp(sub, "talkgroup")) return cmd_talkgroup(&a);
    if (!strcmp(sub, "gmodify"))  return cmd_gmodify(&a);
    if (!strcmp(sub, "gmodifyu")) return cmd_gmodifyu(&a);
    if (!strcmp(sub, "logout"))   return cmd_logout(&a);
    if (!strcmp(sub, "call"))     return cmd_call(&a);
    if (!strcmp(sub, "listen"))   return cmd_listen(&a);
    if (!strcmp(sub, "passthrough")) return cmd_passthrough(&a);
    if (!strcmp(sub, "token"))    return cmd_token(&a, token_action);
    if (!strcmp(sub, "mm"))       return cmd_mm(&a, mm_op);
    if (!strcmp(sub, "im"))    return cmd_im(&a);
    if (!strcmp(sub, "gps"))   return cmd_gps(&a);
    return usage();
}
