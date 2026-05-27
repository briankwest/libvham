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
#include "vham/codec_audio.h"
#include "vham/gps.h"
#include "vham/im.h"
#include "vham/oam.h"
#include "vham/causes.h"
#include "vham/envcfg.h"
#include "vham/nat.h"
#include "vham/passthrough.h"
#include "vham/regreq.h"
#include "vham/regrsp.h"
#include "vham/rtp.h"
#include "vham/sdp.h"
#include "vham/voice.h"
#include "vham/voice_call.h"
#include <math.h>
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
"  vham-cli transmit --user U --pass P --to CHANNEL [--tone HZ] [--file PCM]\n"
"                                                   [--seconds N] [--codec pcmu|pcma]\n"
"                                                   [--rtp-port LOCAL_PORT]\n"
"                                  SETUP a call, then pump RTP. --file expects\n"
"                                  raw 16-bit signed-PCM @ 8 kHz mono.\n"
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
    /* transmit subcommand */
    int         tone_hz;
    int         seconds;
    const char *file;
    const char *codec;
    int         rtp_port;     /* override local RTP port (for port-fwd) */
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
        else if (!strcmp(k, "--tone")   && v) { a->tone_hz = atoi(v); i++; }
        else if (!strcmp(k, "--seconds") && v) { a->seconds = atoi(v); i++; }
        else if (!strcmp(k, "--file")   && v) { a->file   = v; i++; }
        else if (!strcmp(k, "--codec")  && v) { a->codec  = v; i++; }
        else if (!strcmp(k, "--text")   && v) { a->text   = v; i++; }
        else if (!strcmp(k, "--tune")   && v) { a->tune   = v; i++; }
        else if (!strcmp(k, "--lat")    && v) { a->lat = atof(v); i++; }
        else if (!strcmp(k, "--lon")    && v) { a->lon = atof(v); i++; }
        else if (!strcmp(k, "--rtp-port") && v) { a->rtp_port = atoi(v); i++; }
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

/* ---------- transmit (login → tune → SETUP → pump RTP) ----------
 *
 * Bundles every step needed to push audio onto a PoC channel:
 *   1. Login (gets media_gw from REGRSP).
 *   2. STATUSSUBS the channel — server marks us as a participant.
 *   3. Open a UDP socket on a local RTP port we'll advertise.
 *   4. Send CC_SETUP with an SDP pointing at that local port.
 *   5. Watch for ACK + CC_CONN; on CC_INFO mic-grant (sub 0x83), start
 *      pumping RTP frames at 50 fps (20ms PCMU/PCMA) toward media_gw.
 *   6. After `--seconds` of audio (tone or file), send CC_REL.
 */
static int load_pcm_file(const char *path, int16_t **out, size_t *count) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz % 2) { fclose(f); return -1; }
    int16_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out = buf;
    *count = (size_t)sz / 2;
    return 0;
}

static int cmd_transmit(args_t *a) {
    if (!a->user || !a->pass || !a->to) return usage();
    if (!a->tone_hz && !a->file) {
        fprintf(stderr, "transmit: need --tone HZ or --file PATH\n");
        return 2;
    }
    const char *codec_name = a->codec ? a->codec : "pcmu";
    uint8_t pt;
    int samples_per_frame = 160;  /* 20 ms */
    uint32_t clock_rate = 8000;
    /* PTs match vham.net's SdpFillPtParam codec table. */
    if      (!strcmp(codec_name, "pcmu"))   { pt = 0;  }
    else if (!strcmp(codec_name, "pcma"))   { pt = 8;  }
    else if (!strcmp(codec_name, "amr"))    { pt = 97;  }
    else if (!strcmp(codec_name, "amr-wb")) {
        pt = 107; samples_per_frame = 320; clock_rate = 16000;
    }
    else if (!strcmp(codec_name, "ilbc"))   {
        /* idt.ini [RTP_AUDIO_0] CODE=106 PKGTIME=60 — 60 ms = 3 × 20 ms
         * iLBC frames per RTP packet, payload 114 bytes. */
        pt = 106; samples_per_frame = 480;
    }
    else if (!strcmp(codec_name, "opus"))   {
        pt = 109; samples_per_frame = 960; clock_rate = 48000;
    }
    else {
        fprintf(stderr, "transmit: --codec must be pcmu/pcma/amr/amr-wb/ilbc/opus\n");
        return 2;
    }
    int seconds = a->seconds ? a->seconds : 5;
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();

    /* Wall-clock telemetry — emits when VHAM_TIMING=1. */
    struct timeval t_start, t_phase;
    gettimeofday(&t_start, NULL); t_phase = t_start;
    const char *_timing_env = getenv("VHAM_TIMING");
    int _timing_on = _timing_env && *_timing_env != '0';
    #define VHAM_PHASE(label) do {                                          \
        if (!_timing_on) break;                                             \
        struct timeval _now; gettimeofday(&_now, NULL);                     \
        long _ms = (_now.tv_sec - t_phase.tv_sec) * 1000                    \
                 + (_now.tv_usec - t_phase.tv_usec) / 1000;                 \
        long _total = (_now.tv_sec - t_start.tv_sec) * 1000                 \
                    + (_now.tv_usec - t_start.tv_usec) / 1000;              \
        fprintf(stderr, "[t+%ldms] %s (+%ldms)\n", _total, (label), _ms);  \
        t_phase = _now;                                                     \
    } while (0)

    vham_reg_client_t cli; int sig_fd;
    if (do_login(a->user, a->pass, ip_be, port, &sig_fd, &cli) != 0) return 1;
    VHAM_PHASE("login complete");
    if (!cli.have_media_gw) {
        fprintf(stderr, "transmit: REGRSP didn't include a media gateway\n");
        close(sig_fd); return 1;
    }
    printf("media gateway: %u.%u.%u.%u:%u\n",
           (cli.media_gw_ipv4 >> 24) & 0xff,
           (cli.media_gw_ipv4 >> 16) & 0xff,
           (cli.media_gw_ipv4 >> 8) & 0xff,
           (cli.media_gw_ipv4) & 0xff,
           cli.media_gw_port);

    /* Pipeline STATUSSUBS + opportunistic YaoYun handling — fire the
     * STATUSSUBS immediately so the server can process it concurrently
     * with whatever it queued post-REGRSP, then drain everything in a
     * single 150 ms pass. */
    cli.seq_no += 1;
    uint8_t sb[256];
    int sn = vham_build_status_subs(cli.seq_no, a->user, a->to,
                                    VHAM_SUBS_DETAILED, 1, sb, sizeof sb);
    if (sn > 0) send(sig_fd, sb, (size_t)sn, 0);

    /* Drain whatever arrives: YaoYun (MM_PASSTHROUGH), STATUSSUBS
     * TAP-ACKs, MM_REGRSP notifies. 50 ms is enough — YaoYun is
     * server-pushed within an RTT of REGRSP or never. */
    {
        struct timeval drain_tv = { .tv_usec = 50 * 1000 };
        setsockopt(sig_fd, SOL_SOCKET, SO_RCVTIMEO, &drain_tv, sizeof drain_tv);
    }
    uint8_t resp[2048];
    for (int g = 0; g < 8; ++g) {
        ssize_t r = recv(sig_fd, resp, sizeof resp, 0);
        if (r <= 0) break;
        uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
        uint16_t cls   = (uint16_t)((resp[8]  << 8) | resp[9]);
        uint16_t cmd   = (uint16_t)((resp[10] << 8) | resp[11]);
        if (flags == VHAM_TAP_FLAG_ACK) continue;
        if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_PASSTHROUGH) {
            vham_passthrough_t p;
            if (vham_parse_passthrough(resp, (size_t)r, &p) == 0) {
                int yy = vham_passthrough_yaoyun_value(&p);
                if (yy >= 0) {
                    printf("[yy] received YaoYun=%d — acking\n", yy);
                    uint8_t ack[256];
                    cli.seq_no += 1;
                    int an = vham_build_yaoyun_ack(cli.seq_no, a->user,
                                                   p.have_src ? p.src_num : "",
                                                   "YaoYun", yy,
                                                   ack, sizeof ack);
                    if (an > 0) send(sig_fd, ack, (size_t)an, 0);
                }
            }
        }
    }
    VHAM_PHASE("pre-call drained");

    /* Compute call mode early so the RTP-socket bind can use the
     * correct deterministic port (MEDPORT + leg_id * 4 per idt.ini).
     *
     * leg_id is the SRVMSG.dwSrcFsmId. The binary calls PResItem::
     * GetId() to allocate a unique short — radio's was 891 (0x37b).
     * Pick a random short to avoid colliding with a previous
     * session's leg (server may dedup CC_SETUPs by (src,leg)). */
    int peer_numeric = 1;
    for (const char *pp = a->to; *pp; ++pp)
        if (*pp < '0' || *pp > '9') { peer_numeric = 0; break; }
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    uint32_t leg_id = (uint32_t)(rand() % 800 + 100);   /* 100..899 */
    /* com.ids.idtma.media.CSAudio uses SrvType=17 (HALF_DUPLEX) for
     * BOTH channel/group calls AND user-to-user calls. The Java IMType
     * string ("GROUP" vs "HALFSINGLE") is what selects channel vs
     * single-call IE semantics, not SrvType. */
    uint32_t srv_type = VHAM_CALL_HALF_DUPLEX;
    const char *subcode = peer_numeric ? a->to : NULL;

    /* The library's voice_call orchestrator does Steps 2–4 for us:
     * RTP socket bind, STUN, CC_SETUP, recv loop, CC_CONNACK,
     * mic-claim triplet, NAT sentinel, NAT-punch. */
    printf("call mode: %s  (leg=%u  srvType=0x%x  subcode=%s)\n",
           peer_numeric ? "channel/group" : "user-to-user",
           leg_id, srv_type,
           (peer_numeric ? a->to : "<none>"));
    if (a->rtp_port > 0) {
        printf("[rtp] using --rtp-port override: %u\n", a->rtp_port);
    }
    vham_voice_call_t vc;
    vham_voice_call_opts_t vcopts = {
        .sig_fd            = sig_fd,
        .my_num            = a->user,
        .peer_num          = a->to,
        .is_channel_call   = peer_numeric,
        .channel_subcode   = peer_numeric ? a->to : NULL,
        .leg_id            = leg_id,
        .seq_no            = &cli.seq_no,
        .auth_algorithm    = cli.last_algorithm,
        .auth_nonce        = cli.last_nonce,
        .auth_realm        = cli.last_realm,
        .auth_response     = cli.last_response_hex,
        .media_gw_ipv4     = cli.media_gw_ipv4,
        .media_gw_port     = cli.media_gw_port,
        .payload_type      = pt,
        .samples_per_frame = samples_per_frame,
        .clock_rate        = clock_rate,
        .rtp_port_override = (uint16_t)a->rtp_port,
    };
    (void)srv_type; (void)subcode;
    if (vham_voice_call_setup(&vc, &vcopts) != 0) {
        fprintf(stderr, "voice_call_setup failed\n");
        close(sig_fd); return 1;
    }
    VHAM_PHASE("voice_call_setup complete");
    printf("local RTP port: %u\n", vham_voice_call_rtp_port(&vc));
    if (vc.pub_ip) {
        printf("[stun] our public RTP endpoint: %u.%u.%u.%u:%u\n",
               (vc.pub_ip >> 24)&0xff, (vc.pub_ip >> 16)&0xff,
               (vc.pub_ip >>  8)&0xff,  vc.pub_ip      &0xff,
               vc.pub_port);
    }
    printf("[cc] CONNACK + mic-claim triplet sent; per-call port %u\n",
           vc.call.remote_media_port);


    /* Step 5 — prepare audio source. */
    int16_t *src_pcm = NULL;
    size_t   src_n = 0;
    if (a->file) {
        if (load_pcm_file(a->file, &src_pcm, &src_n) != 0) {
            fprintf(stderr, "transmit: can't load %s\n", a->file);
            vham_voice_call_release(&vc, 0x10); close(sig_fd); return 1;
        }
        printf("loaded %zu PCM samples (%.2fs @ 8kHz) from %s\n",
               src_n, (double)src_n / 8000.0, a->file);
    } else {
        src_n = (size_t)seconds * clock_rate;
        src_pcm = malloc(src_n * sizeof *src_pcm);
        if (!src_pcm) {
            vham_voice_call_release(&vc, 0x10); close(sig_fd); return 1;
        }
        for (size_t i = 0; i < src_n; ++i)
            src_pcm[i] = (int16_t)(0.5 * 32767.0 *
                          sin(2.0 * M_PI * a->tone_hz
                              * (double)i / (double)clock_rate));
        printf("generated %d-sec %dHz tone (%zu samples @ %u Hz)\n",
               seconds, a->tone_hz, src_n, clock_rate);
    }

    /* Step 6 — pump audio: one frame per pump_frame() call. The
     * orchestrator handles RTP framing, sendto, NAT-sentinel tick,
     * and inbound signaling drain (auto-ACK + CC_MODIFY redirect). */
    size_t frames  = src_n / (size_t)samples_per_frame;
    size_t sent_ok = 0;
    struct timeval frame_t;
    gettimeofday(&frame_t, NULL);
    uint64_t next_us = (uint64_t)frame_t.tv_sec * 1000000 + frame_t.tv_usec;
    for (size_t i = 0; i < frames; ++i) {
        int rc = vham_voice_call_pump_frame(&vc,
                                            src_pcm + i * samples_per_frame,
                                            (size_t)samples_per_frame,
                                            i == 0 ? 1 : 0);
        if (rc < 0) {
            fprintf(stderr, "pump_frame failed at i=%zu\n", i);
            break;
        }
        if (rc == 0) {
            printf("server CC_REL during TX — stopping\n");
            break;
        }
        sent_ok++;
        /* Pace one packet per frame_samples duration. iLBC = 60 ms,
         * everything else = 20 ms. */
        next_us += (uint64_t)samples_per_frame * 1000000 / clock_rate;
        struct timeval now;
        gettimeofday(&now, NULL);
        uint64_t now_us = (uint64_t)now.tv_sec * 1000000 + now.tv_usec;
        if (next_us > now_us) usleep((useconds_t)(next_us - now_us));
    }
    free(src_pcm);
    printf("sent %zu/%zu RTP frames\n", sent_ok, frames);

    /* Step 7 — release the call (CC_REL + close RTP socket). */
    vham_voice_call_release(&vc, 0x0000);
    close(sig_fd);
    return 0;
}

/* Build a CC_CONN frame to auto-answer an incoming CC_SETUP.
 *
 * The server sent us a CC_SETUP (class=3, cmd=0x50) with its own
 * dwSrcFsmId in the SRVMSG. We echo that as our dwDstFsmId so the
 * server can correlate the answer with the call leg.
 *
 * Mirrors CCFsm::UserAnswer @ 0x2efa6c. */
static int build_cc_conn_answer(const uint8_t *setup, size_t setup_len,
                                uint32_t our_leg,
                                const uint8_t *sdp, size_t sdp_len,
                                uint8_t *out, size_t out_cap) {
    if (setup_len < 32 || !out) return -1;

    /* Pull server's leg from the SETUP's SRVMSG.dwSrcFsmId (bytes 24..27). */
    uint32_t server_leg = ((uint32_t)setup[24] << 24) | ((uint32_t)setup[25] << 16)
                        | ((uint32_t)setup[26] <<  8) | (uint32_t)setup[27];
    /* And echo their TAP seq number. */
    uint32_t seq = ((uint32_t)setup[4] << 24) | ((uint32_t)setup[5] << 16)
                 | ((uint32_t)setup[6] <<  8) | (uint32_t)setup[7];

    vham_buf_t b;
    vham_buf_init(&b, out, out_cap);

    /* TAP header */
    if (vham_pack_u8 (&b, 0x01)) return -1;
    if (vham_pack_u8 (&b, 0x00)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL)) return -1;
    if (vham_pack_u32(&b, seq + 1)) return -1;
    if (vham_pack_u16(&b, VHAM_TAP_CLASS_CC)) return -1;
    if (vham_pack_u16(&b, VHAM_CC_CONN)) return -1;
    size_t tap_len_off = b.off;
    if (vham_pack_u32(&b, 0)) return -1;
    size_t body_start = b.off;

    /* SRVMSG header: dwDstFsmId = server's leg, dwSrcFsmId = ours */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_CC_CONN,
        .dwDstFsmId = server_leg,
        .dwSrcFsmId = our_leg,
    };
    size_t srv_len_off;
    if (vham_pack_srvmsg_header(&b, &sh, &srv_len_off)) return -1;
    size_t srv_body_start = b.off;

    /* IE 0x19 (SDP body). */
    if (sdp && sdp_len > 0) {
        if (vham_pack_u16(&b, 0x0019)) return -1;
        if (vham_pack_u16(&b, (uint16_t)sdp_len)) return -1;
        for (size_t i = 0; i < sdp_len; ++i)
            if (vham_pack_u8(&b, sdp[i])) return -1;
    }

    if (vham_patch_srvmsg_len(&b, srv_len_off, srv_body_start)) return -1;
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >>  8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);
    if (b.err) return -1;
    return (int)b.off;
}

/* ---------- listen (wait briefly for an incoming call) ---------- */
static int cmd_listen(args_t *a) {
    if (!a->user || !a->pass) return usage();
    uint32_t ip_be; uint16_t port;
    if (parse_server(a->server, &ip_be, &port) != 0) return usage();
    vham_reg_client_t cli; int sig_fd;
    if (do_login(a->user, a->pass, ip_be, port, &sig_fd, &cli) != 0) return 1;

    /* Open an RTP socket so we can count incoming media. */
    int rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in lo = { .sin_family = AF_INET, .sin_port = 0,
                              .sin_addr = { .s_addr = htonl(INADDR_ANY) } };
    bind(rtp_fd, (struct sockaddr *)&lo, sizeof lo);
    socklen_t llen = sizeof lo;
    getsockname(rtp_fd, (struct sockaddr *)&lo, &llen);
    uint16_t rtp_port = ntohs(lo.sin_port);
    /* Discover our PUBLIC IP. The server sees us via NAT, so the
     * SDP needs the post-NAT address. Use ifconfig.me as a STUN-ish
     * fallback (LinkPoon's client uses something similar internally). */
    uint32_t local_ip_host = 0;
    {
        FILE *p = popen("curl -s --max-time 4 -4 https://ifconfig.me 2>/dev/null", "r");
        if (p) {
            char ipstr[64] = {0};
            if (fgets(ipstr, sizeof ipstr, p)) {
                struct in_addr a;
                if (inet_aton(ipstr, &a))
                    local_ip_host = ntohl(a.s_addr);
            }
            pclose(p);
        }
        if (local_ip_host == 0) {
            /* Fallback: outbound interface IP (LAN). */
            int probe = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in srv = { .sin_family = AF_INET,
                .sin_port = htons(port), .sin_addr.s_addr = ip_be };
            if (connect(probe, (struct sockaddr *)&srv, sizeof srv) == 0) {
                struct sockaddr_in me; socklen_t ml = sizeof me;
                if (getsockname(probe, (struct sockaddr *)&me, &ml) == 0)
                    local_ip_host = ntohl(me.sin_addr.s_addr);
            }
            close(probe);
        }
    }
    printf("listening on RTP port %u  (advertising IP %u.%u.%u.%u)\n",
           rtp_port,
           (local_ip_host >> 24) & 0xff, (local_ip_host >> 16) & 0xff,
           (local_ip_host >>  8) & 0xff,  local_ip_host        & 0xff);

    /* Subscribe to "###" plus optionally an explicit channel. */
    const char *targets[2] = { "###", a->tune };
    size_t n_t = a->tune ? 2 : 1;
    for (size_t i = 0; i < n_t; ++i) {
        cli.seq_no += 1;
        uint8_t sb[256];
        int sn = vham_build_status_subs(cli.seq_no, a->user, targets[i],
                                        VHAM_SUBS_DETAILED, 1, sb, sizeof sb);
        if (sn > 0) send(sig_fd, sb, (size_t)sn, 0);
    }
    printf("listening as %s on %s%s for %ds...\n",
           a->user, a->tune ? "channel " : "###",
           a->tune ? a->tune : "", a->wait_sec ? a->wait_sec : 30);

    int wait_s = a->wait_sec ? a->wait_sec : 30;
    struct timeval sig_tv = { .tv_usec = 100*1000 };   /* 100 ms */
    setsockopt(sig_fd, SOL_SOCKET, SO_RCVTIMEO, &sig_tv, sizeof sig_tv);
    setsockopt(rtp_fd, SOL_SOCKET, SO_RCVTIMEO, &sig_tv, sizeof sig_tv);
    time_t deadline = time(NULL) + wait_s;
    uint8_t resp[2048];
    int rtp_rx_count = 0;
    vham_cc_call_t call;
    vham_cc_call_init(&call, a->user, "", 0);
    int answered = 0;
    time_t last_keepalive = 0;
    uint16_t ka_seq = 0;
    while (time(NULL) < deadline) {
        /* Periodic NAT-punch keepalive to media gateway (every 5s). */
        if (cli.have_media_gw && time(NULL) - last_keepalive >= 5) {
            last_keepalive = time(NULL);
            struct sockaddr_in mg = { .sin_family = AF_INET,
                .sin_port = htons(cli.media_gw_port),
                .sin_addr = { .s_addr = htonl(cli.media_gw_ipv4) } };
            uint8_t ka[172];
            memset(ka, 0xff, sizeof ka);
            ka[0] = 0x80; ka[1] = 0;
            ka[2] = (uint8_t)(ka_seq >> 8); ka[3] = (uint8_t)ka_seq; ka_seq++;
            ka[4] = ka[5] = ka[6] = ka[7] = 0;
            ka[8] = ka[9] = ka[10] = 0; ka[11] = 0x01;
            sendto(rtp_fd, ka, sizeof ka, 0, (struct sockaddr *)&mg, sizeof mg);
        }
        /* Poll RTP socket first — accumulate audio packets. */
        ssize_t rr = recv(rtp_fd, resp, sizeof resp, MSG_DONTWAIT);
        if (rr > 12) {
            rtp_rx_count++;
            if (rtp_rx_count == 1) {
                uint8_t pt = resp[1] & 0x7f;
                uint16_t seq = (uint16_t)((resp[2] << 8) | resp[3]);
                printf("[rtp] FIRST PACKET pt=%u seq=%u len=%zd\n",
                       pt, seq, rr);
                /* Dump payload bytes — useful for reverse-engineering
                 * the wire format the radio actually uses. */
                printf("[rtp] payload (%zd bytes):", rr - 12);
                for (ssize_t i = 12; i < rr; ++i) printf(" %02x", resp[i]);
                printf("\n");
            } else if (rtp_rx_count <= 5) {
                /* dump first few packets to see if framing is stable */
                printf("[rtp] pkt %d payload (%zd):", rtp_rx_count, rr - 12);
                for (ssize_t i = 12; i < rr; ++i) printf(" %02x", resp[i]);
                printf("\n");
            } else if (rtp_rx_count % 50 == 0) {
                printf("[rtp] received %d packets so far\n", rtp_rx_count);
            }
        }

        /* Then signaling. */
        ssize_t r = recv(sig_fd, resp, sizeof resp, 0);
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
            /* Hex-dump the entire frame for comparison with our TX. */
            printf("[cc] RAW inbound SETUP (%zd bytes):\n", r);
            for (ssize_t i = 0; i < r; ++i) {
                if (i % 16 == 0) printf("  %04zx: ", i);
                printf("%02x ", resp[i]);
                if (i % 16 == 15 || i == r - 1) printf("\n");
            }
            /* Walk IEs in the SETUP body to find IE 0x19 (SDP). The
             * server's SDP tells us where the PER-CALL media gateway
             * port is (different from the REGRSP media_gw_port). */
            uint32_t peer_ip   = 0;
            uint16_t peer_port = 0;
            uint8_t  peer_pt   = 0;
            const uint8_t *body = resp + 32;
            size_t blen = (size_t)r - 32;
            size_t off = 0;
            while (off + 4 <= blen) {
                uint16_t tag = (uint16_t)((body[off] << 8) | body[off+1]);
                uint16_t len = (uint16_t)((body[off+2] << 8) | body[off+3]);
                if (off + 4 + len > blen) break;
                if (tag == 0x0019) {
                    vham_sdp_t p;
                    if (vham_parse_sdp_body(body + off + 4, len, &p) == 0
                        && p.media_count > 0) {
                        peer_ip   = p.media[0].ipv4;
                        peer_port = p.media[0].port;
                        if (p.media[0].codec_count > 0)
                            peer_pt = p.media[0].codecs[0].payload_type;
                        printf("[cc] incoming SETUP — peer media %u.%u.%u.%u:%u pt=%u\n",
                               (peer_ip >> 24)&0xff, (peer_ip >> 16)&0xff,
                               (peer_ip >>  8)&0xff,  peer_ip       &0xff,
                               peer_port, peer_pt);
                    }
                }
                off += 4 + len;
            }
            printf("[cc] answering with CC_CONN\n");
            /* NAT-punch the PER-CALL port we just learned about. */
            if (peer_ip && peer_port) {
                struct sockaddr_in dst = { .sin_family = AF_INET,
                    .sin_port = htons(peer_port),
                    .sin_addr = { .s_addr = htonl(peer_ip) } };
                uint8_t silence[172];
                memset(silence, 0xff, sizeof silence);
                silence[0] = 0x80; silence[1] = peer_pt ? peer_pt : 0;
                for (int k = 0; k < 5; ++k) {
                    silence[3] = (uint8_t)k;
                    sendto(rtp_fd, silence, sizeof silence, 0,
                           (struct sockaddr *)&dst, sizeof dst);
                    usleep(20*1000);
                }
                printf("[rtp] punched per-call %u.%u.%u.%u:%u pt=%u\n",
                       (peer_ip >> 24)&0xff, (peer_ip >> 16)&0xff,
                       (peer_ip >>  8)&0xff,  peer_ip       &0xff,
                       peer_port, peer_pt);
                /* Remember for the keepalive loop */
                cli.media_gw_ipv4 = peer_ip;
                cli.media_gw_port = peer_port;
            }
            /* Build a tiny SDP advertising our rtp_port for RX. */
            vham_sdp_t s = {
                .origin_ipv4 = local_ip_host,
                .origin_port = rtp_port,
                .media_count = 1,
                .media = {{ .media_type = 0, .transport = 0,
                            .ipv4 = local_ip_host, .port = rtp_port,
                            .codec_count = 1,
                            .codecs = {{ .payload_type = 0,
                                         .encoding_param = 1,
                                         .clock_rate = 8000 }} }} };
            snprintf(s.media[0].codecs[0].name,
                     sizeof s.media[0].codecs[0].name, "PCMU");
            uint8_t sdp[512];
            int sdp_n = vham_build_sdp_body(&s, sdp, sizeof sdp);
            if (sdp_n > 0) {
                uint8_t conn[2048];
                /* Use leg=7 for user-to-user, 9 for group. We default to 7
                 * since the listener typically answers user-to-user calls. */
                int cn = build_cc_conn_answer(resp, (size_t)r, 7,
                                              sdp, (size_t)sdp_n,
                                              conn, sizeof conn);
                if (cn > 0) {
                    send(sig_fd, conn, (size_t)cn, 0);
                    printf("[cc] CC_CONN sent (%d bytes)\n", cn);
                    /* Start NAT-punching the media gateway so RTP can
                     * reach us — send 5 silence frames. */
                    if (cli.have_media_gw) {
                        struct sockaddr_in mg = { .sin_family = AF_INET,
                            .sin_port = htons(cli.media_gw_port),
                            .sin_addr = { .s_addr = htonl(cli.media_gw_ipv4) } };
                        uint8_t silence[172];
                        memset(silence, 0xff, sizeof silence);   /* µ-law silence */
                        silence[0] = 0x80; silence[1] = 0;       /* RTP hdr V=2 PT=0 */
                        silence[2] = 0; silence[3] = 0;          /* seq */
                        silence[4] = 0; silence[5] = 0;          /* ts hi */
                        silence[6] = 0; silence[7] = 0;          /* ts lo */
                        silence[8] = 0; silence[9] = 0;
                        silence[10] = 0; silence[11] = 1;        /* SSRC */
                        for (int k = 0; k < 5; ++k) {
                            silence[3] = (uint8_t)k;
                            sendto(rtp_fd, silence, sizeof silence, 0,
                                   (struct sockaddr *)&mg, sizeof mg);
                            usleep(20*1000);
                        }
                        printf("[rtp] sent 5 NAT-punch silence frames to media_gw\n");
                    }
                }
                (void)call; (void)answered;
            }
        } else if (cls == VHAM_TAP_CLASS_CC && cmd == VHAM_CC_INFO) {
            printf("[cc] incoming INFO (mic grant)\n");
        } else if (cls == VHAM_TAP_CLASS_CC && cmd == VHAM_CC_REL) {
            printf("[cc] incoming REL (call ended)\n");
        } else if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_PASSTHROUGH) {
            vham_passthrough_t p;
            if (vham_parse_passthrough(resp, (size_t)r, &p) == 0)
                printf("passthrough code=0x%x from=%s\n",
                       p.code, p.have_src ? p.src_num : "?");
        } else {
            printf("rx cls=0x%04x cmd=0x%04x len=%zd\n", cls, cmd, r);
        }
    }
    printf("\n=== summary: %d RTP packets received during listen ===\n",
           rtp_rx_count);
    close(rtp_fd);
    close(sig_fd);
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
    if (!strcmp(sub, "transmit")) return cmd_transmit(&a);
    if (!strcmp(sub, "listen"))   return cmd_listen(&a);
    if (!strcmp(sub, "passthrough")) return cmd_passthrough(&a);
    if (!strcmp(sub, "token"))    return cmd_token(&a, token_action);
    if (!strcmp(sub, "mm"))       return cmd_mm(&a, mm_op);
    if (!strcmp(sub, "im"))    return cmd_im(&a);
    if (!strcmp(sub, "gps"))   return cmd_gps(&a);
    return usage();
}
