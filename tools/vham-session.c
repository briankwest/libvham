/* tools/vham-session.c — long-running VHAM session.
 *
 * Performs MM registration (with dispatcher auto-hop) and then runs
 * a recv loop that:
 *   - ACKs every incoming CMD/RSP frame at the TAP layer
 *   - feeds CC frames into vham_cc_call_t (state machine)
 *   - if --call <num> was given, sends an initial CC_SETUP with a
 *     minimal audio SDP after login
 *
 * Output is printed as state transitions occur. Loop runs until the
 * call reaches a terminal state or --idle-s is exceeded.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/cc.h"
#include "vham/codec.h"
#include "vham/envcfg.h"
#include "vham/regreq.h"
#include "vham/regrsp.h"
#include "vham/sdp.h"
#include "vham/passthrough.h"
#include "vham/oam.h"
#include "vham/causes.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Server defaults come from VHAM_SERVER (env / .env). If absent we
 * fall back to the public symbolic name. Override with --server. */
#define DEFAULT_SERVER     "us.vham.net"
#define DEFAULT_PORT       10000
#define DEFAULT_TIMEOUT_S  5
#define DEFAULT_IDLE_S     30

static void usage(const char *argv0) {
    fprintf(stderr,
        "vham-session — log in and (optionally) place a PTT call\n"
        "\n"
        "Usage: %s --user <num> --pass <pw> [options]\n"
        "\n"
        "Options:\n"
        "  --user <num>      account number\n"
        "  --pass <pw>       account password (default: VHAM_PASS from .env)\n"
        "  --server <ip>     server IP (default: %s)\n"
        "  --port <port>     UDP port (default: %d)\n"
        "  --call <num>      after login, place a half-duplex call to\n"
        "                    this channel (e.g. 146520 = USA VHF Calling)\n"
        "                    or to a user dispatch number (e.g. V15...)\n"
        "  --tune <num>      after login, also subscribe to channel <num>\n"
        "                    in addition to the '###' wildcard. Without\n"
        "                    this, the server won't deliver incoming\n"
        "                    calls on public channels.\n"
        "  --subcode <code>  channel sub-code (the 'Password' column on\n"
        "                    vham.net — really a CTCSS-style sub-channel).\n"
        "                    Emitted as IE 0x45 in CC_SETUP. Provisional.\n"
        "  --leg <id>        leg id for CC_SETUP (default: 1)\n"
        "  --timeout-s <n>   per-RTT recv timeout (default: %d)\n"
        "  --idle-s <n>      total wall-clock budget after login\n"
        "                    (default: %d). Loop exits when reached.\n"
        "  --send            actually transmit (dry-run by default)\n"
        "  -h, --help        show this help\n",
        argv0, DEFAULT_SERVER, DEFAULT_PORT,
        DEFAULT_TIMEOUT_S, DEFAULT_IDLE_S);
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

static uint16_t peek_u16(const uint8_t *b, size_t at) {
    return ((uint16_t)b[at] << 8) | b[at + 1];
}

static int open_udp_host(uint32_t ipv4_convA, uint16_t port, int timeout_s) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
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
    if (inet_pton(AF_INET, ip, &ina) != 1) return -1;
    return open_udp_host(ntohl(ina.s_addr), (uint16_t)port, timeout_s);
}

static void send_tap_ack(int fd, const uint8_t *frame, size_t n) {
    if (n < 16) return;
    uint32_t seq  = ((uint32_t)frame[4] << 24) | ((uint32_t)frame[5] << 16)
                  | ((uint32_t)frame[6] << 8)  | (uint32_t)frame[7];
    uint16_t cls  = peek_u16(frame, 8);
    uint16_t cmd  = peek_u16(frame, 10);
    uint8_t ack[16];
    int an = vham_build_tap_ack(seq, cls, cmd, ack, sizeof ack);
    if (an == 16) (void)send(fd, ack, 16, 0);
}

/* Build a minimal audio-only SDP body (PCMU). Real calls likely
 * want Opus (PT 106) plus parameters; this is enough for the
 * server to recognize the frame format. */
static int build_minimal_sdp(uint32_t local_ip, uint16_t local_port,
                             uint8_t *out, size_t out_cap) {
    vham_sdp_t s;
    memset(&s, 0, sizeof s);
    s.origin_ipv4 = local_ip;
    s.origin_port = local_port;
    s.media_count = 1;
    vham_sdp_media_t *m = &s.media[0];
    m->ipv4         = local_ip;
    m->port         = local_port;
    m->media_type   = VHAM_SDP_MEDIA_AUDIO;
    m->transport    = VHAM_SDP_TX_RTP_UDP;
    m->codec_count  = 1;
    m->codecs[0].payload_type   = 0;       /* PCMU */
    m->codecs[0].encoding_param = 1;
    m->codecs[0].clock_rate     = 8000;
    snprintf(m->codecs[0].name, sizeof m->codecs[0].name, "PCMU");
    return vham_build_sdp_body(&s, out, out_cap);
}

/* Wallclock seconds since program start */
static double now_s(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

int main(int argc, char **argv) {
    const char *user      = vham_env("VHAM_USER",   NULL);
    const char *pass      = vham_env("VHAM_PASS",   NULL);
    const char *server    = vham_env("VHAM_SERVER", DEFAULT_SERVER);
    int port              = DEFAULT_PORT;
    const char *call_num  = NULL;
    const char *tune_chan = NULL;   /* extra channel to subscribe to */
    const char *subcode   = NULL;   /* IE 0x45 — channel sub-code ("Password" on vham.net) */
    int         query_groups = 0;   /* send IDT_GQueryU after login */
    const char *join_group   = NULL;/* send IDT_GAddU to join this group */
    uint32_t leg_id       = 1;
    int timeout_s         = DEFAULT_TIMEOUT_S;
    int idle_s            = DEFAULT_IDLE_S;
    int send_for_real     = 0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "--user") && i + 1 < argc)     { user = argv[++i]; }
        else if (!strcmp(a, "--pass") && i + 1 < argc)     { pass = argv[++i]; }
        else if (!strcmp(a, "--server") && i + 1 < argc)   { server = argv[++i]; }
        else if (!strcmp(a, "--port") && i + 1 < argc)     { port = atoi(argv[++i]); }
        else if (!strcmp(a, "--call") && i + 1 < argc)     { call_num = argv[++i]; }
        else if (!strcmp(a, "--tune") && i + 1 < argc)     { tune_chan = argv[++i]; }
        else if (!strcmp(a, "--subcode") && i + 1 < argc)  { subcode   = argv[++i]; }
        else if (!strcmp(a, "--query-groups"))             { query_groups = 1; }
        else if (!strcmp(a, "--join") && i + 1 < argc)     { join_group = argv[++i]; }
        else if (!strcmp(a, "--leg") && i + 1 < argc)      { leg_id = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--timeout-s") && i + 1 < argc){ timeout_s = atoi(argv[++i]); }
        else if (!strcmp(a, "--idle-s") && i + 1 < argc)   { idle_s = atoi(argv[++i]); }
        else if (!strcmp(a, "--send"))                     { send_for_real = 1; }
        else { fprintf(stderr, "unknown arg: %s\n\n", a); usage(argv[0]); return 1; }
    }
    if (!user || !pass) { fprintf(stderr, "--user/--pass required\n"); return 1; }

    struct in_addr ina;
    if (inet_pton(AF_INET, server, &ina) != 1) { fprintf(stderr, "bad ip\n"); return 1; }
    uint32_t server_ipv4 = ntohl(ina.s_addr);

    /* --- REGISTRATION --- */
    vham_reg_client_t cli;
    vham_reg_client_init(&cli, user, pass, server_ipv4, (uint16_t)port);

    uint8_t buf[1500];
    int n = vham_reg_client_emit(&cli, buf, sizeof buf);
    if (n <= 0) { fprintf(stderr, "build initial REGREQ failed\n"); return 1; }

    if (!send_for_real) {
        printf("(dry-run; would send %d-byte REGREQ to %s:%d)\n",
               n, server, port);
        if (call_num) printf("(would then place call to %s)\n", call_num);
        return 0;
    }

    int fd = open_udp(server, port, timeout_s);
    if (fd < 0) return 2;

    /* Phase 1 with auto-hop */
    uint8_t resp[2048];
    int rn = 0;
    vham_reg_state_t st = VHAM_REG_INIT;
    for (int hop = 0; hop < 3; ++hop) {
        if (send(fd, buf, (size_t)n, 0) != (ssize_t)n) {
            fprintf(stderr, "send failed\n"); close(fd); return 3;
        }
        rn = -1;
        for (int g = 0; g < 8; ++g) {
            ssize_t r = recv(fd, resp, sizeof resp, 0);
            if (r < 0) break;
            uint16_t flags = peek_u16(resp, 2);
            uint16_t cmd   = peek_u16(resp, 10);
            if (flags == VHAM_TAP_FLAG_ACK) continue;
            send_tap_ack(fd, resp, (size_t)r);
            if (cmd == VHAM_MM_REGRSP) { rn = (int)r; break; }
        }
        if (rn < 0) { fprintf(stderr, "no REGRSP\n"); close(fd); return 3; }

        st = vham_reg_client_recv(&cli, resp, (size_t)rn);
        if (st == VHAM_REG_REDIRECT) {
            char ip[INET_ADDRSTRLEN];
            struct in_addr a = { .s_addr = htonl(cli.server_ipv4) };
            inet_ntop(AF_INET, &a, ip, sizeof ip);
            fprintf(stderr, "[hop] → %s:%u\n", ip, cli.server_port);
            close(fd);
            fd = open_udp_host(cli.server_ipv4, cli.server_port, timeout_s);
            if (fd < 0) return 2;
            n = vham_reg_client_emit(&cli, buf, sizeof buf);
            if (n <= 0) { close(fd); return 5; }
            continue;
        }
        break;
    }
    fprintf(stderr, "[reg] phase1 state: %s\n",
            st == VHAM_REG_OK ? "OK" :
            st == VHAM_REG_FAILED ? "FAILED" :
            st == VHAM_REG_SENT_INITIAL ? "SENT_INITIAL" : "?");

    if (st == VHAM_REG_SENT_INITIAL) {
        /* Phase 2: auth */
        n = vham_reg_client_emit(&cli, buf, sizeof buf);
        if (n <= 0) { fprintf(stderr, "build phase2 failed\n"); close(fd); return 4; }
        if (send(fd, buf, (size_t)n, 0) != (ssize_t)n) { close(fd); return 3; }
        rn = -1;
        for (int g = 0; g < 8; ++g) {
            ssize_t r = recv(fd, resp, sizeof resp, 0);
            if (r < 0) break;
            uint16_t flags = peek_u16(resp, 2);
            uint16_t cmd   = peek_u16(resp, 10);
            if (flags == VHAM_TAP_FLAG_ACK) continue;
            send_tap_ack(fd, resp, (size_t)r);
            if (cmd == VHAM_MM_REGRSP) { rn = (int)r; break; }
        }
        if (rn < 0) { fprintf(stderr, "no REGRSP for phase 2\n"); close(fd); return 3; }
        st = vham_reg_client_recv(&cli, resp, (size_t)rn);
    }
    if (st != VHAM_REG_OK) {
        printf("\nlogin: FAILED (state=%d cause=0x%x)\n",
               (int)st, cli.session_id);
        close(fd); return 7;
    }
    /* --- STATUS SUBSCRIPTION ---
     *
     * Real clients subscribe to status events after login so the
     * server pushes incoming-call notifications and presence
     * updates. Without this, the server treats us as "online but
     * silent" and never routes calls to us. */
    {
        /* Per MM::Subs in the binary, each subscription target is sent
         * as its own STATUSSUBS message. Send "###" first, then any
         * specific channel via --tune. */
        const char *targets[2] = { "###", tune_chan };
        size_t      n_targets  = tune_chan ? 2 : 1;
        for (size_t i = 0; i < n_targets; ++i) {
            uint32_t subs_seq = cli.seq_no + 1;
            cli.seq_no = subs_seq;
            uint8_t sub_pkt[256];
            int subs_n = vham_build_status_subs(subs_seq, user,
                                                targets[i],
                                                VHAM_SUBS_DETAILED,
                                                (uint32_t)(i + 1),
                                                sub_pkt, sizeof sub_pkt);
            if (subs_n <= 0) continue;
            fprintf(stderr, "[sub] >>> STATUSSUBS target='%s' (%d bytes)\n",
                    targets[i], subs_n);
            (void)send(fd, sub_pkt, (size_t)subs_n, 0);
            /* Drain immediate ACK */
            for (int g = 0; g < 4; ++g) {
                ssize_t r = recv(fd, resp, sizeof resp, 0);
                if (r < 0) break;
                if (peek_u16(resp, 2) == VHAM_TAP_FLAG_ACK) continue;
                send_tap_ack(fd, resp, (size_t)r);
                fprintf(stderr, "[sub] <<< %zd bytes cmd=0x%04x\n",
                        r, peek_u16(resp, 10));
            }
        }
    }

    /* --- GROUP QUERY (optional) ---
     * Ask the server to list our own group memberships. Mirrors
     * IDT_GQueryU(100L, our_num, 1, 0, 0) — scope=own, ucAll=1. */
    if (query_groups) {
        cli.seq_no += 1;
        uint8_t qbuf[256];
        vham_query_ext_t qe = { .uc_all = 1 };
        int qn = vham_build_oam_gqueryu(cli.seq_no, user, user,
                                        100, &qe, qbuf, sizeof qbuf);
        if (qn > 0) {
            fprintf(stderr, "[oam] >>> GQueryU (%d bytes, dwSn=100)\n", qn);
            (void)send(fd, qbuf, (size_t)qn, 0);
            for (int g = 0; g < 4; ++g) {
                ssize_t r = recv(fd, resp, sizeof resp, 0);
                if (r < 0) break;
                if (peek_u16(resp, 2) == VHAM_TAP_FLAG_ACK) continue;
                send_tap_ack(fd, resp, (size_t)r);
                vham_oam_rsp_t rsp;
                if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
                    fprintf(stderr,
                        "[oam] <<< RSP op=0x%x status=0x%04x count=%u session=0x%x sender='%s'\n",
                        rsp.op_code, rsp.status, rsp.count,
                        rsp.session_id, rsp.echoed_num);
                    if (rsp.have_ginfo && rsp.ginfo.count > 0) {
                        for (uint16_t k = 0; k < rsp.ginfo.count; ++k) {
                            fprintf(stderr, "       grp[%u] num=%s name='%s'\n",
                                    k, rsp.ginfo.entries[k].num,
                                    rsp.ginfo.entries[k].name);
                        }
                    }
                } else {
                    fprintf(stderr, "[oam] <<< %zd bytes cls=0x%04x cmd=0x%04x (unparsed)\n",
                            r, peek_u16(resp, 8), peek_u16(resp, 10));
                }
            }
        }
    }

    /* --- GROUP JOIN (optional) ---
     * Attempt to self-add to a group via OAM_REQ op=9 (GAddU). Some
     * servers permit this for open channels; admin-only configs reject it. */
    if (join_group) {
        cli.seq_no += 1;
        uint8_t jbuf[256];
        int jn = vham_build_oam_gaddu(cli.seq_no, user, join_group,
                                      100, jbuf, sizeof jbuf);
        if (jn > 0) {
            fprintf(stderr, "[oam] >>> GAddU (%d bytes) target=%s\n",
                    jn, join_group);
            (void)send(fd, jbuf, (size_t)jn, 0);
            for (int g = 0; g < 4; ++g) {
                ssize_t r = recv(fd, resp, sizeof resp, 0);
                if (r < 0) break;
                if (peek_u16(resp, 2) == VHAM_TAP_FLAG_ACK) continue;
                send_tap_ack(fd, resp, (size_t)r);
                vham_oam_rsp_t rsp;
                if (vham_parse_oam_rsp(resp, (size_t)r, &rsp) == 0) {
                    fprintf(stderr,
                        "[oam] <<< RSP op=0x%x status=0x%04x (%s)\n",
                        rsp.op_code, rsp.status,
                        vham_cause_name(rsp.status));
                } else {
                    fprintf(stderr, "[oam] <<< %zd bytes cls=0x%04x cmd=0x%04x (unparsed)\n",
                            r, peek_u16(resp, 8), peek_u16(resp, 10));
                }
            }
        }
    }

    printf("\nlogin: OK   session_id=0x%08x   media_gw=", cli.session_id);
    if (cli.have_media_gw) {
        struct in_addr a = { .s_addr = htonl(cli.media_gw_ipv4) };
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ip, sizeof ip);
        printf("%s:%u\n", ip, cli.media_gw_port);
    } else {
        printf("(none)\n");
    }
    if (cli.have_org) {
        printf("\norg: %u entry(s)\n", cli.org.count);
        for (uint16_t k = 0; k < cli.org.count; ++k) {
            const vham_org_entry_t *e = &cli.org.entries[k];
            printf("  [%u] num=%s name='%s' users=%u ds=%u ds0=%s\n",
                   k, e->num, e->name, e->user_num, e->ds_num,
                   e->ds0_num);
            if (e->app_name[0])
                printf("       app='%s'\n", e->app_name);
            if (e->app_icon[0])
                printf("       icon=%s\n", e->app_icon);
        }
    }
    if (cli.have_ginfo) {
        printf("\ngroups: %u entry(s)\n", cli.ginfo.count);
        for (uint16_t k = 0; k < cli.ginfo.count; ++k) {
            const vham_ginfo_member_t *m = &cli.ginfo.entries[k];
            printf("  [%u] num=%s name='%s' prio=%u type=%u chan=%u status=%u\n",
                   k, m->num, m->name, m->prio, m->type, m->chan_num,
                   m->status);
            if (m->ag_num[0])  printf("       ag=%s\n", m->ag_num);
            if (m->fg_count)   printf("       fg(%u)=%s\n", m->fg_count, m->fg_num);
        }
    } else {
        printf("\ngroups: (none — silent-activation account has no memberships yet)\n");
    }
    if (cli.have_ftp) {
        struct in_addr a = { .s_addr = htonl(cli.ftp.ipv4) };
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ip, sizeof ip);
        printf("\nftp: %s:%u  user=%s\n", ip, cli.ftp.port, cli.ftp.username);
    }

    /* --- CALL (optional) ---
     *
     * If --call was specified, send a CC_SETUP after login. Either
     * way, drop into the recv loop so we can act as a callee for
     * incoming calls or observe server-initiated events. */
    vham_cc_call_t call;
    vham_cc_call_init(&call, user, call_num ? call_num : "", leg_id);

    if (call_num) {
        uint8_t sdp[1024];
        int sdp_n = build_minimal_sdp(0xc0a80164, 10001, sdp, sizeof sdp);
        if (sdp_n <= 0) { fprintf(stderr, "build SDP failed\n"); close(fd); return 6; }
        fprintf(stderr, "[sdp] body: %d bytes\n", sdp_n);

        n = vham_cc_call_emit(&call, sdp, (size_t)sdp_n,
                              VHAM_CALL_HALF_DUPLEX,
                              subcode,
                              cli.last_algorithm,
                              cli.last_nonce,
                              cli.last_realm,
                              cli.last_response_hex,
                              buf, sizeof buf);
        if (n <= 0) { fprintf(stderr, "build CC_SETUP failed\n"); close(fd); return 6; }
        fprintf(stderr, "[cc ] >>> SETUP (%d bytes)\n", n);
        hexdump(">>", buf, (size_t)n);
        if (send(fd, buf, (size_t)n, 0) != (ssize_t)n) { close(fd); return 3; }
    } else {
        fprintf(stderr, "[loop] listening as callee (no --call)\n");
    }

    /* --- LOOP --- */
    /* Send the NAT keepalive immediately, then every NATTIME/2 (15s
     * provides ample margin under the 30s NATTIME default). */
    double start = now_s();
    int idle_ticks = 0;
    double next_nat_s = 0.0;  /* fire immediately */
    while (now_s() - start < idle_s) {
        if (now_s() - start >= next_nat_s) {
            uint8_t ping[3];
            if (vham_build_nat_ping(ping, sizeof ping) == 3) {
                (void)send(fd, ping, 3, 0);
                fprintf(stderr, "[nat] >>> keepalive (3 bytes)\n");
            }
            next_nat_s = (now_s() - start) + 15.0;
        }
        ssize_t r = recv(fd, resp, sizeof resp, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++idle_ticks % 4 == 0)
                    fprintf(stderr, "[loop] idle (%.0fs elapsed)\n",
                            now_s() - start);
                continue;
            }
            fprintf(stderr, "[loop] recv: %s\n", strerror(errno));
            break;
        }
        idle_ticks = 0;
        /* NAT-plane traffic: log size + first 4 bytes and skip. */
        if (vham_is_nat_packet(resp, (size_t)r)) {
            fprintf(stderr, "[nat] <<< %zd bytes (NAT probe/response)\n", r);
            continue;
        }
        uint16_t flags = peek_u16(resp, 2);
        uint16_t cls   = peek_u16(resp, 8);
        uint16_t cmd   = peek_u16(resp, 10);
        if (flags == VHAM_TAP_FLAG_ACK) {
            fprintf(stderr, "[loop] (TAP ACK cmd=0x%04x)\n", cmd);
            continue;
        }
        send_tap_ack(fd, resp, (size_t)r);
        fprintf(stderr, "[loop] <<< %zd bytes  cls=0x%04x cmd=0x%04x\n",
                r, cls, cmd);
        hexdump("<<", resp, (size_t)r);

        /* MM_PASSTHROUGH: YaoYun negotiation, IM, generic events. */
        if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_PASSTHROUGH) {
            vham_passthrough_t pt;
            if (vham_parse_passthrough(resp, (size_t)r, &pt) == 0) {
                fprintf(stderr,
                    "[pt ] event code=0x%02x type=0x%x utsn=0x%x sn='%s' time='%s' dlen=%u",
                    pt.code, pt.type, pt.ut_sn, pt.sn, pt.time, pt.data_len);
                if (pt.have_src)     fprintf(stderr, " from=%s", pt.src_num);
                if (pt.have_display) fprintf(stderr, " disp='%s'", pt.display);
                fprintf(stderr, "\n");

                int yy = vham_passthrough_yaoyun_value(&pt);
                if (yy >= 0) {
                    cli.seq_no += 1;
                    uint8_t ack[256];
                    int an = vham_build_yaoyun_ack(cli.seq_no, user,
                                                   pt.have_src ? pt.src_num : "",
                                                   "YaoYun", yy,
                                                   ack, sizeof ack);
                    if (an > 0) {
                        (void)send(fd, ack, (size_t)an, 0);
                        fprintf(stderr, "[pt ] >>> YaoYun ack (yy=%d)\n", yy);
                    }
                }
                continue;
            }
        }

        /* MM_STATUSNOTIFY: presence / group-status pushes. */
        if (cls == VHAM_TAP_CLASS_MM && cmd == 0x0091) {
            vham_status_notify_t n;
            if (vham_parse_status_notify(resp, (size_t)r, &n) == 0) {
                fprintf(stderr,
                    "[mm ] STATUSNOTIFY subject='%s' counter=%u status=%u",
                    n.subject_num, n.counter, n.status);
                if (n.have_peer) fprintf(stderr, " peer=%s", n.peer_num);
                fprintf(stderr, "\n");
                continue;
            }
        }

        /* MM-plane event delivery (server pushes incoming-call
         * notifications as MM_REGRSP frames with ucSrc=CC). */
        if (cls == VHAM_TAP_CLASS_MM && cmd == VHAM_MM_REGRSP) {
            vham_mm_notify_t note;
            if (vham_parse_mm_notify(resp, (size_t)r, &note) == 0 &&
                note.have_notify) {
                const char *kind = "unknown";
                if (note.sub_opcode == 0x0021) kind = "call-incoming";
                fprintf(stderr,
                    "[mm ] notify: sub_opcode=0x%04x (%s) status=0x%02x for='%s'\n",
                    note.sub_opcode, kind, note.notify_status,
                    note.echoed_num);
                continue;
            }
        }

        if (cls == VHAM_TAP_CLASS_CC) {
            uint16_t in_cmd = cmd;
            vham_call_state_t cs = vham_cc_call_recv(&call, resp, (size_t)r);
            fprintf(stderr, "[cc ] state: %s   cmd=0x%04x   cause=0x%x\n",
                    vham_call_state_str(cs), in_cmd, call.last_cause);
            if (cs == VHAM_CALL_RELEASED || cs == VHAM_CALL_FAILED) break;

            /* Callee path: incoming CC_SETUP → answer with our SDP. */
            if (in_cmd == VHAM_CC_SETUP) {
                uint8_t local_sdp[1024];
                int sdp_n = build_minimal_sdp(0xc0a80164, 10001,
                                              local_sdp, sizeof local_sdp);
                if (sdp_n > 0) {
                    n = vham_cc_call_answer(&call, local_sdp, (size_t)sdp_n,
                                            buf, sizeof buf);
                    if (n > 0) {
                        fprintf(stderr, "[cc ] >>> CONN (%d bytes)\n", n);
                        (void)send(fd, buf, (size_t)n, 0);
                    }
                }
            }
            /* Incoming CC_INFO (e.g. mic-grant from peer): ack it
             * and surface the mic state. */
            else if (in_cmd == VHAM_CC_INFO) {
                if (call.mic_action) {
                    const char *act_name =
                        call.mic_action == VHAM_USERCTRL_REQUEST ? "REQ" :
                        call.mic_action == VHAM_USERCTRL_RELEASE ? "REL" :
                                                                   "???";
                    fprintf(stderr,
                        "[cc ] mic %s   holder='%s'\n",
                        act_name, call.mic_holder);
                }
                n = vham_cc_call_info_ack(&call, buf, sizeof buf);
                if (n > 0) {
                    fprintf(stderr, "[cc ] >>> INFOACK (%d bytes)\n", n);
                    (void)send(fd, buf, (size_t)n, 0);
                }
            }
            /* Incoming CC_REL: echo CC_REL back to close the leg. */
            else if (in_cmd == VHAM_CC_REL) {
                n = vham_cc_call_release(&call, 0x10, buf, sizeof buf);
                if (n > 0) {
                    fprintf(stderr, "[cc ] >>> REL (%d bytes)\n", n);
                    (void)send(fd, buf, (size_t)n, 0);
                }
                break;
            }
        }
    }

    printf("\nfinal call state: %s   cause=0x%x\n",
           vham_call_state_str(call.state), call.last_cause);
    close(fd);
    return 0;
}
