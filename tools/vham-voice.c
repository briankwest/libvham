/* tools/vham-voice.c — RTP/voice harness for libvham.
 *
 * Modes:
 *   send  — read 16-bit signed mono 8 kHz PCM from file (or - for stdin),
 *           encode to G.711 (PCMU or PCMA), packetize into 20 ms RTP
 *           packets, send over UDP at real-time cadence.
 *   recv  — bind UDP, receive RTP, decode G.711, write 16-bit PCM to
 *           file (or - for stdout). Tracks loss / reorder.
 *   echo  — bind UDP, reflect every received RTP packet back to its
 *           sender (loopback testing).
 *   tone  — generate a 440 Hz sine wave for `seconds`, send as RTP.
 *   dtmf  — generate an RFC 4733 DTMF burst for each digit in --digits.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vham/voice.h"
#include "vham/g711.h"
#include "vham/rtp.h"
#include "vham/jitter.h"
#include "vham/codec_audio.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void usage(const char *argv0) {
    fprintf(stderr,
        "vham-voice — RTP voice harness\n"
        "\n"
        "Usage:\n"
        "  %s send --peer <ip:port> --in <file|-> [options]\n"
        "  %s recv --bind <ip:port> [--out <file|->] [options]\n"
        "  %s echo --bind <ip:port> [options]\n"
        "  %s tone --peer <ip:port> --seconds <n> [--hz <hz>] [options]\n"
        "  %s dtmf --peer <ip:port> --digits <chars> [options]\n"
        "\n"
        "Options:\n"
        "  --codec pcmu|pcma|opus|amr|ilbc   (default: pcmu)\n"
        "                       Opus only available when libvham is\n"
        "                       built with WITH_OPUS=1.\n"
        "  --ssrc <u32>        sender SSRC (default: 0x12345678)\n"
        "  --duration-s <n>    max time to run (default: send=until EOF,\n"
        "                      recv/echo=300, tone/dtmf=arg-dependent)\n"
        "  --no-pace           skip clock pacing (send as fast as possible)\n"
        "  --verbose           per-packet logging\n",
        argv0, argv0, argv0, argv0, argv0);
}

typedef struct {
    const char *mode;
    const char *peer;
    const char *bind;
    const char *in_path;
    const char *out_path;
    const char *codec;
    const char *digits;
    uint32_t    ssrc;
    int         seconds;
    int         hz;
    int         no_pace;
    int         verbose;
    int         duration_s;
    int         jitter_ms;
} args_t;

static int parse_args(int argc, char **argv, args_t *a) {
    memset(a, 0, sizeof *a);
    if (argc < 2) return -1;
    a->mode = argv[1];
    a->codec = "pcmu";
    a->ssrc = 0x12345678;
    a->seconds = 3;
    a->hz = 440;
    a->duration_s = -1;
    for (int i = 2; i < argc; ++i) {
        const char *x = argv[i];
        if (!strcmp(x, "--peer") && i + 1 < argc)        a->peer = argv[++i];
        else if (!strcmp(x, "--bind") && i + 1 < argc)   a->bind = argv[++i];
        else if (!strcmp(x, "--in") && i + 1 < argc)     a->in_path = argv[++i];
        else if (!strcmp(x, "--out") && i + 1 < argc)    a->out_path = argv[++i];
        else if (!strcmp(x, "--codec") && i + 1 < argc)  a->codec = argv[++i];
        else if (!strcmp(x, "--digits") && i + 1 < argc) a->digits = argv[++i];
        else if (!strcmp(x, "--ssrc") && i + 1 < argc)   a->ssrc = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(x, "--seconds") && i + 1 < argc) a->seconds = atoi(argv[++i]);
        else if (!strcmp(x, "--hz") && i + 1 < argc)     a->hz = atoi(argv[++i]);
        else if (!strcmp(x, "--duration-s") && i + 1 < argc) a->duration_s = atoi(argv[++i]);
        else if (!strcmp(x, "--no-pace"))                a->no_pace = 1;
        else if (!strcmp(x, "--verbose"))                a->verbose = 1;
        else if (!strcmp(x, "--jitter-ms") && i + 1 < argc) a->jitter_ms = atoi(argv[++i]);
        else { fprintf(stderr, "unknown arg: %s\n\n", x); return -1; }
    }
    return 0;
}

static int parse_ip_port(const char *s, struct sockaddr_in *sa) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", s);
    char *colon = strrchr(buf, ':');
    if (!colon) return -1;
    *colon = 0;
    int port = atoi(colon + 1);
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, buf, &sa->sin_addr) != 1) return -1;
    return 0;
}

static int open_udp_send(const struct sockaddr_in *peer) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (const struct sockaddr *)peer, sizeof *peer) != 0) {
        close(fd); return -1;
    }
    return fd;
}

static int open_udp_bind(const struct sockaddr_in *bind_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (bind(fd, (const struct sockaddr *)bind_addr, sizeof *bind_addr) != 0) {
        close(fd); return -1;
    }
    return fd;
}

static uint8_t codec_pt(const char *c) {
    if (!strcmp(c, "pcma"))   return VHAM_RTP_PT_PCMA;
    if (!strcmp(c, "opus"))   return 106;
    if (!strcmp(c, "amr"))    return 96;
    if (!strcmp(c, "amr-wb")) return 97;
    if (!strcmp(c, "ilbc"))   return 102;
    return VHAM_RTP_PT_PCMU;
}

static FILE *open_io(const char *path, const char *mode) {
    if (!path || !strcmp(path, "-")) {
        return (mode[0] == 'r') ? stdin : stdout;
    }
    return fopen(path, mode);
}

/* ---------- send ---------- */
static int cmd_send(const args_t *a) {
    if (!a->peer || !a->in_path) { usage("vham-voice"); return 1; }
    struct sockaddr_in peer;
    if (parse_ip_port(a->peer, &peer) != 0) {
        fprintf(stderr, "bad peer\n"); return 2;
    }
    int fd = open_udp_send(&peer);
    if (fd < 0) { perror("socket"); return 2; }

    FILE *in = open_io(a->in_path, "rb");
    if (!in) { perror("open in"); close(fd); return 2; }

    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, codec_pt(a->codec), a->ssrc);

    int16_t pcm[VHAM_VOICE_SAMPLES];
    uint8_t pkt[1500];
    uint64_t total = 0;
    uint64_t marker = 1;  /* first packet of stream gets marker=1 */

    while (1) {
        size_t got = fread(pcm, sizeof(int16_t), VHAM_VOICE_SAMPLES, in);
        if (got == 0) break;
        /* short final frame: zero-pad */
        if (got < VHAM_VOICE_SAMPLES) {
            memset(pcm + got, 0, (VHAM_VOICE_SAMPLES - got) * sizeof(int16_t));
        }
        if (!a->no_pace) vham_voice_tx_pace(&tx);
        int n = vham_voice_tx_pcm_frame(&tx, pcm, VHAM_VOICE_SAMPLES,
                                        (uint8_t)marker, pkt, sizeof pkt);
        marker = 0;
        if (n < 0) { fprintf(stderr, "encode failed\n"); break; }
        if (send(fd, pkt, (size_t)n, 0) != (ssize_t)n) {
            fprintf(stderr, "send: %s\n", strerror(errno)); break;
        }
        total++;
        if (a->verbose) {
            fprintf(stderr, "[tx] #%llu seq=%u ts=%u len=%d\n",
                    (unsigned long long)total,
                    tx.sequence - 1, tx.timestamp - VHAM_VOICE_SAMPLES, n);
        }
        if (a->duration_s > 0 &&
            total * VHAM_VOICE_PTIME_MS >= (uint64_t)a->duration_s * 1000) break;
    }
    fprintf(stderr, "sent %llu RTP packets (%llu ms)\n",
            (unsigned long long)total,
            (unsigned long long)(total * VHAM_VOICE_PTIME_MS));
    if (in != stdin) fclose(in);
    close(fd);
    return 0;
}

/* ---------- recv ---------- */
static int cmd_recv(const args_t *a) {
    if (!a->bind) { usage("vham-voice"); return 1; }
    struct sockaddr_in baddr;
    if (parse_ip_port(a->bind, &baddr) != 0) {
        fprintf(stderr, "bad bind\n"); return 2;
    }
    int fd = open_udp_bind(&baddr);
    if (fd < 0) { perror("bind"); return 2; }

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    FILE *out = a->out_path ? open_io(a->out_path, "wb") : NULL;
    int dur = (a->duration_s > 0) ? a->duration_s : 300;
    struct timeval start; gettimeofday(&start, NULL);

    vham_voice_rx_t rx;
    vham_voice_rx_init(&rx);

    /* Jitter buffer. Initialized lazily on first audio packet so we
     * pick up the right clock rate from its codec. */
    vham_jitter_t jb;
    int jb_ready = 0;
    uint32_t jb_target_ms = a->jitter_ms > 0 ? (uint32_t)a->jitter_ms : 60;

    uint8_t buf[2048];
    vham_voice_frame_t frame;

    while (1) {
        struct sockaddr_in from; socklen_t flen = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0,
                             (struct sockaddr *)&from, &flen);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timeval now; gettimeofday(&now, NULL);
                if (now.tv_sec - start.tv_sec >= dur) break;
                continue;
            }
            perror("recv"); break;
        }

        /* Peek at RTP header to get seq + ts before any decoding. */
        if (r < 12) continue;
        uint16_t seq = (uint16_t)((buf[2] << 8) | buf[3]);
        uint32_t ts  = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                       ((uint32_t)buf[6] <<  8) |  (uint32_t)buf[7];
        uint8_t  pt  = (uint8_t)(buf[1] & 0x7f);

        /* DTMF bypasses the jitter buffer entirely. */
        if (pt >= 96 && r >= 16 && r - 12 == 4) {
            if (vham_voice_rx_feed(&rx, buf, (size_t)r, &frame) == 0 &&
                frame.kind == VHAM_VOICE_FRAME_DTMF) {
                fprintf(stderr,
                    "[rx] DTMF  event=%u end=%u vol=%u dur=%u\n",
                    frame.dtmf.event, frame.dtmf.end,
                    frame.dtmf.volume, frame.dtmf.duration);
            }
            continue;
        }

        /* Lazy init the jitter buffer using the codec's clock rate. */
        if (!jb_ready) {
            vham_audio_codec_t *c = vham_codec_by_pt(pt);
            uint32_t rate = c ? c->clock_rate : 8000;
            vham_jitter_init(&jb, rate, jb_target_ms);
            jb_ready = 1;
        }
        (void)vham_jitter_push(&jb, seq, ts, buf, (size_t)r);

        /* Drain whatever the jitter buffer is willing to deliver now. */
        vham_jitter_pkt_t jpkt;
        while (vham_jitter_pop(&jb, &jpkt)) {
            if (vham_voice_rx_feed(&rx, jpkt.payload, jpkt.length,
                                   &frame) != 0)
                continue;
            if (frame.kind == VHAM_VOICE_FRAME_AUDIO) {
                if (out)
                    fwrite(frame.pcm, sizeof(int16_t),
                           frame.pcm_samples, out);
                if (a->verbose) {
                    fprintf(stderr,
                        "[rx] AUDIO pt=%u seq=%u ts=%u m=%u samples=%zu\n",
                        frame.payload_type, frame.sequence,
                        frame.timestamp, frame.marker, frame.pcm_samples);
                }
            }
        }
    }
    fprintf(stderr,
        "recv stats: pkt=%llu dtmf=%llu lost=%llu reorder=%llu",
        (unsigned long long)rx.pkt_count,
        (unsigned long long)rx.dtmf_count,
        (unsigned long long)rx.lost_count,
        (unsigned long long)rx.drop_count);
    if (jb_ready) {
        fprintf(stderr, "   jb: delivered=%u dropped_late=%u dropped_dup=%u",
                jb.delivered, jb.dropped_late, jb.dropped_dup);
    }
    fputc('\n', stderr);
    if (out && out != stdout) fclose(out);
    close(fd);
    return 0;
}

/* ---------- echo ---------- */
static int cmd_echo(const args_t *a) {
    if (!a->bind) { usage("vham-voice"); return 1; }
    struct sockaddr_in baddr;
    if (parse_ip_port(a->bind, &baddr) != 0) { fprintf(stderr,"bad bind\n"); return 2; }
    int fd = open_udp_bind(&baddr);
    if (fd < 0) { perror("bind"); return 2; }
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    int dur = (a->duration_s > 0) ? a->duration_s : 300;
    struct timeval start; gettimeofday(&start, NULL);

    uint8_t buf[2048];
    uint64_t total = 0;
    while (1) {
        struct sockaddr_in from; socklen_t flen = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0,
                             (struct sockaddr *)&from, &flen);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timeval now; gettimeofday(&now, NULL);
                if (now.tv_sec - start.tv_sec >= dur) break;
                continue;
            }
            perror("recv"); break;
        }
        sendto(fd, buf, (size_t)r, 0, (struct sockaddr *)&from, flen);
        total++;
        if (a->verbose) fprintf(stderr, "[echo] %zd bytes\n", r);
    }
    fprintf(stderr, "echoed %llu pkts\n", (unsigned long long)total);
    close(fd);
    return 0;
}

/* ---------- tone ---------- */
static int cmd_tone(const args_t *a) {
    if (!a->peer) { usage("vham-voice"); return 1; }
    struct sockaddr_in peer;
    if (parse_ip_port(a->peer, &peer) != 0) { fprintf(stderr,"bad peer\n"); return 2; }
    int fd = open_udp_send(&peer);
    if (fd < 0) { perror("socket"); return 2; }

    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, codec_pt(a->codec), a->ssrc);
    if (!tx.codec) {
        fprintf(stderr, "codec %s not available (rebuild with WITH_OPUS=1?)\n",
                a->codec ? a->codec : "(default)");
        return 3;
    }
    const size_t frame_samples = tx.codec->frame_samples;
    const uint32_t clock_rate  = tx.codec->clock_rate;
    const int total_frames = (a->seconds * 1000) / VHAM_VOICE_PTIME_MS;
    int16_t pcm[VHAM_VOICE_MAX_SAMPLES];
    uint8_t pkt[1500];
    double phase = 0.0;
    const double dphase = 2.0 * 3.14159265358979 * (double)a->hz
                              / (double)clock_rate;
    uint64_t marker = 1;
    for (int f = 0; f < total_frames; ++f) {
        for (size_t i = 0; i < frame_samples; ++i) {
            double v = sin(phase) * 8000.0;
            pcm[i] = (int16_t)v;
            phase += dphase;
            if (phase > 2.0 * 3.14159265358979) phase -= 2.0 * 3.14159265358979;
        }
        if (!a->no_pace) vham_voice_tx_pace(&tx);
        int n = vham_voice_tx_pcm_frame(&tx, pcm, frame_samples,
                                        (uint8_t)marker, pkt, sizeof pkt);
        marker = 0;
        if (n < 0) break;
        send(fd, pkt, (size_t)n, 0);
        if (a->verbose && f % 50 == 0)
            fprintf(stderr, "[tone] frame %d/%d\n", f, total_frames);
    }
    fprintf(stderr, "tone done (%d frames, %ds)\n", total_frames, a->seconds);
    close(fd);
    return 0;
}

/* ---------- dtmf ---------- */
static int cmd_dtmf(const args_t *a) {
    if (!a->peer || !a->digits) { usage("vham-voice"); return 1; }
    struct sockaddr_in peer;
    if (parse_ip_port(a->peer, &peer) != 0) { fprintf(stderr,"bad peer\n"); return 2; }
    int fd = open_udp_send(&peer);
    if (fd < 0) { perror("socket"); return 2; }

    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, codec_pt(a->codec), a->ssrc);

    /* Each digit: 200ms total = 10 packets of 20ms.
     * Per RFC 4733, send a few "end" packets at the end for redundancy. */
    for (const char *c = a->digits; *c; ++c) {
        int ev = vham_dtmf_from_char(*c);
        if (ev < 0) { fprintf(stderr, "skip '%c'\n", *c); continue; }
        const int frames = 10;
        uint16_t dur = VHAM_VOICE_SAMPLES;
        for (int f = 0; f < frames; ++f) {
            if (!a->no_pace) vham_voice_tx_pace(&tx);
            uint8_t pkt[64];
            int n = vham_voice_tx_dtmf(&tx, (uint8_t)ev, 10, dur,
                                       /* end on last 3 packets */
                                       (f >= frames - 3) ? 1 : 0,
                                       pkt, sizeof pkt);
            if (n > 0) send(fd, pkt, (size_t)n, 0);
            dur += VHAM_VOICE_SAMPLES;
        }
        /* Advance media timestamp past the DTMF event. */
        tx.timestamp += dur;
        if (a->verbose) fprintf(stderr, "[dtmf] sent '%c'\n", *c);
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    args_t a;
    if (parse_args(argc, argv, &a) != 0) {
        usage(argv[0]);
        return 1;
    }
    if (!strcmp(a.mode, "send")) return cmd_send(&a);
    if (!strcmp(a.mode, "recv")) return cmd_recv(&a);
    if (!strcmp(a.mode, "echo")) return cmd_echo(&a);
    if (!strcmp(a.mode, "tone")) return cmd_tone(&a);
    if (!strcmp(a.mode, "dtmf")) return cmd_dtmf(&a);
    usage(argv[0]);
    return 1;
}
