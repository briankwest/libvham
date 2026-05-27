/* libvham/include/vham/nat.h — NAT and STUN helpers.
 *
 * Pure stateless helpers that the CLI was open-coding. STUN discovery
 * over an existing UDP socket, and a TAP-ACK echo builder driven
 * directly from a received TAP frame.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_NAT_H
#define VHAM_NAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Discover the public IPv4/port for an existing UDP socket via a STUN
 * Binding Request (RFC 5389). Sends to `stun_host:stun_port`, waits
 * up to `timeout_ms` ms for a response, parses XOR-MAPPED-ADDRESS.
 *
 * The socket is left configured with a recv timeout matching the call;
 * callers can override afterward if they want non-blocking semantics.
 *
 *   fd          existing UDP socket (we send/recv on it)
 *   stun_host   "stun.l.google.com" is a reasonable default
 *   stun_port   typically 19302
 *   timeout_ms  e.g. 2000
 *   out_ip      host-order IPv4 (network order on the wire)
 *   out_port    host-order port
 *
 * Returns 0 on success, -1 on error/timeout (out_ip/port unmodified). */
int vham_stun_discover(int fd,
                       const char *stun_host, uint16_t stun_port,
                       int timeout_ms,
                       uint32_t *out_ip, uint16_t *out_port);

/* Examine a received TAP frame and, if it is NOT itself an ACK,
 * build a TAP-ACK echoing its seq/class/cmd. The bridge retransmits
 * any frame we fail to ACK, so the cli's recv loop must call this
 * on every received non-ACK packet.
 *
 *   recv_buf, recv_len  the packet we just received
 *   ack_out, ack_cap    output buffer (must be ≥ 16 bytes)
 *
 * Returns:
 *   16   if an ACK was written (caller should send it back)
 *    0   if the input was itself a TAP-ACK (nothing to do)
 *   -1   on invalid input or buffer too small. */
int vham_tap_build_ack_for(const void *recv_buf, size_t recv_len,
                           void *ack_out, size_t ack_cap);

/* ----- Media-channel NAT sentinel state ---------------------------
 *
 * Mirrors `CMediaTrans::SendNat @ 0x277d30` + `CMediaTrans::Scan @
 * 0x277eb4`: send a 3-byte `FF D3 01` packet on the RTP socket to the
 * per-call media peer, both at call start (3× back-to-back, see
 * SetSendNat(true) @ 0x277fd8) and every 2000 ms during the call.
 *
 * Without this the server's bridge silently drops outbound RTP from
 * the SDK client even though signaling looks fine.  The cli used to
 * open-code this; the state struct hides the 2s timer and the
 * sendto() boilerplate. */
typedef struct {
    int      fd;             /* UDP RTP socket */
    uint32_t peer_ip_be;     /* network-order IPv4 */
    uint16_t peer_port_be;   /* network-order port */
    uint64_t next_send_us;   /* CLOCK_MONOTONIC absolute */
} vham_media_nat_t;

/* Initialize state, point at `peer_ip_host:peer_port_host` (the per-call
 * media endpoint learned from CC_CONN), and send the initial 3× FF D3 01
 * registration burst.  Returns 0 on success, -1 on sendto failure. */
int vham_media_nat_open(vham_media_nat_t *s, int fd,
                        uint32_t peer_ip_host, uint16_t peer_port_host);

/* If ≥2 seconds elapsed since the last sentinel, send a fresh FF D3 01
 * and reset the timer. Call this from the RTP send loop. Returns:
 *   1   sentinel sent this call
 *   0   not yet time
 *  -1   sendto failure (errno set). */
int vham_media_nat_tick(vham_media_nat_t *s);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_NAT_H */
