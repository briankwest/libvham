# libvham

A clean-room C reimplementation of the **VHAM / IDS-IDTMA** push-to-talk-over-cellular protocol, reverse-engineered from `libsvcapi.so` shipped in the LinkPoon Android app.

- **13k LOC** of portable C across 30+ source files
- **82 unit tests** + 30-check live test suite (`test/live.sh`)
- **17 CLI subcommands** in `vham-cli` covering every wire op we've reversed
- **6 audio codecs** (PCMU, PCMA, AMR-NB, AMR-WB, iLBC, Opus) — see [Media reality check](#media-reality-check) for bridge support
- **Real DTLS-SRTP** via mbedtls 3 *or* OpenSSL 1.1+ + libsrtp 2
- **Autoconf-based** build with auto-detection of optional libraries
- **End-to-end voice TX/RX** confirmed against live `us.vham.net` infrastructure (channel 446.001, May 2026)
- Call setup ~2.0 s median (mostly server RTT); profiling opt-in via `VHAM_TIMING=1`
- Zero hardcoded credentials — all config via `.env`

---

## Table of Contents

- [What this is](#what-this-is)
- [Architecture](#architecture)
  - [Layer diagram](#layer-diagram)
  - [Component map](#component-map)
  - [Threading model](#threading-model)
- [Quick start](#quick-start)
- [Build](#build)
- [Configuration via `.env`](#configuration-via-env)
- [Operations in detail](#operations-in-detail)
  - [Login (registration)](#login-registration)
  - [Channel TX (transmit on a PTT channel)](#channel-tx-transmit-on-a-ptt-channel)
  - [Channel RX (inbound listen)](#channel-rx-inbound-listen)
  - [NAT keepalive](#nat-keepalive)
  - [Group operations (OAM)](#group-operations-oam)
  - [PASSTHROUGH: IM, YaoYun, raw](#passthrough-im-yaoyun-raw)
  - [DTLS-SRTP handshake](#dtls-srtp-handshake)
  - [Token cache](#token-cache)
- [Tools](#tools)
- [Protocol coverage](#protocol-coverage)
- [Media reality check](#media-reality-check)
- [Performance: call setup latency](#performance-call-setup-latency)
- [Testing](#testing)
- [Layout](#layout)
- [Legal and ethical use](#legal-and-ethical-use)

---

## What this is

VHAM (LinkPoon's PoC stack) implements a Chinese-origin "IDS-IDTMA" protocol that runs entirely over UDP and provides:

- Half-duplex PTT calls (1-to-1 and group / channel)
- Talk-groups (admin-provisioned) and personal contact lists (user-creatable)
- IM (text over PASSTHROUGH), GPS reporting, presence
- Channel subscribe / status notifications
- DTLS-SRTP option for media encryption
- RTP-over-TCP fallback (RFC 4571) for restricted networks

The original `libsvcapi.so` is a stripped C++ shared library with ~3,800 mangled symbols. `libvham` is a portable C library that reimplements the protocol's wire format and the client-side state machines needed to interoperate with the public LinkPoon servers (`us.vham.net`, `th.vham.net`, `linkpoon.com`).

---

## Architecture

### Layer diagram

```
       ┌───────────────────────────────────────────────────────────┐
       │  tools/  vham-cli, vham-voice, vham-session, vham-call …   │
       │          (thin CLIs over the public library API)          │
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  High-level orchestrators                                 │
       │    voice_call.c   end-to-end PTT call (TX side)           │
       │    cc.c           CC FSM: SETUP/CONN/INFO/REL state mach. │
       │    regreq+regrsp  REGREQ digest auth + REGRSP parser      │
       │    oam.c          group CRUD (GAdd/GAddU/GModify/…)       │
       │    passthrough.c  PASSTHROUGH framing (IM, YaoYun, raw)   │
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  Composite IEs / parsers                                  │
       │    composites.c   OrgList, UsrGInfo, FtpInfo, CallUserCtrl│
       │                   CamInfo, Info, ResReport, GpsRec, …     │
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  Wire framing                                             │
       │    codec.c        TAP (16B) + SRVMSG (16B) + TLV IE pack  │
       │    sdp.c          custom binary SDP (5-codec offer)       │
       │    segment.c      large-frame UDP segmentation            │
       │    retx.c         signaling retransmission                │
       │    md5+auth       RFC 2617 digest                         │
       │    causes.c       95-entry cause-code dictionary          │
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  Media                                                    │
       │    voice.c        PCM-in → encode → RTP → sendto          │
       │    rtp.c rtcp.c   RTP header pack/parse, RR/SR builders   │
       │    nat.c          FF D3 01 sentinel (CMediaTrans::SendNat)│
       │    jitter.c       recenter-on-early jitter buffer         │
       │    dtmf.c         RFC 4733                                │
       │    h264.c         FU-A packetization                      │
       │    srtp*.c        DTLS-SRTP (mbedtls *or* OpenSSL backend)│
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  Codecs                                                   │
       │    g711.c             µ-law / A-law (built-in)            │
       │    codec_amr.c        AMR-NB + AMR-WB (opencore + vo)     │
       │    codec_ilbc.c       iLBC (libilbc)                      │
       │    codec_opus.c       Opus (libopus)                      │
       │    codec_audio.c      pluggable dispatch table            │
       └───────────────────────────────────────────────────────────┘
       ┌───────────────────────────────────────────────────────────┐
       │  Infra                                                    │
       │    envcfg.c       .env / env-var / CLI-flag precedence    │
       │    tokenstore.c   on-disk session token cache             │
       │    account.c      region prefix, silent-activation        │
       └───────────────────────────────────────────────────────────┘
```

### Component map

| Header (`include/vham/`) | Responsibility |
|---|---|
| `codec.h` | TAP + SRVMSG header layout, IE pack/unpack, all `wMsgId` constants |
| `regreq.h` / `regrsp.h` | `MM_REGREQ` build + digest, `MM_REGRSP` parser + dispatcher redirect |
| `cc.h` | `vham_cc_call_t` state machine; one struct per active call |
| `voice_call.h` | High-level orchestrator: bind RTP, STUN, CC_SETUP, mic-grant, NAT-punch, audio pump |
| `voice.h` | Codec-agnostic TX/RX loop |
| `codec_audio.h` | Pluggable codec table (PT → encode/decode pair) |
| `composites.h` | TLV bodies that recurse inside outer IEs (~20 parsers) |
| `nat.h` | `vham_media_nat_t` — FF D3 01 sentinel state |
| `rtp.h` / `rtcp.h` | RTP header + RTCP RR/SR builders |
| `jitter.h` | Receive-side jitter buffer (configurable depth, recenter-on-early) |
| `oam.h` | Group / org operations (op 5/7/9/10/11/12) |
| `im.h` / `gps.h` | Thin wrappers over PASSTHROUGH |
| `passthrough.h` | PASSTHROUGH framing + IM JSON + YaoYun negotiation |
| `causes.h` | `vham_cause_lookup(code) → {english, chinese}` |
| `sdp.h` | LinkPoon's custom binary SDP (NOT RFC 4566) |
| `srtp.h` | DTLS-SRTP dispatcher + virtual transport |
| `envcfg.h` | Config resolution (CLI > env > .env > `~/.vham/env` > default) |
| `tokenstore.h` | On-disk REGRSP token cache |
| `account.h` | Region prefix derivation, silent-activation hooks |

### Threading model

**libvham is single-threaded.** Every API is synchronous; the caller drives I/O via blocking `recv()` with `SO_RCVTIMEO` for phase deadlines. Long-running flows (e.g. `vham_voice_call_pump_frame`) drain the signaling socket opportunistically on each call so unsolicited server frames (TAP retransmits, CC_MODIFY, CC_REL) are seen without a dedicated thread.

This is intentional: PTT half-duplex inherently has one talker at a time, so single-threaded keeps state ownership simple and means no locking around the seq counter, TAP-ACK bookkeeping, or NAT sentinel timing. A consumer that wants concurrency (e.g. an Android app) owns the thread placement and just calls into the library serially per call.

---

## Quick start

```sh
git clone … && cd libvham
./configure
make
cp .env.example .env       # fill in VHAM_USER / VHAM_PASS
./tools/vham-cli login     # OK  session=0x...  org=...
./tools/vham-cli list      # see your group memberships
./test/live.sh             # 30-check end-to-end smoke test
```

---

## Build

```sh
./configure
make            # builds libvham.a + tests + 6 tools
make test       # runs the 82-test offline suite
```

### Optional dependencies

| Library | Provides | Detection |
|---|---|---|
| `libopus` | Opus codec | `pkg-config opus` → fallback `AC_CHECK_LIB` |
| `libopencore-amrnb` + `libopencore-amrwb` + `libvo-amrwbenc` | AMR-NB + AMR-WB encoders/decoders | header + symbol probe |
| `libilbc` (WebRTC iLBC) | iLBC 20 ms (PT 106) | header + symbol probe |
| `mbedtls` 3.x **or** OpenSSL 1.1+ — both with `libsrtp2` | DTLS-SRTP (AES_CM_128_HMAC_SHA1_80) | Two interchangeable backends. `--with-dtls=auto` (default) prefers mbedtls; `--with-dtls=openssl` forces OpenSSL. mbedtls 4.x is rejected (it removed `mbedtls_ssl_conf_rng`). |

After `./configure`:

```
  libvham build configuration
  ------------------------------
  cc           = gcc
  Opus         = yes
  AMR-NB/WB    = yes
  iLBC         = yes
  DTLS-SRTP    = yes
```

### Manual overrides

```sh
./configure --without-opus
./configure --without-dtls
./configure --with-dtls=openssl       # use OpenSSL instead of mbedtls
./configure --with-dtls=mbedtls       # explicit (default when both present)
./configure --with-amr=no             # same as --without-amr
./configure CC=clang CFLAGS="-O3 -march=native"
./configure --without-opus --without-amr --without-ilbc --without-dtls   # minimal G.711-only
```

`--with-X` (without `=no`) errors if the library isn't found, instead of silently dropping the feature.

### macOS via Homebrew

```sh
brew install opus opencore-amr vo-amrwbenc libilbc libsrtp mbedtls@3
# OR for OpenSSL backend:
brew install opus opencore-amr vo-amrwbenc libilbc libsrtp openssl@3

./configure                       # auto picks whichever DTLS backend is installed
./configure --with-dtls=openssl   # force OpenSSL if both available
make
```

`configure` runs `brew --prefix` automatically and version-pins `mbedtls@3`. The Linux equivalent path uses standard distro packages (Debian: `libopus-dev libopencore-amrnb-dev libopencore-amrwb-dev libvo-amrwbenc-dev libilbc-dev libmbedtls-dev libsrtp2-dev`).

### Re-generating the configure script

```sh
ACLOCAL_PATH=/opt/homebrew/share/aclocal autoreconf -i
```

---

## Configuration via `.env`

Tools never hardcode credentials. They look up values via `vham_env(key, default)` which checks (in order):

1. **CLI flag** (`--user`, `--pass`, …) — always wins
2. **Environment variable** (`VHAM_USER`, `VHAM_PASS`, …)
3. **`./.env`** (current working directory)
4. **`$HOME/.vham/env`** (user-wide)
5. **Default** value

Copy `.env.example` to `.env`:

```sh
# Account
VHAM_USER=V1XXXXXXXXXX
VHAM_PASS=...

# Optional secondary account for two-party tests
VHAM_USER2=V1YYYYYYYYYY
VHAM_PASS2=...

# Server. Accepts host:port or ip:port.
# Known endpoints: us.vham.net (V1), th.vham.net (V2), linkpoon.com (V3)
VHAM_SERVER=us.vham.net:10000

# Per-call defaults (override via --to / --tune / --group)
VHAM_TO=
VHAM_TUNE=
VHAM_GROUP=
```

`.env` is git-ignored. `.env.example` is committed as a template.

---

## Operations in detail

This section is the working manual for every protocol op we drive. Each subsection covers the wire flow, the relevant library functions, and any gotchas seen on live infrastructure.

### Login (registration)

The two-phase RFC 2617 digest auth.

```
client → server :  MM_REGREQ  (no auth)
server → client :  MM_REGRSP  cause=0x02 (CHALLENGE)  + realm + nonce + algorithm
client → server :  MM_REGREQ  + Authorization digest
server → client :  MM_REGRSP  cause=0x00 (OK)         + orgs + groups + media-gw
                  OR
                   MM_REGRSP  cause=0x01 (REDIRECT)   + new dispatcher IP/port
```

**Library:** `vham_reg_client_login()` (regreq.c + regrsp.c) handles both phases and follows a single redirect transparently. If the dispatcher reassigns us, the new IP:port is what gets used for all subsequent ops.

**Things to know:**
- Password convention on `us.vham.net` is `111111` for the public test accounts and silent-activated radios.
- The REGRSP carries the **media gateway IP:port** used as a default destination for CC_SETUP; per-call media moves to a different port once CC_CONN arrives.
- After OK, the server may push **YaoYun feature negotiation** (PASSTHROUGH with a JSON capabilities blob) within ~50 ms. We auto-ack so the server stops retransmitting; otherwise it sits in a 1 s retry loop.

### Channel TX (transmit on a PTT channel)

This is the marquee operation. End-to-end audio confirmed against `us.vham.net` channel 446.001 (May 2026).

```
                                 ┌─ login() ────────────────────────────────┐
                                 │ REGREQ → REGRSP                          │
                                 │ drain YaoYun + STATUSSUBS  ~50 ms        │
                                 └──────────────────────────────────────────┘
                                                ↓
            ┌─────────────────── vham_voice_call_setup() ───────────────────┐
            │  bind RTP socket on MEDPORT_BASE + leg_id*4                   │
            │      (or rtp_port_override for explicit port-forwarding)      │
            │  STUN probe (informational, 500 ms timeout)                   │
            │  build CC_SETUP                                               │
            │     ucSrc=ucDst=4 (MM module)                                 │
            │     SrvType=0x11 (HALF_DUPLEX) ← yes, even for channel        │
            │     IMType=GROUP    ← channel discriminator                   │
            │     IE 0x27/0x28: our num twice                               │
            │     IE 0x45/0x46/0x47: channel num                            │
            │     IE 0x30: groupflag=1, 0x36: bw=64, 0x7a: chan_flag=2      │
            │     SDP IP=0; 5 codecs (AMR, iLBC, PCMU, PCMA, AMR-NB)        │
            │  send CC_SETUP → wait for CC_SETUPACK + CC_CONN               │
            │     (200 ms inner timeout × N iters; 4 s outer deadline)      │
            │  parse per-call media port from CC_CONN's SDP                 │
            │  send CC_CONNACK (bare TAP+SRVMSG, no IEs)                    │
            │  send mic-acquisition triplet:                                │
            │     CC_INFO action=1 (mic-grant)                              │
            │     CC_USERCTRL with MediaAttribute(1,0,0,0)                  │
            │     CC_INFO action=5 (TalkingID announcement)                 │
            │     ── server replies CC_INFOACK (0x56)                       │
            │  vham_media_nat_open → 3× FF D3 01 to media port              │
            │  NAT-punch: 2 silence RTP frames back-to-back                 │
            └───────────────────────────────────────────────────────────────┘
                                                ↓
            ┌─────── audio pump (vham_voice_call_pump_frame, loop) ────────┐
            │  encode one PCM frame → RTP (per-codec packetization)        │
            │  sendto media_dst                                             │
            │  every 2 s: re-send FF D3 01 NAT sentinel                    │
            │  opportunistic recv(sig_fd, MSG_DONTWAIT):                   │
            │      TAP-ACK each non-ACK frame                              │
            │      CC_MODIFY  → re-target media_dst                        │
            │      CC_REL     → return 0, stop pumping                     │
            └──────────────────────────────────────────────────────────────┘
                                                ↓
                          vham_voice_call_release(cause)
                          ── sends CC_REL, closes RTP socket
```

**Library entry points:**
- `vham_voice_call_setup(&vc, &opts)` — everything from bind to NAT-punch
- `vham_voice_call_pump_frame(&vc, pcm, n_samples, marker)` — one audio frame; returns 0 on server CC_REL
- `vham_voice_call_release(&vc, cause)` — CC_REL + socket close

**Gotchas, all hard-won from the bridge:**
- **`SrvType=0x11`, not `0x12`.** The Android `CSAudio.groupAudioCall` source path passes 17 (HALF_DUPLEX), not 18. Channel-vs-user is signalled by `IMType=GROUP` in IE 0x76, not by SrvType.
- **SDP `IP=0` (zero).** Per `CIDTLeg::InitMySdp`. The server learns the source from observed RTP; this also makes source-IP validation lenient when behind cone NAT.
- **Local media port = `MEDPORT_BASE + leg_id*4`** by default (idt.ini `MEDPORT=20000`). Override via `rtp_port_override` when port-forwarding through symmetric NAT.
- **TAP-ACK *everything*.** Without it the server retransmits aggressively (1 s loop). `pump_frame` drains opportunistically; setup phases use a tight `SO_RCVTIMEO`.
- **The TalkingID action=5 INFO is what makes the radio display update.** Without it the audio still bridges, but other listeners' screens never show "X is talking".
- **CC_USERCTRL extra bytes = `01 00 00 00`** — that's `MediaAttribute(ucAudioSend=1, …)` per the Android `new MediaAttribute(1,0,0,0)` site.

### Channel RX (inbound listen)

```
                    vham_cli listen --tune <channel>
                         │
                         ├─ STATUSSUBS for the channel
                         │       (DETAILED + reserved)
                         │
                         │  recv loop:
                         ┴─→  CC_SETUP   ← someone keyed up
                              │
                              ├─ send CC_SETUPACK
                              ├─ parse SDP for per-call media port (IE 0x19)
                              ├─ bind/connect our RTP socket to that port
                              ├─ open NAT sentinel (FF D3 01 × 3 + 2 s tick)
                              ├─ send CC_CONNACK
                              │
                              │  receive RTP, push through jitter, decode
                              │  TAP-ACK every non-ACK signaling frame
                              │
                          CC_REL ← talker unkeyed   →  close call state
                              │   or
                          CC_INFO action=5 (TalkingID) → update display
```

The receive side is fully functional end-to-end and was the first thing verified live. Channel 44600100 on `us.vham.net` (446.001 MHz amateur PTT) is a useful smoke test — anyone keying up triggers the path.

### NAT keepalive

Two distinct keepalives, on two sockets:

1. **Signaling NAT** — `MM_NAT` (`wMsgId 0x1e`) sent over the signaling socket every ~10 s while logged in. Driven by `vham_reg_client_keepalive()`.
2. **Media NAT** — 3-byte `FF D3 01` sentinel sent over the *RTP* socket to the media gateway. 3× at the start of a call, then every 2 s for the call's lifetime. Mirrors `CMediaTrans::SendNat` + `CMediaTrans::Scan` from the binary.

The media NAT is the one that actually matters for audio to flow — without it, the bridge's port mapping for our public endpoint times out within seconds and audio drops.

### Group operations (OAM)

All OAM ops use class 0x02, wMsgId in the LSB. Supported:

| Op | Function | Purpose |
|---|---|---|
| 5 | `vham_build_oam_gadd` | Create a new group |
| 7 | `vham_build_oam_gmodify` | Rename / repri a group |
| 9 | `vham_build_oam_gaddu` | Add user to group (join) |
| 10 | `vham_build_oam_gdelu` | Remove user (leave) |
| 11 | `vham_build_oam_gmodifyu` | Modify user-in-group attrs *(admin-gated on server)* |
| 12 | `vham_build_oam_gqueryu` | Query a group's membership (`--scope` 0–3) |

The CLI bundles `gadd + gaddu + verify` into `vham-cli talkgroup` which surfaces the admin-downgrade behaviour: silent-activated accounts can create groups but the server rewrites `gtype=7 → gtype=2`, so calls between members won't actually bridge.

### PASSTHROUGH: IM, YaoYun, raw

`MM_PASSTHROUGH` (`wMsgId 0x1b`) is the catch-all for non-call user-to-user/user-to-server messages. It carries a 2-tuple `(code, type)` plus an arbitrary `data` blob:

- **IM** = code 1, type 1, data = JSON `{"msg":"...","ts":...}`
- **YaoYun** = code/type pair the server picks; data = feature-capability JSON. Auto-ack to stop the server retransmitting.
- **Anything else** = `vham-cli passthrough --code N --type N --data "..."` for poking unknown ops during reversing.

### DTLS-SRTP handshake

A virtual `BIO`/transport wraps an `int fd` and feeds the DTLS stack with whatever the client received over the per-call media socket. Once handshake completes, RFC 5705 keying material is derived and handed to libsrtp 2 with `AES_CM_128_HMAC_SHA1_80`.

Backends are picked at configure time (`--with-dtls=mbedtls|openssl|auto|no`). Both are interchangeable; the stub used when `--without-dtls` is selected makes the build succeed but the path returns "DTLS not compiled in" at runtime.

Live VHAM channels appear to use plaintext RTP by default — DTLS-SRTP is implemented for protocol completeness and for any deployment that requires it (`CMediaTrans` flags `bSrtp`).

### Token cache

On successful login, the server's session token is persisted to `$HOME/.vham/tokens/<user>` so a subsequent invocation can skip the digest exchange. `vham-cli token show` / `token clear` to inspect / nuke.

This is purely opportunistic; if the cached token is rejected we fall back to the full digest auth path.

---

## Tools

### `vham-cli` — unified PTT client

17 subcommands covering every protocol op we've reversed. All flags default to env values.

| Subcommand | Wire op | Purpose |
|---|---|---|
| `login` | MM_REGREQ | Authenticate, print session id |
| `logout` | MM_QUIT (0x18) | Explicit signoff |
| `list` | — | List group memberships from REGRSP |
| `query` | OAM op 12 GQueryU | Query a specific group; supports `--scope N` |
| `join` | OAM op 9 GAddU | Add self to a group |
| `leave` | OAM op 10 GDelU | Remove self from a group |
| `gadd` | OAM op 5 GAdd | Create a new group (`--gtype` defaults to 7; server downgrades to type 2 for non-admin) |
| `gmodify` | OAM op 7 GModify | Rename / repri a group |
| `gmodifyu` | OAM op 11 GModifyU | Modify user-in-group attrs *(admin-gated by server — returns parameter_error for normal accounts)* |
| `talkgroup` | gadd + gaddu + verify | Bundle: create with type=7, join, then re-login and surface what the server actually stored |
| `im` | MM_PASSTHROUGH | Send a text IM |
| `gps` | MM_GPSREPORT | Push a location update |
| `call` | CC_SETUP | Place a PTT call; watches briefly for ACK / CC_CONN / CC_REL |
| `transmit` | full TX flow | End-to-end channel TX — log in, CC_SETUP, NAT, claim mic, generate or stream audio, CC_REL |
| `listen` | STATUSSUBS + recv loop | Subscribe to a channel; decode notifies / IMs / inbound calls for `--wait` seconds |
| `passthrough` | MM_PASSTHROUGH | Send raw PASSTHROUGH with `--code N --type N --data "..."` |
| `mm <op>` | MM_{ACCREQ,MODREQ,PROFREQ,ROUTEREQ,NATT_PROB,QUIT} | Send any of the auxiliary MM ops |
| `token show\|clear` | — | Manage the persistent token cache |

```sh
./tools/vham-cli                                # prints usage
./tools/vham-cli login                          # reads VHAM_USER/PASS from .env
./tools/vham-cli list
./tools/vham-cli gadd --group 88888 --name "test"
./tools/vham-cli call --to 12345 --wait 5
./tools/vham-cli transmit --tune 44600100 --tone 1000 --duration 2
./tools/vham-cli listen --tune 44600100 --wait 30
./tools/vham-cli mm profreq
VHAM_TIMING=1 VHAM_VC_TIMING=1 ./tools/vham-cli transmit … 2>timing.log
```

### Other tools

| Tool | Purpose |
|---|---|
| `vham-activate` | HTTP Flow-A device activation (silent-activate with a fabricated IMEI) |
| `vham-login` | Standalone MM_REGREQ smoke test (digest auth path) |
| `vham-call` | Build a CC_SETUP frame and optionally `--send` it |
| `vham-session` | Long-running session: login, NAT keepalive, channel subscribe, decoded recv loop |
| `vham-voice` | RTP send/receive with any registered codec; jitter buffer enabled; DTMF support |

---

## Protocol coverage

### Supported

#### MM (mobility management — `wMsgId` class 0x01)

| Id | Name | Direction | Status |
|---|---|---|---|
| `0x10` | REGREQ | C→S | full (digest auth, two-phase with realm+nonce) |
| `0x11` | REGRSP | S→C | full parser (org list, group list, FTP info, dispatcher hop) |
| `0x12` | ACCREQ | C→S | encoder |
| `0x13` | ACCRSP | S→C | known id |
| `0x14` | ROUTEREQ | C→S | encoder |
| `0x15` | ROUTERSP | S→C | known id |
| `0x16` | PROFREQ | C→S | encoder |
| `0x17` | PROFRSP | S→C | known id |
| `0x18` | QUIT | C→S | full |
| `0x19` | MODREQ | C→S | encoder |
| `0x1a` | MODRSP | S→C | known id |
| `0x1b` | PASSTHROUGH | both | full (IM, YaoYun, arbitrary code/type/data) |
| `0x1c` | PROXYREGREQ | C→S | encoder |
| `0x1d` | PROXYREGRSP | S→C | known id |
| `0x1e` | NAT | C→S | full (NAT keepalive) |
| `0x1f` | NATT_PROB | C→S | encoder |
| `0x90` | STATUSSUBS | C→S | full |
| `0x91` | STATUSNOTIFY | S→C | full parser |
| `0x92` | GPSREPORT | C→S | full |

#### CC (call control — class 0x04)

| Id | Name | Direction | Status |
|---|---|---|---|
| `0x50` | SETUP | both | full (SDP, leg id, IE 0x76 IMType heuristic for group calls) |
| `0x51` | SETUPACK | S→C | parsed |
| `0x52` | ALERT | S→C | parsed |
| `0x53` | CONN | both | full |
| `0x54` | CONNACK | both | full |
| `0x55` | INFO | both | full (mic grant + TalkingID actions) |
| `0x56` | INFOACK | both | full (auto-emitted) |
| `0x57` | MODIFY | both | wMsgId defined; encoder missing |
| `0x58` | MODIFYACK | both | wMsgId defined; encoder missing |
| `0x59` | REL | both | full (cause codes) |
| `0x5a` | RLC | both | wMsgId defined; minimal handler |
| `0x5b` | USERCTRL | both | full encoder (`vham_encode_call_userctrl`) + decoder |
| `0x5c` | STREAMCTRL | both | composite parser; encoder missing |
| `0x5d` | CONFSTATUSREQ | C→S | wMsgId defined; no FSM driver |
| `0x5e` | CONFSTATUSRSP | S→C | wMsgId defined; no FSM driver |

#### OAM (operations admin — class 0x02)

| Op | Name | Status |
|---|---|---|
| `5` | GAdd | full encoder + live-verified |
| `7` | GModify | full + live-verified (rename works) |
| `9` | GAddU (join) | full + live-verified |
| `10` | GDelU (leave) | full + live-verified |
| `11` | GModifyU | encoder; server admin-gates (returns 0x28 parameter_error for non-admin) |
| `12` | GQueryU | full + live-verified |

#### Composite IEs (TLV bodies)

OrgList, UsrGInfo, FtpInfo, WatchLeg, LegExt, GpsRec, CamInfo, Info, PlayInfo, ResReport, GMemberExtInfo, CallExt, CallStreamCtrl, CommQuery, FsmPair, NsQueryExt, VerInfo, UsrPos, RouteCfg, GMemStatus, CallUserCtrl — all have parsers; most have encoders.

#### Other

- 95-entry cause-code dictionary (Chinese + English names)
- Token cache (`$HOME/.vham/tokens/`)
- YaoYun feature negotiation (auto-ack)
- Dispatcher hop (server tells client to reconnect; library follows transparently)
- Silent-activation account creation (Flow-A HTTP)

### Partially supported

| Feature | What works | What's missing |
|---|---|---|
| `CC_USERCTRL` | Full encoder + decoder; `claim_mic` uses it | (none — was missing before, now full) |
| `CC_STREAMCTRL` | wMsgId + composite parser | No outbound encoder |
| `CC_MODIFY` / `CC_MODIFYACK` | wMsgIds defined | No encoder for in-call SDP renegotiation |
| Conference (`CC_CONFSTATUSREQ/RSP`) | wMsgIds defined | No FSM driver; needs admin-provisioned conf group to test |
| File-attached IM | PASSTHROUGH JSON + `FtpInfo` parser | No FTP pickup leg — we see the FTP descriptor but don't fetch the attachment |
| Talk-group routing (type=7) | Encoder requests gtype=7 | Server downgrades to type=2 for non-admin; user-to-user calls won't bridge between members |

### Not supported

| Capability | Where it lives in the binary | Effort to add |
|---|---|---|
| **OAM user CRUD** (UAdd/UDel/UModify ops 1/2/3) | `OAM::UAdd` etc. | ~150 LOC, admin-gated |
| **OAM `UQuery` (op 4)** | `OAM::UQuery` | ~40 LOC, possibly works for non-admin |
| **OAM `UQueryG` (op 13)** | `OAM::UQueryG` — "what groups is this user in?" | ~40 LOC |
| **OAM Org CRUD** (OAdd/ODel/OModify/OQuery) | `OAM::OAdd` etc. | ~150 LOC, admin-only |
| **`OAM_NOTIFY` (0x72)** | Server-pushed admin events | ~80 LOC, passive listener |
| **`MM_GPSHISQUERYREQ/RSP` (0x94/0x95)** | `SrvUnpkGpsRecStr` (IE 0x6d) | ~80 LOC, historical track query |
| **`CC_HB` (0x02)** | `CPTM_CC_HB` timer | ~30 LOC, call keep-alive |
| **H.265 (HEVC)** | `H265NalType`, `H265GetFrame` | ~200 LOC, similar to existing H.264 FU-A |
| **GB-28181 SDP profile** | `SdpGenStr_28181_Broadcast` | ~250 LOC, Chinese national surveillance interop |
| **TCP media relay** | `TcpRelayFsm` (separate from RFC 4571) | ~400 LOC, TURN-style UDP-fallback path |
| **Pre-CONN audio buffer** | `UP::FackConnectBufAudioData` | ~150 LOC, prevents first-syllable clipping |
| **Multi-leg conference fan-out** | `CRtpRecvStreamMgr`, `CLegTransMgr` | ~400 LOC + needs admin conf group |
| **WebRTC audio processing** (AEC, NS, AGC, VAD) | ~477 `webrtc::` symbols | out of scope (client-side DSP) |
| **JNI / Android display bridge** | `PJniEnvTable`, ANativeWindow, libyuv | out of scope (Android-specific) |
| **MML interactive shell** | `POam*`, `IdtMml*` | out of scope (debug-only) |

---

## Media reality check

We have working encoders for six codecs, but the LinkPoon bridge at `us.vham.net` does *not* actually accept all of them on the wire. Tested against live channel 44600100 in May 2026:

| Codec | PT | Wire spec | Live result |
|---|---|---|---|
| **PCMU (G.711 µ-law)** | 0 | 20 ms / 160 B + RTP | ✅ end-to-end works |
| **PCMA (G.711 A-law)** | 8 | 20 ms / 160 B + RTP | ✅ end-to-end works |
| **iLBC** | 106 | **60 ms** / 3× 38-byte frames = 114 B payload | ✅ **preferred codec** (matches `idt.ini CODE=106 PKGTIME=60`) |
| **AMR-NB** | 96 | RFC 4867 BE single-frame | ❌ encoder is correct, but the bridge doesn't actually decode AMR — see below |
| **AMR-WB** | 107 | RFC 4867 BE | ❌ not advertised by the channel bridge |
| **Opus** | 106 PT (Opus profile) | 20 ms | ❌ not advertised by the bridge |

**Critical: PT 97 "AMR" on vham.net is not real AMR.**

The bridge's PT 97 stream is 39 bytes per frame regardless of mode — no RFC 4867 AMR-NB sizing matches that. What does match: **1-byte CMR-shaped header + 38-byte iLBC-20ms frame** (RFC 3952). The bridge is transcoding the radio's native iLBC into a custom wrapping and labeling it PT 97 / "AMR" for SDP advertisement. A standard AMR encoder produces bytes the bridge won't decode.

**Practical advice:**
- For TX, use **iLBC at PT 106 with 60 ms packetization** — that's the radio's preferred codec, validated end-to-end.
- PCMU / PCMA also work end-to-end and are useful for cross-codec testing.
- Keep AMR-NB and AMR-WB encoders in the build for SDP advertisement / future deployments that *do* speak standards-compliant AMR — but don't rely on them as primary on vham.net.

The AMR analysis is captured in `src/codec_amr.c` (the BE serializer is correct per binary disassembly), and the rationale for keeping it stems from `RTP_AMR_WriteOneFrame @ 0x2495b8` being a real RFC 4867 path — just not the one the channel bridge uses.

---

## Performance: call setup latency

Median call setup, login through first audio frame on `us.vham.net`:

| Phase | Time | Notes |
|---|---|---|
| Login (REGREQ → REGRSP) | ~170 ms | Two round-trips (dispatcher redirect) |
| Drain YaoYun + STATUSSUBS | ~50 ms | Pipelined; both fire then 50 ms drain |
| `voice_call_setup`: bind + STUN | ~20 ms | STUN times out fast (500 ms); proceeds with IP=0 |
| CC_SETUP → CC_SETUPACK → CC_CONN | ~800–1000 ms | Server RTT bound, 3 round-trips |
| Mic-grant triplet + NAT-punch | ~20 ms | Fire-and-go; 2 silence frames immediate |
| **Total** | **~2.0–2.2 s** | down from 6.6 s baseline (68% reduction) |

Profile a run with `VHAM_TIMING=1 VHAM_VC_TIMING=1 ./tools/vham-cli transmit …` — each major phase emits a wall-clock + delta line to stderr. The remaining latency is genuine server RTT; further reduction needs server-side changes.

---

## Testing

### Offline (no network)

```sh
make test                # 82 unit tests
```

Covers wire-format encoders + decoders for every supported protocol op, codec round-trips for all backends, jitter buffer, segmentation, retransmission, token persistence, MD5 vectors, digest-auth conformance, captured-bytes pinning.

### Live (talks to a real server, needs `.env`)

```sh
./test/live.sh           # 30-check end-to-end smoke test
```

Covers:

1. Offline unit tests
2. Codec loopback (6 codecs through dispatch table + jitter buffer)
3. Live registration
4. Group ops (list, query, gadd, join, gmodify, leave, talkgroup)
5. IM / GPS / passthrough send
6. Auxiliary MM ops (profreq, modreq, routereq, accreq, nattprob)
7. Token cache lifecycle
8. Two-account PTT signaling (caller emits CC_SETUP; listener decodes inbound activity)

Each check is green/red/yellow with a one-line label. Exit code = number of failed checks. Section 8 is skipped automatically if `VHAM_USER2` / `VHAM_PASS2` aren't set.

---

## Layout

```
configure.ac          autoconf source
configure             generated configure script (committed; users don't need autotools)
Makefile.in           Makefile template
build-aux/            install-sh

include/vham/         public headers (one per module)
src/                  implementation
  codec.c               TAP / SRVMSG framing, IE pack/unpack
  md5.c, auth.c         RFC 2617 digest
  regreq.c, regrsp.c    MM_REGREQ / MM_REGRSP + redirect handler
  cc.c                  CC FSM (SETUP/CONN/INFO/REL)
  voice_call.c          high-level voice-call orchestrator
  voice.c               codec-dispatch RTP TX/RX
  oam.c                 OAM op encoders (5, 7, 9, 10, 11, 12)
  passthrough.c         MM_PASSTHROUGH + IM + YaoYun
  im.c, gps.c           helpers above passthrough
  composites.c          parsers for ~20 TLV body types
  causes.c              95-entry cause-code dictionary
  sdp.c                 binary SDP build/parse
  rtp.c, rtcp.c         RTP / RTCP
  nat.c                 FF D3 01 media-NAT sentinel
  jitter.c              recenter-on-early jitter buffer
  segment.c, retx.c     large-frame handling
  codec_audio.c         dispatch table
  codec_opus.c          (built when WITH_OPUS)
  codec_amr.c           (built when WITH_AMR)
  codec_ilbc.c          (built when WITH_ILBC)
  srtp.c                DTLS-SRTP dispatcher / stub
  srtp_mbedtls.c        DTLS-SRTP backend — mbedtls 3
  srtp_openssl.c        DTLS-SRTP backend — OpenSSL 1.1+
  h264.c                FU-A
  account.c             region prefix / silent-activation
  tokenstore.c          on-disk token cache
  envcfg.c              .env loader

tools/
  vham-cli.c            unified PTT client (17 subcommands)
  vham-session.c        long-running session
  vham-voice.c          RTP send/receive
  vham-login.c          standalone REGREQ smoke
  vham-call.c           CC_SETUP builder
  vham-activate.c       Flow-A HTTP activation

test/
  test_codec.c          82-test offline suite
  test_fixtures.h       parameterized test names (override via VHAM_TEST_*)
  mock_server.c/.h      in-process mock for regreq tests
  live.sh               30-check end-to-end live smoke

../protocol-spec/       wire-format documentation (sibling directory)
```

---

## Legal and ethical use

### Origin and scope

This project documents the wire format and client behavior of a proprietary protocol by static analysis of a publicly distributed Android app (`libsvcapi.so` from the LinkPoon app), for the purpose of independent interoperability. It contains no copied source code and reproduces no proprietary code paths byte-for-byte. The protocol's intellectual-property holders are not affiliated with, nor have they endorsed, this work. All trademarks are the property of their respective owners.

The library is published under the terms in `LICENSE`. It is provided **as-is, without warranty of any kind**; the authors disclaim all liability for any use, misuse, damages, or other consequences arising from running it.

### Required authorization

Running libvham against any server requires explicit, prior authorization from that server's operator. The default endpoints (`us.vham.net`, `th.vham.net`, `linkpoon.com`, and any successor or affiliated infrastructure) are LinkPoon's commercial production network. **Do not run libvham against these endpoints, or any other VHAM-compatible server, except with accounts and on infrastructure you have written permission to test.**

In particular, the existence of a publicly-known default password on the LinkPoon network (see [security review notes](#) — `111111` is shipped as the universal default on silent-activated accounts) does *not* constitute permission to log in as accounts that aren't yours. Account credentials that *happen to be guessable* are still other people's credentials. Logging in as another user without authorization is unlawful in virtually every jurisdiction this software might run in, irrespective of how weak the password is.

### Prohibited uses

You may not use libvham (or any derivative work) to:

- **Impersonate** another user — log into accounts that aren't yours, send PASSTHROUGH/IM messages as another party, transmit voice on radio channels under another user's callsign or display name, or otherwise represent yourself as a third party.
- **Surveil** third parties — passively or actively collect GPS reports, IMs, voice traffic, presence, channel membership, or any other personally identifiable information of users who have not consented to being observed.
- **Disrupt** the network or its users — flood channels, tear down third-party calls via CC_REL, fabricate accounts to abuse free-tier limits, or interfere with normal operations.
- **Create accounts on infrastructure you do not own.** The `vham-activate` tool exists to document the silent-activation HTTP flow we observed in the wild. Using it against LinkPoon's servers (or any server you don't operate) creates accounts on someone else's commercial infrastructure without their consent.
- **Transmit on licensed radio spectrum without proper authorization.** PTT calls bridged through VHAM that egress onto amateur radio channels (e.g. 446.xxx MHz) are subject to the radio regulations of the jurisdiction where the egress occurs — including, in the United States, **FCC Part 97**. Transmitting under a callsign that is not your own, or without a valid license for the band you're hitting, is a federal offense in the US and broadly illegal elsewhere. The fact that the protocol allows it doesn't make it lawful.

### Security research and responsible disclosure

If you discover security weaknesses in the LinkPoon network or in any VHAM-compatible deployment, please disclose them responsibly to the operator before publishing exploit-grade material. Coordinated disclosure protects users; uncoordinated disclosure puts them at risk. The authors of libvham are not responsible for, and do not endorse, weaponization of any finding documented in this repository.

If you are a representative of LinkPoon (or any other VHAM operator) and wish to coordinate on remediating the issues this codebase implicitly documents, open an issue or contact the maintainers privately.

### Export and dual-use

libvham implements cryptographic primitives via mbedtls / OpenSSL / libsrtp 2. Users are responsible for ensuring their use complies with the export-control regimes of their jurisdiction (e.g. EAR in the US, the EU Dual-Use Regulation). The library itself contains no novel cryptography and uses standard implementations of public algorithms.

### No agency, no endorsement

Nothing in this README, the project's documentation, or any associated communications should be read as legal advice. If you are unsure whether a particular use is lawful, consult an attorney in your jurisdiction *before* running the software.
