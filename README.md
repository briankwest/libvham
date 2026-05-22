# libvham

A clean-room C reimplementation of the **VHAM / IDS-IDTMA** push-to-talk-over-cellular protocol, reverse-engineered from `libsvcapi.so` shipped in the LinkPoon Android app.

- **13,375 LOC** across 30+ source files
- **82 unit tests** + 30-check live test suite (`test/live.sh`)
- **17 CLI subcommands** in `vham-cli` covering every wire op we've reversed
- **6 audio codecs** (PCMU, PCMA, AMR-NB, AMR-WB, iLBC, Opus)
- **Real DTLS-SRTP** via mbedtls 3 + libsrtp 2
- **Autoconf-based** build with auto-detection of optional libraries
- Zero hardcoded credentials — all config via `.env`

---

## Table of Contents

- [What this is](#what-this-is)
- [Quick start](#quick-start)
- [Build](#build)
  - [Optional dependencies](#optional-dependencies)
  - [Manual overrides](#manual-overrides)
  - [macOS via Homebrew](#macos-via-homebrew)
- [Configuration via `.env`](#configuration-via-env)
- [Tools](#tools)
  - [`vham-cli` — unified PTT client](#vham-cli--unified-ptt-client)
  - [Other tools](#other-tools)
- [Protocol coverage](#protocol-coverage)
  - [Supported](#supported)
  - [Partially supported](#partially-supported)
  - [Not supported](#not-supported)
- [Testing](#testing)
- [Layout](#layout)
- [Legal](#legal)

---

## What this is

VHAM (LinkPoon's PoC stack) implements a Chinese-origin "IDS-IDTMA" protocol that runs entirely over UDP and provides:

- Half-duplex PTT calls (1-to-1 and group)
- Talk-groups (admin-provisioned) and personal contact lists (user-creatable)
- IM (text over PASSTHROUGH), GPS reporting, presence
- Channel subscribe / status notifications
- DTLS-SRTP option for media encryption
- RTP-over-TCP fallback (RFC 4571) for restricted networks

The original `libsvcapi.so` is a stripped C++ shared library with ~3,800 mangled symbols. `libvham` is a portable C library that reimplements the protocol's wire format and the client-side state machines needed to interoperate with the public LinkPoon servers (`us.vham.net`, `th.vham.net`, `linkpoon.com`).

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
| `libopus` | Opus codec (PT 106) | `pkg-config opus` → fallback `AC_CHECK_LIB` |
| `libopencore-amrnb` + `libopencore-amrwb` + `libvo-amrwbenc` | AMR-NB (PT 96) + AMR-WB (PT 97) | header + symbol probe |
| `libilbc` (WebRTC iLBC) | iLBC 20ms (PT 102) | header + symbol probe |
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
# OR for OpenSSL backend (already installed by default on most systems):
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
| `im` | MM_PASSTHROUGH | Send a text IM (PASSTHROUGH with IM JSON) |
| `gps` | MM_GPSREPORT | Push a location update |
| `call` | CC_SETUP | Place a PTT call; watches briefly for ACK / CC_CONN / CC_REL |
| `listen` | STATUSSUBS + recv loop | Subscribe to a channel; decode notifies / IMs / inbound calls for `--wait` seconds |
| `passthrough` | MM_PASSTHROUGH | Send raw PASSTHROUGH with `--code N --type N --data "..."` |
| `mm <op>` | MM_{ACCREQ,MODREQ,PROFREQ,ROUTEREQ,NATT_PROB,QUIT} | Send any of the auxiliary MM ops |
| `token show\|clear` | — | Manage the persistent token cache |

```sh
./tools/vham-cli                            # prints usage
./tools/vham-cli login                      # reads VHAM_USER/PASS from .env
./tools/vham-cli list
./tools/vham-cli gadd --group 88888 --name "test"
./tools/vham-cli talkgroup --group 99999    # surfaces admin gate
./tools/vham-cli call --to 12345 --wait 5
./tools/vham-cli listen --tune 12345 --wait 30
./tools/vham-cli mm profreq
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
| `0x55` | INFO | both | full (mic grant decode) |
| `0x56` | INFOACK | both | full (auto-emitted) |
| `0x57` | MODIFY | both | wMsgId defined; encoder missing |
| `0x58` | MODIFYACK | both | wMsgId defined; encoder missing |
| `0x59` | REL | both | full (cause codes) |
| `0x5a` | RLC | both | wMsgId defined; minimal handler |
| `0x5b` | USERCTRL | both | composite (`CallUserCtrl`) parser; encoder missing |
| `0x5c` | STREAMCTRL | both | composite (`CallStreamCtrl`) parser; encoder missing |
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

#### Media

- **G.711 µ-law (PCMU, PT 0)** — built in
- **G.711 A-law (PCMA, PT 8)** — built in
- **AMR-NB (PT 96)** — opencore-amrnb (MR122 by default, 32-byte frame)
- **AMR-WB (PT 97)** — vo-amrwbenc + opencore-amrwb (mode 8, 23.85 kbps)
- **iLBC (PT 102)** — libilbc, 20 ms / 38 bytes
- **Opus (PT 106)** — libopus, 48 kHz mono 20 ms
- **RTP / RTCP** — full sender + receiver paths
- **RTP-over-TCP** — RFC 4571 framing
- **Jitter buffer** — recenter-on-early, configurable depth
- **DTMF** — RFC 4733 (PT 101)
- **H.264** — FU-A packetization, NALU parsing
- **DTLS-SRTP** — pluggable backend (mbedtls 3 *or* OpenSSL 1.1+) with virtual transport, RFC 5764 key derivation via RFC 5705, libsrtp 2 cipher (AES_CM_128_HMAC_SHA1_80). Choose at configure time with `--with-dtls=mbedtls|openssl|auto|no`.
- **Segmentation + retx** — for large composite frames over UDP

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
| `GModifyU` (OAM op 11) | Wire format correct (byte-identical to GAddU) | Server returns `parameter_error` for non-admin accounts — this is server policy, not a bug |
| `CC_USERCTRL` / `CC_STREAMCTRL` | wMsgIds + composite parsers | No outbound encoder; no FSM integration |
| `CC_MODIFY` / `CC_MODIFYACK` | wMsgIds defined | No encoder for in-call SDP renegotiation |
| Conference (`CC_CONFSTATUSREQ/RSP`) | wMsgIds defined | No FSM driver; needs admin-provisioned conf group to test |
| File-attached IM | PASSTHROUGH JSON + `FtpInfo` parser | No FTP pickup leg — we see the FTP descriptor but don't fetch the attachment |
| Talk-group routing (type=7) | Encoder requests gtype=7 | Server downgrades to type=2 for non-admin; calls won't bridge between members |
| PTT channel RX | **Full end-to-end** — joins channel, auto-answers `CC_SETUP`, NAT-punches per-call port (from `IE 0x19 SDP` in the inbound `CC_SETUP`), receives AMR-WB RTP. Live-verified against `us.vham.net` channel 44600100 (446.001 MHz amateur). | — |
| PTT channel TX | Encoder sends correct `CC_SETUP` with `IMType=GROUP`, leg_id=9, subcode=`00`. Server `TAP-ACK`s. RTP sent to media gateway. | Server doesn't return `CC_SETUPACK`/`CC_CONN` and never allocates a per-call media port — silent-activated accounts are gated to RX-only on amateur channels. Admin would need to link the vhamid to an FCC callsign via `findVhamid` to permit TX. |
| AMR-WB RTP packetization | Encoder/decoder via libvo-amrwbenc + libopencore-amrwb (offline round-trips work) | Encoder writes IF1 storage format (TS 26.201 §A.2). RTP-wire needs RFC 4867 §4.4 octet-aligned conversion — ~50 LOC outstanding. |

### Not supported

| Capability | Where it lives in the binary | Effort to add |
|---|---|---|
| **OAM user CRUD** (UAdd/UDel/UModify ops 1/2/3) | `OAM::UAdd` etc., `IDT_UAdd` JNI | ~150 LOC, static OK, but server admin-gated like GModifyU |
| **OAM `UQuery` (op 4)** | `OAM::UQuery` | ~40 LOC, possibly works for non-admin |
| **OAM `UQueryG` (op 13)** | `OAM::UQueryG` — "what groups is this user in?" | ~40 LOC |
| **OAM Org CRUD** (OAdd/ODel/OModify/OQuery) | `OAM::OAdd` etc. | ~150 LOC, admin-only |
| **`OAM_NOTIFY` (0x72)** | Server-pushed admin events | ~80 LOC, passive listener |
| **`OAM_CTRL` (0x73)** | Admin control messages | passive parser |
| **`OAM_SETID` (0x74)** | ID assignment | passive parser |
| **`MM_GPSHISQUERYREQ/RSP` (0x94/0x95)** | `MM::GpsHisQuery`, `SrvUnpkGpsRecStr` (IE 0x6d) | ~80 LOC, historical GPS track query |
| **`CC_HB` (0x02)** | `CPTM_CC_HB` timer | ~30 LOC, call keep-alive |
| **H.265 (HEVC)** | `H265NalType`, `H265GetFrame` | ~200 LOC, similar to existing H.264 FU-A |
| **GB-28181 SDP profile** | `SdpGenStr_28181_Broadcast` | ~250 LOC, Chinese national surveillance interop |
| **TCP media relay** | `TcpRelayFsm`, `TcpRelayMgr` (separate from RFC 4571) | ~400 LOC, TURN-style UDP-fallback path |
| **Pre-CONN audio buffer** | `UP::FackConnectBufAudioData` | ~150 LOC, prevents first-syllable clipping |
| **Multi-leg conference fan-out** | `CRtpRecvStreamMgr`, `CLegTransMgr` | ~400 LOC + needs admin conf group |
| **SIM CRC32 device fingerprint** | `PGetSimCrc32` | needs format reverse |
| **WebRTC audio processing** (AEC, NS, AGC, VAD) | ~477 `webrtc::` symbols | out of scope (client-side DSP, not protocol) |
| **JNI / Android display bridge** | `PJniEnvTable`, ANativeWindow, libyuv | out of scope (Android-specific) |
| **MML interactive shell** | `POam*`, `IdtMml*`, `PStfMml*` | out of scope (debug-only) |

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
configure             generated configure script (commit so users don't need autotools)
Makefile.in           Makefile template
build-aux/            install-sh

include/vham/         public headers (one per module)
src/                  implementation
  codec.c               TAP / SRVMSG framing, IE pack/unpack
  md5.c, auth.c         RFC 2617 digest
  regreq.c, regrsp.c    MM_REGREQ / MM_REGRSP + redirect handler
  cc.c                  CC FSM (SETUP/CONN/INFO/REL)
  oam.c                 OAM op encoders (5,7,9,10,11,12)
  passthrough.c         MM_PASSTHROUGH + IM + YaoYun
  im.c, gps.c           helpers above passthrough
  composites.c          parsers for ~20 TLV body types
  causes.c              95-entry cause-code dictionary
  sdp.c                 SDP build/parse
  rtp.c, rtcp.c         RTP / RTCP
  jitter.c              recenter-on-early jitter buffer
  segment.c, retx.c     large-frame handling
  voice.c               codec-dispatch TX/RX
  codec_audio.c         dispatch table
  codec_opus.c          (built when WITH_OPUS)
  codec_amr.c           (built when WITH_AMR)
  codec_ilbc.c          (built when WITH_ILBC)
  srtp.c                DTLS-SRTP dispatcher / stub
  srtp_mbedtls.c        DTLS-SRTP backend — mbedtls 3 (built when --with-dtls=mbedtls)
  srtp_openssl.c        DTLS-SRTP backend — OpenSSL 1.1+ (built when --with-dtls=openssl)
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

## Legal

This project documents the wire format and client behavior of a proprietary protocol by static analysis of a publicly distributed Android app, for interoperability purposes. It contains no copied source code and no proprietary code-paths reproduced byte-for-byte. The protocol's intellectual-property holders are not affiliated with this work.

Use against any server requires authorization from that server's operator. The default endpoints (`us.vham.net`, `th.vham.net`, `linkpoon.com`) are LinkPoon's commercial infrastructure — only use accounts you have permission to use.

`SPDX-License-Identifier: MIT`
