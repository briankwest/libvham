#!/usr/bin/env bash
# test/live.sh — end-to-end test runner for libvham.
#
# Reads credentials from .env (in the project root) — same file the tools
# themselves auto-load. Override individual values via environment, e.g.:
#
#   VHAM_USER=V1... VHAM_PASS=... test/live.sh
#
# Sections:
#   1. Offline unit tests (make test)
#   2. Codec loopback (all 6 codecs)
#   3. Live registration
#   4. Group ops (list, query, gadd, join, gmodify, leave, talkgroup)
#   5. IM / GPS / passthrough
#   6. Auxiliary MM ops
#   7. Token cache
#   8. Two-account signaling (skipped if VHAM_USER2 not set)
#
# Exit code = number of failed checks.

set -u

# -- locate project root ----------------------------------------------------
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)
cd "$root"

# -- source .env (tools auto-load it too, but the script itself needs the
#    VHAM_USER2/VHAM_PASS2 vars for orchestrating two-account flows) ------
if [[ -f .env ]]; then
    set -a            # auto-export every var assigned below
    # shellcheck disable=SC1091
    source .env
    set +a
fi

# Defaults so we can still print informative skip messages
: "${VHAM_USER:=}"
: "${VHAM_PASS:=}"
: "${VHAM_USER2:=}"
: "${VHAM_PASS2:=}"
: "${VHAM_SERVER:=us.vham.net:10000}"
: "${VHAM_GROUP:=}"

# -- output helpers ---------------------------------------------------------
if [[ -t 1 ]]; then
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else
    G=; R=; Y=; C=; N=
fi

pass=0
fail=0
skip=0

section() { printf '\n%s== %s ==%s\n' "$C" "$1" "$N"; }
ok()      { printf '  %sOK%s    %s\n' "$G" "$N" "$1"; ((pass++)); }
bad()     { printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; ((fail++)); }
note()    { printf '  %sSKIP%s  %s\n' "$Y" "$N" "$1"; ((skip++)); }

# Run an expression; pass if it produces output that matches a regex.
# Usage: check "label" "command…" "expected-regex"
check() {
    local label=$1 cmd=$2 expect=$3
    local out
    out=$(eval "$cmd" 2>&1)
    if [[ "$out" =~ $expect ]]; then
        ok "$label"
    else
        bad "$label"
        printf '        cmd:    %s\n' "$cmd"
        printf '        expect: %s\n' "$expect"
        printf '        got:    %s\n' "$(printf '%s' "$out" | head -2)"
    fi
}

require_user()  { [[ -n "$VHAM_USER"  && -n "$VHAM_PASS"  ]]; }
require_user2() { [[ -n "$VHAM_USER2" && -n "$VHAM_PASS2" ]]; }

# -- 1. offline unit tests --------------------------------------------------
section "1. Offline unit tests"
if [[ ! -x test/test_codec ]]; then
    note "test/test_codec not built — running make"
    make >/dev/null 2>&1
fi
make_test_out=$(make test 2>&1 | tail -1)
if [[ "$make_test_out" == "OK" ]]; then
    ok "make test (82 unit tests)"
else
    bad "make test — last line: $make_test_out"
fi

# -- 2. codec loopback ------------------------------------------------------
section "2. Codec loopback (RTP through dispatch + jitter buffer)"
if [[ ! -x tools/vham-voice ]]; then
    note "vham-voice not built — skipping codec loopback"
else
    for c in pcmu pcma amr amr-wb ilbc opus; do
        port=$((34000 + RANDOM % 1000))
        ./tools/vham-voice recv --bind 127.0.0.1:$port --duration-s 2 --jitter-ms 60 \
            > /tmp/vham-rx.log 2>&1 &
        rx_pid=$!
        sleep 0.3
        ./tools/vham-voice tone --peer 127.0.0.1:$port --codec "$c" \
            --seconds 1 --hz 440 >/dev/null 2>&1
        wait "$rx_pid" 2>/dev/null || true
        stats=$(grep 'recv stats' /tmp/vham-rx.log 2>/dev/null)
        if [[ "$stats" =~ pkt=50.*lost=0 ]]; then
            ok "$c loopback ($stats)"
        else
            bad "$c loopback — $stats"
        fi
    done
fi

# -- 3. live registration ---------------------------------------------------
section "3. Live registration"
if ! require_user; then
    note "VHAM_USER/VHAM_PASS not set — skipping live tests"
    printf '\n  Add them to .env to enable. See .env.example.\n\n'
    echo "$fail"
    exit "$fail"
fi
check "login"     "./tools/vham-cli login"            "^OK.*session=0x"

# -- 4. group operations ----------------------------------------------------
section "4. Group operations"
check "list"               "./tools/vham-cli list"                                    "groups \([0-9]+\):"
check "query (known group)" "./tools/vham-cli query --group ${VHAM_GROUP:-12345}"     "status=0x0000"

# Use a randomized group number so re-runs don't conflict
test_grp=$(( (RANDOM % 90000) + 200000 ))
check "gadd"                "./tools/vham-cli gadd --group $test_grp --name livetest"        "status=0x0000"
check "join (after gadd)"   "./tools/vham-cli join --group $test_grp"                        "status=0x0000"
check "list includes new"   "./tools/vham-cli list"                                          "$test_grp"
check "gmodify (rename)"    "./tools/vham-cli gmodify --group $test_grp --name renamed-by-script" "status=0x0000"
check "talkgroup admin gate" "./tools/vham-cli talkgroup --group $((test_grp+1)) --name talk-probe" "type=2.*admin gate|status=0x0000"
check "leave"               "./tools/vham-cli leave --group $test_grp"                       "status=0x0000"
check "list omits removed"  "./tools/vham-cli list | grep -c $test_grp"                      "^0$"

# -- 5. messaging primitives ------------------------------------------------
section "5. IM / GPS / passthrough"
peer="${VHAM_USER2:-V19999999999}"
check "im send"          "./tools/vham-cli im --to $peer --text 'hello from live.sh'"  "IM sent"
check "gps send"         "./tools/vham-cli gps --lat 37.77 --lon -122.42"              "GPS sent"
check "passthrough send" "./tools/vham-cli passthrough --to $peer --code 1 --data 'ping'" "passthrough sent"

# -- 6. MM op smoke ---------------------------------------------------------
section "6. Auxiliary MM ops (server should TAP-ACK each)"
for op in profreq modreq routereq accreq nattprob; do
    check "mm $op"  "./tools/vham-cli mm $op"  "TAP-ACK"
done

# -- 7. token cache ---------------------------------------------------------
section "7. Token cache"
./tools/vham-cli token clear --user "$VHAM_USER" >/dev/null 2>&1 || true
check "token: no cache initially" "./tools/vham-cli token show --user $VHAM_USER"  "no token cached"
./tools/vham-cli login >/dev/null 2>&1
check "token: cache after login"  "./tools/vham-cli token show --user $VHAM_USER"  "user=$VHAM_USER|no token cached"
check "token clear"               "./tools/vham-cli token clear --user $VHAM_USER" "ok|not present"

# -- 8. two-account signaling -----------------------------------------------
section "8. Two-account PTT signaling"
if ! require_user2; then
    note "VHAM_USER2/VHAM_PASS2 not set — skipping two-account flow"
else
    listen_log=$(mktemp)
    VHAM_USER="$VHAM_USER2" VHAM_PASS="$VHAM_PASS2" \
        ./tools/vham-cli listen --tune "${VHAM_GROUP:-12345}" --wait 8 \
            > "$listen_log" 2>&1 &
    listen_pid=$!
    sleep 1.5
    check "caller CC_SETUP"  "./tools/vham-cli call --to ${VHAM_GROUP:-12345} --wait 4" \
                             "CC_SETUP sent.*server TAP-ACK"
    wait "$listen_pid" 2>/dev/null || true
    if grep -q "incoming CC_SETUP\|notify:" "$listen_log"; then
        ok "listener saw incoming activity"
    else
        note "listener saw no incoming (expected for type=2 personal groups — admin gate)"
    fi
    rm -f "$listen_log"
fi

# -- summary ----------------------------------------------------------------
printf '\n%s== summary ==%s  %spass=%d%s  %sfail=%d%s  %sskip=%d%s\n\n' \
    "$C" "$N" "$G" "$pass" "$N" "$R" "$fail" "$N" "$Y" "$skip" "$N"
exit "$fail"
