#!/usr/bin/env bash
# Start the local HTTP API and wait until it answers, then print how to reach it.
#
# usage: serve-start.sh [--listen <addr>]
#   default: a Unix socket under this packet's state directory.
#
# A Unix socket is the default here for the same reason it is smolvm's: the API
# has no authentication of any kind, so the socket's file permissions are the
# only boundary there is. Over loopback TCP the boundary is the whole machine.

set -uo pipefail

STATE_DIR="${SMOLVM_SKILL_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/smolvm-skills}"
mkdir -p "$STATE_DIR"

LISTEN="unix://$STATE_DIR/local-api.sock"
if [ "${1:-}" = "--listen" ]; then LISTEN="$2"; fi

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

case "$LISTEN" in
    unix://*)
        SOCK="${LISTEN#unix://}"
        rm -f "$SOCK"
        CURLOPTS=(-s --unix-socket "$SOCK")
        BASE="http://localhost"
        ;;
    *)
        CURLOPTS=(-s)
        BASE="http://$LISTEN"
        ;;
esac

"$SMOLVM" serve start --listen "$LISTEN" > "$STATE_DIR/local-api.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$STATE_DIR/local-api.pid"
printf '%s\n' "$LISTEN" > "$STATE_DIR/local-api.listen"

# Assert a value from /health, not that the process is alive: the server writes
# its listening line before it can answer, and a dead server leaves a stale pid.
# 60 s: the server answered /health in 1 s on both hosts here. This is the
# margin for a loaded host, not an expected wait.
health=""
waited=0
while [ "$waited" -lt 60 ]; do
    health="$(curl "${CURLOPTS[@]}" "$BASE/health" 2>/dev/null)"
    case "$health" in *'"status":"ok"'*) break ;; esac
    sleep 1
    waited=$((waited + 1))
done

case "$health" in
    *'"status":"ok"'*)
        printf 'listen=%s\n' "$LISTEN"
        printf 'pid=%s\n' "$pid"
        printf 'health=%s\n' "$health"
        printf 'ready_after_s=%s\n' "$waited"
        printf 'result=serving\n'
        ;;
    *)
        printf 'result=failed\n'
        printf 'log:\n'
        sed 's/^/  /' "$STATE_DIR/local-api.log"
        exit 1
        ;;
esac

# `serve start` also clears VM directories a crashed or force-killed run left
# behind, which is worth knowing before reporting those as a leak.
if grep -q 'Reclaimed' "$STATE_DIR/local-api.log" 2>/dev/null; then
    grep 'Reclaimed' "$STATE_DIR/local-api.log" | sed 's/^/note: /'
fi
