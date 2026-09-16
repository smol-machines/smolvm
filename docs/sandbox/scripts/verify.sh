#!/usr/bin/env bash
# Assert the sandbox held: from inside the guest, and from the host afterwards.
#
# usage: verify.sh [--repo <dir>] [--out <dir>] [--expect-file <name>]
#                  [--expect <value>] [--image <img>] [--route offline|network-on]
#
# Two halves, and both are needed. The inside half proves the workload could not
# write the repo and could not reach the network; the host half proves the
# artifact came out and the repo is unchanged. A run that "succeeded" tells you
# neither.

set -uo pipefail

REPO="./repo"
OUT="./out"
EXPECT_FILE="result.txt"
EXPECT=""
IMAGE="python:3.12-alpine"
ROUTE="offline"

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)        REPO="$2"; shift ;;
        --out)         OUT="$2"; shift ;;
        --expect-file) EXPECT_FILE="$2"; shift ;;
        --expect)      EXPECT="$2"; shift ;;
        --image)       IMAGE="$2"; shift ;;
        --route)       ROUTE="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

printf 'route=%s\n' "$ROUTE"
REPO="$(cd "$REPO" && pwd)"
OUT="$(cd "$OUT" && pwd)"

# The probe must run in the same shape as the real run, or it proves nothing
# about that run. On the network-on route the workload has egress by
# construction, so the network assertion changes rather than disappearing.
case "$ROUTE" in
    offline)    cache=(--oci-cache); net=();       expect_net=blocked ;;
    network-on) cache=();            net=(--net);  expect_net=REACHED ;;
    *) printf 'unknown route: %s (offline or network-on)\n' "$ROUTE" >&2; exit 2 ;;
esac

fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '%s=ok (%s)\n' "$1" "$2"
    else
        printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"
        fail=1
    fi
}

# --- from inside the guest, in the same shape a real run uses ----------------
inside="$("$SMOLVM" machine run --mem 2048 ${cache[@]+"${cache[@]}"} ${net[@]+"${net[@]}"} --image "$IMAGE" \
    --volume "$REPO:/workspace:ro" \
    --volume "$OUT:/out" \
    -- sh -c '
        touch /workspace/SANDBOX_PROBE 2>/dev/null && echo "workspace=WRITABLE" || echo "workspace=readonly"
        touch /out/SANDBOX_PROBE      2>/dev/null && echo "out=writable"       || echo "out=READONLY"
        wget -q -T3 -O- http://example.com >/dev/null 2>&1 && echo "net=REACHED" || echo "net=blocked"
    ' 2>&1 | tr -d '\r')"
printf '%s\n' "$inside" | sed 's/^/  /'

check inside_workspace "$(printf '%s' "$inside" | sed -n 's/^workspace=//p')" readonly
check inside_out       "$(printf '%s' "$inside" | sed -n 's/^out=//p')"       writable
check inside_network   "$(printf '%s' "$inside" | sed -n 's/^net=//p')"       "$expect_net"
if [ "$ROUTE" = "network-on" ]; then
    printf 'note=on this route the workload reaching the network is the expected result, not a failure. It is the price of the route, and the reason offline is the default.\n'
fi

# --- from the host afterwards ------------------------------------------------
if [ -n "$EXPECT" ]; then
    check artifact "$(cat "$OUT/$EXPECT_FILE" 2>/dev/null | tr -d '\r\n')" "$EXPECT"
elif [ -s "$OUT/$EXPECT_FILE" ]; then
    printf 'artifact=present (%s)\n' "$OUT/$EXPECT_FILE"
else
    printf 'artifact=FAIL missing or empty: %s\n' "$OUT/$EXPECT_FILE"
    fail=1
fi

# The probe above tried to write the repo. If the read-only mount leaked, the
# evidence is sitting in the repo now.
if [ -e "$REPO/SANDBOX_PROBE" ]; then
    printf 'repo_unchanged=FAIL the read-only mount leaked: %s/SANDBOX_PROBE exists\n' "$REPO"
    fail=1
else
    printf 'repo_unchanged=ok\n'
fi
rm -f "$OUT/SANDBOX_PROBE"

if [ "$fail" -eq 0 ]; then printf 'result=sandbox_held\n'; else printf 'result=FAILED\n'; fi
exit "$fail"
