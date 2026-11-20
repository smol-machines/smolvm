#!/usr/bin/env bash
# Concurrent and churned outbound TCP connections from a guest, on each
# network backend.
#
# A guest must be able to hold as many connections as a GitHub-hosted runner
# (tens of thousands), and the host must give back what a connection used as
# soon as the guest closes it. For TSI and for virtio-net this suite:
#   - holds COUNT connections open at once from one guest to a sink on the
#     host, then echoes a byte over every one of them (end to end, not just
#     the guest's handshake), and
#   - opens and closes CHURN connections, each echoing a byte, and checks the
#     machine's host process holds no more file descriptors afterwards and
#     that the sink sees every connection closed, and
#   - makes short HTTP requests to a real server on the internet (REMOTE),
#     one after another and many at once, half of them closed by the server
#     first and half half-closed by the guest first, every one read to the
#     end. A local sink only ever closes after the guest does, which is how a
#     reset on a server's early close once went unnoticed.
#
#   SMOLVM_BIN=./target/release/smolvm tests/test_connections.sh
#
# Environment:
#   SMOLVM_BIN      smolvm to test (default: $SMOLVM, else smolvm on PATH)
#   BACKENDS        default "tsi virtio-net"
#   COUNT           concurrent connections (default 10000; on macOS capped
#                   below kern.maxfilesperproc, the per-process file limit
#                   only root can raise)
#   CHURN           connections opened and closed (default 100000)
#   HOST_ADDR       host address the guest dials (default: the host's
#                   address on its default route)
#   TEST_IMAGE      guest image with python3 (default python:3.12-alpine)
#   REMOTE          real HTTP server host:port (default deb.debian.org:80,
#                   which answers a half-closed request; example.com does
#                   not, even from the host); REMOTE=skip leaves it out
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-${SMOLVM:-smolvm}}"
BACKENDS="${BACKENDS:-tsi virtio-net}"
COUNT="${COUNT:-10000}"
CHURN="${CHURN:-100000}"
TEST_IMAGE="${TEST_IMAGE:-python:3.12-alpine}"
REMOTE="${REMOTE:-deb.debian.org:80}"
fixtures="$(cd "$(dirname "$0")" && pwd)/fixtures/connections"
command -v "$SMOLVM_BIN" >/dev/null || { echo "Missing tool: $SMOLVM_BIN" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Missing tool: python3" >&2; exit 1; }

os="$(uname -s)"
inflight=2048
rate=0
if [[ "$os" == Darwin ]]; then
    # A macOS listen queue holds 128 pending connections.
    inflight=128
    # Closed connections keep their local port in TIME-WAIT for 30 s out of
    # 16384 ephemeral ports, so a sustained churn tops out near 540 a second.
    rate=450
    # An idle machine process holds about 180 descriptors of its own, so on a
    # Mac with the usual 10,240-file cap the full 10,000 fit.
    per_process=$(sysctl -n kern.maxfilesperproc)
    if (( COUNT > per_process - 200 )); then
        echo "NOTE: macOS allows one process $per_process open files (kern.maxfilesperproc);"
        echo "      holding $((per_process - 200)) connections instead of $COUNT"
        COUNT=$((per_process - 200))
    fi
fi

if [[ -z "${HOST_ADDR:-}" ]]; then
    if [[ "$os" == Darwin ]]; then
        iface=$(route -n get default | awk '/interface:/ {print $2}')
        HOST_ADDR=$(ipconfig getifaddr "$iface")
    else
        HOST_ADDR=$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
    fi
fi
[[ -n "$HOST_ADDR" ]] || { echo "Could not find the host address; set HOST_ADDR" >&2; exit 1; }

work=$(mktemp -d)
sink_pid=""
machines=()
cleanup() {
    for name in "${machines[@]}"; do
        "$SMOLVM_BIN" machine stop --name "$name" >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine delete --name "$name" -f >/dev/null 2>&1 || true
    done
    [[ -n "$sink_pid" ]] && kill "$sink_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Sixteen sink ports, so a churn is not capped by one destination's TIME-WAIT tuples.
for _ in 1 2 3 4 5; do
    first_port=$((20000 + RANDOM % 20000))
    last_port=$((first_port + 15))
    SINK_REPORT="$work/sink.report" python3 "$fixtures/sink.py" $(seq "$first_port" "$last_port") \
        >"$work/sink.log" 2>&1 &
    sink_pid=$!
    for _ in $(seq 50); do
        grep -q ready "$work/sink.log" 2>/dev/null && break
        kill -0 "$sink_pid" 2>/dev/null || break
        sleep 0.1
    done
    grep -q ready "$work/sink.log" 2>/dev/null && break
    sink_pid=""
done
[[ -n "$sink_pid" ]] || { echo "Could not start the host sink" >&2; cat "$work/sink.log" >&2; exit 1; }
ports="$first_port-$last_port"

sink_open() {
    rm -f "$work/sink.report"
    kill -USR1 "$sink_pid"
    for _ in $(seq 50); do
        [[ -s "$work/sink.report" ]] && break
        sleep 0.1
    done
    sed -n 's/^open=\([0-9]*\).*/\1/p' "$work/sink.report"
}

# Open file descriptors of a process, when this host lets us count them.
fd_count() {
    local pid=$1
    if [[ "$os" == Darwin ]]; then
        lsof -n -P -a -p "$pid" -d 0-2147483647 2>/dev/null | tail -n +2 | wc -l | tr -d ' '
    elif ls "/proc/$pid/fd" >/dev/null 2>&1; then
        ls "/proc/$pid/fd" | wc -l
    elif sudo -n true 2>/dev/null; then
        # The machine's process is not dumpable, so its fd table is root's to read.
        sudo -n ls "/proc/$pid/fd" | wc -l
    fi
}

json_field() {
    python3 -c 'import json, sys; print(json.loads(sys.argv[1])["result"].get(sys.argv[2], 0))' "$1" "$2"
}

failed=0
fail() {
    echo "FAIL: $*"
    failed=1
}

# Wait out the TIME-WAIT of the previous run's connections (host side).
settle_ports() {
    if [[ "$os" == Darwin ]]; then sleep 32; fi
}

for backend in $BACKENDS; do
    echo "== $backend: hold $COUNT connections at once"
    output=$("$SMOLVM_BIN" machine run --net --net-backend "$backend" --cpus 4 --mem 4096 \
        --image "$TEST_IMAGE" -v "$fixtures:/probe" -- \
        env INFLIGHT="$inflight" python3 /probe/client.py hold "$HOST_ADDR" "$ports" "$COUNT" 3 2>&1) || true
    line=$(printf '%s\n' "$output" | grep '^{' | tail -1)
    echo "   $line"
    if [[ -z "$line" ]]; then
        fail "$backend hold: no result"
        printf '%s\n' "$output" | tail -5
    else
        connected=$(json_field "$line" connected)
        echoed=$(json_field "$line" echoed)
        [[ "$connected" == "$COUNT" ]] || fail "$backend hold: $connected of $COUNT connected"
        [[ "$echoed" == "$COUNT" ]] || fail "$backend hold: $echoed of $COUNT carried data end to end"
    fi
    sleep 2
    open=$(sink_open)
    [[ "$open" == 0 ]] || fail "$backend hold: the host still has $open connections open after the guest closed them"
    settle_ports

    if [[ "$REMOTE" != skip ]]; then
        for shape in "40 1" "120 20"; do
            read -r total concurrency <<<"$shape"
            echo "== $backend: $total HTTP requests to $REMOTE, $concurrency at a time"
            line=$("$SMOLVM_BIN" machine run --net --net-backend "$backend" --image "$TEST_IMAGE" \
                -v "$fixtures:/probe" -- \
                python3 /probe/client.py http "${REMOTE%:*}" "${REMOTE##*:}" "$total" "$concurrency" 2>&1 |
                grep '^{' | tail -1) || true
            echo "   $line"
            if [[ -z "$line" ]]; then
                fail "$backend http: no result"
                continue
            fi
            ok=$(( $(json_field "$line" ok_server_closed) + $(json_field "$line" ok_half_closed) ))
            [[ "$ok" == "$total" ]] ||
                fail "$backend http: $ok of $total requests to $REMOTE completed"
        done
    fi

    echo "== $backend: open and close $CHURN connections"
    name="conn-churn-$backend-$$"
    machines+=("$name")
    "$SMOLVM_BIN" machine create --name "$name" --net --net-backend "$backend" --cpus 4 --mem 4096 \
        --image "$TEST_IMAGE" -v "$fixtures:/probe" >/dev/null
    "$SMOLVM_BIN" machine start --name "$name" >/dev/null
    pid=$("$SMOLVM_BIN" machine status --name "$name" --json |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["pid"])')
    # Warm up so lazily created host state is in place before counting.
    "$SMOLVM_BIN" machine exec --name "$name" -- \
        env INFLIGHT="$inflight" RATE="$rate" python3 /probe/client.py churn "$HOST_ADDR" "$ports" 2000 200 >/dev/null
    sleep 3
    before=$(fd_count "$pid")
    line=$("$SMOLVM_BIN" machine exec --name "$name" -- \
        env INFLIGHT="$inflight" RATE="$rate" python3 /probe/client.py churn "$HOST_ADDR" "$ports" "$CHURN" 200 |
        grep '^{' | tail -1) || true
    echo "   $line"
    sleep 6
    after=$(fd_count "$pid")
    if [[ -z "$line" ]]; then
        fail "$backend churn: no result"
    else
        echoed=$(json_field "$line" echoed)
        [[ "$echoed" == "$CHURN" ]] || fail "$backend churn: $echoed of $CHURN connections carried data"
    fi
    if [[ -n "$before" && -n "$after" ]]; then
        echo "   host process file descriptors: $before before, $after after"
        (( after <= before + 16 )) || fail "$backend churn: host descriptors grew from $before to $after"
    else
        echo "   (cannot read the machine process's descriptors here; checked the sink instead)"
    fi
    open=$(sink_open)
    [[ "$open" == 0 ]] || fail "$backend churn: the host still has $open connections open"
    "$SMOLVM_BIN" machine stop --name "$name" >/dev/null 2>&1 || true
    "$SMOLVM_BIN" machine delete --name "$name" -f >/dev/null 2>&1 || true
    settle_ports
done

if [[ "$failed" == 0 ]]; then
    echo "PASS: $COUNT concurrent and $CHURN churned connections, and real-server HTTP, on: $BACKENDS"
else
    echo "FAIL: guest connection scale"
    exit 1
fi
