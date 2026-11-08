#!/usr/bin/env bash
# UDP between sockets inside one TSI machine stays inside the machine.
#
# Under TSI every guest socket can also reach the outside through the host,
# and UDP between two sockets of the same machine has to keep working beside
# that: an event-driven echo server answers clients on 127.0.0.1, ::1 and
# the machine's own address, connected and unconnected; a container-style
# network namespace on a veth pair talks to the machine and back; a local
# caching resolver (unbound on 127.0.0.1:53) answers dig, Python and Go once
# resolv.conf points at it; and Docker containers in the machine reach each
# other, a server on the machine and a published port. Outbound DNS to the
# machine's real resolver is checked alongside, so the outside path holds.
#
#   SMOLVM_BIN=./target/release/smolvm tests/test_tsi_udp.sh
#
# Environment:
#   SMOLVM_BIN       smolvm to test (default: smolvm on PATH)
#   DIND_IMAGE       default docker:29-dind
#   REGISTRY_MIRROR  passed to dockerd as --registry-mirror (e.g. https://mirror.gcr.io)
#   SKIP_DOCKER=1    skip the Docker part
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-smolvm}"
DIND_IMAGE="${DIND_IMAGE:-docker:29-dind}"
fixtures="$(cd "$(dirname "$0")" && pwd)/fixtures/tsi-udp"
command -v "$SMOLVM_BIN" >/dev/null || { echo "Missing tool: $SMOLVM_BIN" >&2; exit 1; }

failed=0
vm_name="tsi-udp-docker-$$"
created=0
cleanup() {
    if [[ "$created" == 1 ]]; then
        "$SMOLVM_BIN" machine stop --name "$vm_name" >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Run a fixture script in a fresh TSI machine and report its PASS/FAIL lines.
in_machine() {
    local script=$1 output rc=0
    echo "== $script"
    output=$("$SMOLVM_BIN" machine run --net --net-backend tsi --mem 2048 \
        -v "$fixtures:/t" --image alpine:3.23 -- sh "/t/$script" 2>&1) || rc=$?
    printf '%s\n' "$output" | grep -E '^(PASS|FAIL|ALL PASS|SOME FAILED|machine address)' || true
    if [[ "$rc" != 0 ]] || ! printf '%s\n' "$output" | grep -q '^ALL PASS$'; then
        failed=1
    fi
}

in_machine guest.sh
in_machine dns.sh

if [[ "${SKIP_DOCKER:-0}" != 1 ]]; then
    echo "== docker.sh"
    dind_cmd=(dockerd-entrypoint.sh)
    [[ -n "${REGISTRY_MIRROR:-}" ]] && dind_cmd+=("--registry-mirror=$REGISTRY_MIRROR")
    "$SMOLVM_BIN" machine create --name "$vm_name" --net --net-backend tsi --mem 3072 \
        --image "$DIND_IMAGE" -v /var/lib/docker -v /var/lib/containerd \
        -v "$fixtures:/t" -- "${dind_cmd[@]}" >/dev/null
    created=1
    "$SMOLVM_BIN" machine start --name "$vm_name" >/dev/null
    for ((attempt = 0; attempt < 120; attempt++)); do
        "$SMOLVM_BIN" machine exec --name "$vm_name" -- docker version >/dev/null 2>&1 && break
        sleep 1
    done
    rc=0
    output=$("$SMOLVM_BIN" machine exec --name "$vm_name" -- sh /t/docker.sh 2>&1) || rc=$?
    printf '%s\n' "$output" | grep -E '^(PASS|FAIL|ALL PASS|SOME FAILED|container )' || true
    if [[ "$rc" != 0 ]] || ! printf '%s\n' "$output" | grep -q '^ALL PASS$'; then
        failed=1
    fi
fi

if [[ "$failed" == 0 ]]; then
    echo "PASS: UDP between sockets of one TSI machine stays inside it"
else
    echo "FAIL: UDP inside a TSI machine"
    exit 1
fi
