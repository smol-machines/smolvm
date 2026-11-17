#!/usr/bin/env bash
# End-to-end check of published ports: hundreds of mappings per machine (the
# cap was 64), IPv4 and IPv6 loopback, a port published on a running TSI
# machine, and on macOS a port below 1024 published by a normal user.
#
#   SMOLVM_BIN=./target/release/smolvm tests/test_published_ports.sh
#
# Environment:
#   SMOLVM_BIN   smolvm to test (default: smolvm on PATH)
#   IMAGE        default busybox:1.37 (needs httpd)
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-smolvm}"
IMAGE="${IMAGE:-busybox:1.37}"
for tool in "$SMOLVM_BIN" curl; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

machines=()
cleanup() {
    for name in "${machines[@]}"; do
        "$SMOLVM_BIN" machine stop --name "$name" >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine delete --name "$name" -f >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# Wait up to ~15 s for an HTTP answer at $1; print its body.
answers() {
    local attempt
    for ((attempt = 0; attempt < 150; attempt++)); do
        if curl -fsS -m 2 "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Serve "ok" on guest ports 80, 8080 and 20150.
serve='mkdir -p /w && echo ok > /w/index.html && (httpd -f -p 80 -h /w & httpd -f -p 8080 -h /w & httpd -f -p 20150 -h /w & wait)'

low=()
if [[ "$(uname -s)" == Darwin ]]; then
    low=(-p 80:80)
fi

# 1. Published at create (virtio-net): 300 + a few mappings on one machine.
vm="ports-create-$$"
machines+=("$vm")
"$SMOLVM_BIN" machine create --name "$vm" --image "$IMAGE" --net \
    -p 18080:8080 -p 20000-20299 "${low[@]}" -- sh -c "$serve" >/dev/null
"$SMOLVM_BIN" machine start --name "$vm" >/dev/null
[[ "$(answers http://127.0.0.1:18080/)" == ok ]] || fail "-p 18080:8080 not reachable on 127.0.0.1"
[[ "$(answers http://127.0.0.1:20150/)" == ok ]] || fail "port 20150 of a 300-port range not reachable"
if [[ -n "$(ip -6 addr show lo 2>/dev/null)$(ifconfig lo0 2>/dev/null | grep inet6)" ]]; then
    [[ "$(answers 'http://[::1]:18080/')" == ok ]] || fail "-p 18080:8080 not reachable on [::1]"
fi
pass "301 mappings at create: 127.0.0.1 and [::1] reachable"
if [[ ${#low[@]} -gt 0 ]]; then
    [[ "$(answers http://localhost/)" == ok ]] || fail "-p 80:80 not reachable at http://localhost/ as $(id -un)"
    pass "-p 80:80 reachable at http://localhost/ as $(id -un)"
fi
"$SMOLVM_BIN" machine stop --name "$vm" >/dev/null

# 2. Published on a running TSI machine: 300 mappings added live, then removed.
vm="ports-live-$$"
machines+=("$vm")
"$SMOLVM_BIN" machine create --name "$vm" --image "$IMAGE" --net \
    -- sh -c "$serve" >/dev/null
"$SMOLVM_BIN" machine start --name "$vm" >/dev/null
"$SMOLVM_BIN" machine update --name "$vm" -p 20000-20299 >/dev/null
[[ "$(answers http://127.0.0.1:20150/)" == ok ]] || fail "live-published port 20150 not reachable"
"$SMOLVM_BIN" machine update --name "$vm" --remove-port 20000-20299 >/dev/null
if curl -fsS -m 2 http://127.0.0.1:20150/ >/dev/null 2>&1; then
    fail "port 20150 still answers after it was removed"
fi
pass "300 mappings published and removed on a running TSI machine"

echo "PASS: published ports"
