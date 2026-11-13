#!/usr/bin/env bash
# End-to-end check, on an Apple silicon Mac, that x86_64 images run inside a
# Docker machine through Rosetta: in containers Docker starts (their own mount
# namespaces), keeping the PID they were started with (a shell as PID 1, an
# amd64 postgres whose entrypoint waits on `pg_ctl -w`), stopping promptly on
# `docker stop`, and leaving no extra processes behind.
#
#   SMOLVM_BIN=./target/release/smolvm tests/test_rosetta_nested.sh
#
# Environment:
#   SMOLVM_BIN       smolvm to test (default: smolvm on PATH)
#   DIND_IMAGE       default docker:29-dind
#   REGISTRY_MIRROR  passed to dockerd as --registry-mirror (e.g. https://mirror.gcr.io)
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-smolvm}"
DIND_IMAGE="${DIND_IMAGE:-docker:29-dind}"
if [[ "$(uname -s)/$(uname -m)" != Darwin/arm64 ]]; then
    echo "SKIP: Rosetta needs an Apple silicon Mac"
    exit 0
fi
for tool in "$SMOLVM_BIN" docker; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

vm_name="rosetta-nested-$$"
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

fail() {
    echo "FAIL: $*" >&2
    dk logs pg >&2 || true
    "$SMOLVM_BIN" machine logs --name "$vm_name" --tail 40 >&2 || true
    exit 1
}
pass() { echo "PASS: $*"; }
dk() {
    env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        docker --host "unix://$docker_socket" "$@"
}
amd64() { dk run --rm --platform linux/amd64 "$@"; }

dind_cmd=(dockerd-entrypoint.sh)
[[ -n "${REGISTRY_MIRROR:-}" ]] && dind_cmd+=("--registry-mirror=$REGISTRY_MIRROR")
"$SMOLVM_BIN" machine create --name "$vm_name" --image "$DIND_IMAGE" \
    --cpus 4 --mem 4096 --net --rosetta \
    -v /var/lib/docker -v /var/lib/containerd --docker-socket -- "${dind_cmd[@]}" >/dev/null
created=1
docker_socket="$("$SMOLVM_BIN" machine data-dir --name "$vm_name")/docker.sock"
"$SMOLVM_BIN" machine start --name "$vm_name" >/dev/null
for ((attempt = 0; attempt < 120; attempt++)); do
    dk version >/dev/null 2>&1 && break
    sleep 0.5
done
dk version >/dev/null 2>&1 || fail "Docker never answered on $docker_socket"

# 1. A nested container translates, and its shell keeps PID 1.
out=$(amd64 alpine:3.23 sh -c 'echo "$(uname -m) $$"')
[[ "$out" == "x86_64 1" ]] || fail "alpine/amd64 printed '$out', want 'x86_64 1'"
pass "docker run --platform linux/amd64 alpine: x86_64, PID 1"

# 2. Common runtimes.
out=$(amd64 node:22-alpine node -e 'console.log(process.arch)')
[[ "$out" == x64 ]] || fail "node/amd64 printed '$out'"
out=$(amd64 python:3.12-slim python -c 'import platform; print(platform.machine())')
[[ "$out" == x86_64 ]] || fail "python/amd64 printed '$out'"
pass "node and python amd64 images run"

# 3. postgres: its entrypoint waits for the server by PID (pg_ctl -w).
dk run -d --name pg --platform linux/amd64 -e POSTGRES_PASSWORD=pw postgres:16-alpine >/dev/null
for ((attempt = 0; attempt < 90; attempt++)); do
    dk logs pg 2>&1 | grep -c 'init process complete' >/dev/null && break
    dk logs pg 2>&1 | grep -c 'did not start in time' >/dev/null && break
    sleep 1
done
dk logs pg 2>&1 | grep -c 'init process complete' >/dev/null || fail "amd64 postgres never finished init"
for ((attempt = 0; attempt < 30; attempt++)); do
    dk exec pg pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
done
version=$(dk exec pg psql -U postgres -tAc 'select version()')
[[ "$version" == *x86_64* ]] || fail "postgres answered '$version'"
start=$(date +%s)
dk stop pg >/dev/null
(( $(date +%s) - start < 8 )) || fail "docker stop took the full grace period: the signal missed postgres"
dk rm -f pg >/dev/null
pass "amd64 postgres initialises, answers queries and stops on SIGTERM"

# 4. No extra processes: x86_64 execs under a PID 1 that never reaps leave nothing.
dk run -d --name keep --platform linux/amd64 alpine:3.23 sleep 600 >/dev/null
for _ in $(seq 1 10); do dk exec keep true; done
dk exec keep sh -c 'for i in $(seq 1 20); do /bin/true; done'
zombies=$(dk exec keep sh -c 'ps -o stat | grep -c "^Z" || true')
dk rm -f keep >/dev/null
[[ "$zombies" == 0 ]] || fail "$zombies zombie processes after 30 x86_64 execs"
pass "30 x86_64 execs leave no processes behind"

echo "PASS: x86_64 images run in nested containers through Rosetta"
