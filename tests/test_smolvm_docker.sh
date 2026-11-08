#!/usr/bin/env bash
# End-to-end test of `smolvm docker`: one command gives a Docker engine that
# `docker` reaches with no DOCKER_HOST, shares the home directory at the same
# path, resolves host.docker.internal to the host, exposes its socket to
# containers, and keeps Docker data across stop, start and reset.
#
# usage: tests/test_smolvm_docker.sh
#
#   SMOLVM_BIN               smolvm to test (default: smolvm on PATH)
#   SMOLVM_DOCKER_E2E_MIRROR registry mirror for the engine, for hosts that hit
#                            Docker Hub's anonymous limit (e.g. https://mirror.gcr.io)
#
# It refuses to run when a Docker machine already exists, and deletes the one
# it creates. The docker CLI configuration goes to a temporary DOCKER_CONFIG,
# and ~/.testcontainers.properties is restored on exit.
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-smolvm}"
for tool in "$SMOLVM_BIN" docker python3; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
if "$SMOLVM_BIN" machine status --name docker >/dev/null 2>&1; then
    echo "A machine named 'docker' exists; delete it (smolvm docker delete) to run this test" >&2
    exit 2
fi

unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
work=$(mktemp -d "$HOME/.smolvm-docker-e2e.XXXXXX")
export DOCKER_CONFIG="$work/docker-config"
props="$HOME/.testcontainers.properties"
props_backup=""
if [[ -e "$props" ]]; then
    props_backup="$work/testcontainers.properties"
    cp -p "$props" "$props_backup"
fi
server_pid=""

cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
    "$SMOLVM_BIN" docker delete --force >/dev/null 2>&1 || true
    if [[ -n "$props_backup" ]]; then
        cp -p "$props_backup" "$props"
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { echo "FAIL: $*" >&2; "$SMOLVM_BIN" docker logs --tail 40 >&2 || true; exit 1; }
pass() { echo "PASS: $*"; }
mirror_args=()
[[ -n "${SMOLVM_DOCKER_E2E_MIRROR:-}" ]] && mirror_args=(--registry-mirror "$SMOLVM_DOCKER_E2E_MIRROR")

# 1. One command, then plain `docker`.
"$SMOLVM_BIN" docker ${mirror_args[@]+"${mirror_args[@]}"}
[[ "$(docker context show)" == smol ]] || fail "the smol context is not selected"
[[ "$(docker run --rm alpine echo ok)" == ok ]] || fail "docker run with no DOCKER_HOST"
socket="$HOME/.smolvm/run/docker.sock"
[[ -S "$socket" ]] || fail "no socket at $socket"
if [[ -z "$props_backup" ]]; then
    grep -qx "docker.host=unix://$socket" "$props" || fail "Testcontainers is not pointed at $socket"
fi
pass "smolvm docker, then docker run with no DOCKER_HOST"

# 2. The home directory at the same path: read a host file, write one back.
echo from-host > "$work/in.txt"
out=$(docker run --rm -v "$work:$work" -w "$work" alpine sh -c 'cat in.txt; echo from-container > out.txt')
[[ "$out" == from-host ]] || fail "container read '$out' from a home bind mount"
[[ "$(cat "$work/out.txt")" == from-container ]] || fail "container write not visible on the host"
pass "home directory shared at the same path"

# 3. The socket, mounted from its default path and from the host's stable path.
for source in /var/run/docker.sock "$socket"; do
    version=$(docker run --rm -v "$source:/var/run/docker.sock" docker:29-cli \
        docker version --format '{{.Server.Version}}')
    [[ -n "$version" ]] || fail "no engine behind a container's mount of $source"
done
pass "containers that mount /var/run/docker.sock or $socket reach the engine"

# 4. host.docker.internal reaches a server bound to the host's loopback.
echo host-reached > "$work/index.html"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
    python3 -c "import socket; socket.create_connection(('127.0.0.1', $port), 1)" 2>/dev/null && break
    sleep 0.1
done
for name in host.docker.internal gateway.docker.internal; do
    out=$(docker run --rm alpine wget -qO- -T 5 "http://$name:$port/")
    [[ "$out" == host-reached ]] || fail "$name:$port gave '$out'"
done
out=$(docker run --rm --add-host hostgw:host-gateway alpine wget -qO- -T 5 "http://hostgw:$port/")
[[ "$out" == host-reached ]] || fail "host-gateway:$port gave '$out'"
docker network create smolvm-e2e >/dev/null
out=$(docker run --rm --network smolvm-e2e alpine wget -qO- -T 5 "http://host.docker.internal:$port/")
docker network rm smolvm-e2e >/dev/null
[[ "$out" == host-reached ]] || fail "host.docker.internal on a user network gave '$out'"
pass "host.docker.internal, gateway.docker.internal and host-gateway reach the host"

# 5. Stop and start keep Docker data.
docker volume create smolvm-e2e-data >/dev/null
docker run --rm -v smolvm-e2e-data:/d alpine sh -c 'echo kept > /d/f'
"$SMOLVM_BIN" docker stop
"$SMOLVM_BIN" docker status | grep -q '^Engine:  not answering' || fail "status after stop"
"$SMOLVM_BIN" docker start
[[ "$(docker run --rm -v smolvm-e2e-data:/d alpine cat /d/f)" == kept ]] || fail "volume lost across stop/start"
pass "stop and start keep volumes"

# 6. Reset applies new settings and keeps volumes; --volumes starts empty.
"$SMOLVM_BIN" docker reset --mem 2048
"$SMOLVM_BIN" docker status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(0 if s["mem_mib"]==2048 and s["engine_version"] else 1)' \
    || fail "reset did not apply --mem 2048"
[[ "$(docker run --rm -v smolvm-e2e-data:/d alpine cat /d/f)" == kept ]] || fail "volume lost across reset"
"$SMOLVM_BIN" docker reset --volumes
[[ -z "$(docker volume ls -q)" ]] || fail "reset --volumes kept volumes"
pass "reset keeps volumes; reset --volumes removes them"

# 7. Delete removes the machine and the host wiring.
"$SMOLVM_BIN" docker delete --force
[[ ! -e "$socket" && ! -L "$socket" ]] || fail "socket link left behind"
[[ "$(docker context show)" == default ]] || fail "the smol context is still selected"
if [[ -z "$props_backup" ]]; then
    [[ ! -e "$props" ]] || fail "~/.testcontainers.properties left behind"
fi
pass "delete removes the machine, the socket link and the context"
