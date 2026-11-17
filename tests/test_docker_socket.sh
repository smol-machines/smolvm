#!/usr/bin/env bash
set -euo pipefail

SMOLVM_BIN="${SMOLVM_BIN:-smolvm}"
for tool in "$SMOLVM_BIN" docker curl python3; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

trial_dir=$(mktemp -d /tmp/smolvm-docker-XXXXXX)
vm_name="docker-socket-$(basename "$trial_dir")"
control_socket="$trial_dir/control.sock"
created=0

cleanup() {
    if [[ "$created" == 1 ]]; then
        "$SMOLVM_BIN" machine stop --name "$vm_name" >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
    fi
    rm -rf "$trial_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
ping_socket() { curl --silent --show-error --fail --max-time 3 --unix-socket "$1" http://localhost/_ping; }

wait_for_daemon() {
    local attempt
    for ((attempt = 0; attempt < 90; attempt++)); do
        if [[ "$(ping_socket "$control_socket" 2>/dev/null || true)" == OK ]]; then
            return
        fi
        sleep 1
    done
    "$SMOLVM_BIN" machine logs --name "$vm_name" --tail 60 >&2 || true
    fail "Docker never became reachable through the general socket bridge"
}

docker_trial() {
    python3 -c 'import subprocess, sys; sys.exit(subprocess.run(sys.argv[1:], timeout=120).returncode)' \
        env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH -u DOCKER_DEFAULT_PLATFORM \
        docker --host "unix://$docker_socket" "$@"
}

assert_docker_bridge() {
    local arch output expected
    [[ "$(ping_socket "$docker_socket")" == OK ]] || fail "dedicated Docker bridge /_ping"
    arch=$(docker_trial info --format '{{.Architecture}}')
    case "$(uname -m):$arch" in
        arm64:aarch64|arm64:arm64|aarch64:aarch64|aarch64:arm64|x86_64:x86_64|x86_64:amd64) ;;
        *) fail "Docker architecture $arch differs from host $(uname -m)" ;;
    esac

    docker_trial pull alpine:3.23 >/dev/null
    output=$(printf 'stdin delivered\n' | docker_trial run -i --rm alpine:3.23 \
        sh -c 'cat; printf "EOF reached\n"')
    expected=$(printf 'stdin delivered\nEOF reached\n')
    [[ "$output" == "$expected" ]] || fail "stdin EOF did not preserve daemon output: $output"

    output=$(docker_trial run --rm alpine:3.23 sh -c 'sleep 1; printf "late output\n"')
    [[ "$output" == 'late output' ]] || fail "output lost after attach without stdin"
    echo "PASS: dedicated Docker socket, native $arch, stdin EOF and delayed output"
}

"$SMOLVM_BIN" machine create --name "$vm_name" --image docker:29-dind \
    --cpus 2 --mem 2048 --net --storage 20 \
    -v /var/lib/docker -v /var/lib/containerd --docker-socket \
    --expose-socket "/var/run/docker.sock:$control_socket"
created=1
docker_socket="$("$SMOLVM_BIN" machine data-dir --name "$vm_name")/docker.sock"

"$SMOLVM_BIN" machine start --name "$vm_name"
wait_for_daemon
assert_docker_bridge

"$SMOLVM_BIN" machine stop --name "$vm_name"
"$SMOLVM_BIN" machine start --name "$vm_name"
wait_for_daemon
assert_docker_bridge
echo 'PASS: Docker bridge still works after stop/start'
