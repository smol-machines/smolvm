#!/usr/bin/env bash
#
# The Docker Engine API that `smolvm engine` serves, driven by the docker CLI
# and Docker Compose exactly as users run them: containers, images, ports,
# volumes, exec, logs, and the default network.
#
# Needs the docker CLI. With DOCKER_HOST set, the
# suite uses that engine; otherwise it starts `smolvm engine serve` on a
# socket of its own and stops it at the end.
#
# Usage: ./tests/run_tests.sh engine     or     ./tests/test_engine.sh

source "$(dirname "$0")/common.sh"
init_smolvm

if ! command -v docker >/dev/null 2>&1; then
    log_skip "docker CLI not installed"
    exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/smolvm-engine-XXXXXX")
ENGINE_PID=""
PREFIX="smolvm-engine-test-$$"

if [[ -z "${DOCKER_HOST:-}" ]]; then
    SOCKET="$WORK/docker.sock"
    "$SMOLVM" engine serve --socket "$SOCKET" >"$WORK/engine.log" 2>&1 &
    ENGINE_PID=$!
    for _ in $(seq 1 100); do
        [[ -S "$SOCKET" ]] && break
        sleep 0.1
    done
    export DOCKER_HOST="unix://$SOCKET"
fi
SOCKET_PATH="${DOCKER_HOST#unix://}"

cleanup() {
    local id
    for id in $(docker ps -aq --filter "label=$PREFIX" 2>/dev/null); do
        docker rm -f "$id" >/dev/null 2>&1 || true
    done
    for id in $(docker network ls -q --filter "label=$PREFIX" 2>/dev/null); do
        docker network rm "$id" >/dev/null 2>&1 || true
    done
    for id in $(docker volume ls -q --filter "label=$PREFIX" 2>/dev/null); do
        docker volume rm "$id" >/dev/null 2>&1 || true
    done
    if [[ -n "$ENGINE_PID" ]]; then
        kill "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Every container, network and volume the suite makes carries this label so
# the cleanup removes exactly those.
run() { docker run --label "$PREFIX" "$@"; }

# `grep -q` that reads its whole input: an early exit would kill the writer
# with SIGPIPE, which `pipefail` turns into a failure.
has() { grep -c "$@" >/dev/null; }

echo ""
echo "=========================================="
echo "  smolvm engine (Docker API) tests"
echo "=========================================="
echo ""

docker pull -q alpine >/dev/null
docker pull -q nginx:alpine >/dev/null

# --- system ------------------------------------------------------------------

test_ping_version_info() {
    [[ "$(curl -s --unix-socket "$SOCKET_PATH" http://d/_ping)" == OK ]] || return 1
    docker version --format '{{.Server.APIVersion}}' | has '^1\.' || return 1
    docker info --format '{{.OSType}}' | has -x linux
}

test_versioned_paths() {
    curl -sf --unix-socket "$SOCKET_PATH" http://d/v1.44/version >/dev/null &&
        curl -sf --unix-socket "$SOCKET_PATH" http://d/v1.24/info >/dev/null
}

# --- containers ----------------------------------------------------------------

test_run_echo_and_exit_codes() {
    [[ "$(run --rm alpine echo hello)" == hello ]] || return 1
    local rc=0
    run --rm alpine sh -c 'exit 3' || rc=$?
    [[ $rc -eq 3 ]]
}

test_missing_command_is_127() {
    local rc=0
    run --rm alpine no-such-command 2>/dev/null || rc=$?
    [[ $rc -eq 127 ]]
}

test_stdin_and_tty() {
    [[ "$(echo piped | run --rm -i alpine cat)" == piped ]] || return 1
    command -v script >/dev/null || return 0
    local out
    if [[ "$(uname -s)" == Darwin ]]; then
        out=$(script -q /dev/null docker run --label "$PREFIX" --rm -t alpine tty </dev/null | tr -d '\r')
    else
        out=$(script -qec "docker run --label $PREFIX --rm -t alpine tty" /dev/null </dev/null | tr -d '\r')
    fi
    echo "$out" | has '/dev/pts/'
}

test_detached_logs_exec_top_stats() {
    local name="$PREFIX-web"
    run -d --name "$name" nginx:alpine >/dev/null || return 1
    docker exec "$name" sh -c 'echo exec-ok' | has exec-ok || return 1
    docker top "$name" | has nginx || return 1
    docker stats --no-stream "$name" | has "$name" || return 1
    sleep 1
    docker logs "$name" 2>&1 | has 'start worker process' || return 1
    docker logs -t --tail 1 "$name" 2>&1 | has -E '^[0-9]{4}-' || return 1
    docker rm -f "$name" >/dev/null
}

test_lifecycle_stop_start_restart_pause() {
    local name="$PREFIX-life"
    run -d --name "$name" alpine sleep 300 >/dev/null || return 1
    docker stop -t 1 "$name" >/dev/null || return 1
    [[ "$(docker inspect -f '{{.State.Status}}' "$name")" == exited ]] || return 1
    docker start "$name" >/dev/null || return 1
    docker restart -t 1 "$name" >/dev/null || return 1
    docker pause "$name" >/dev/null || return 1
    [[ "$(docker inspect -f '{{.State.Status}}' "$name")" == paused ]] || return 1
    docker unpause "$name" >/dev/null || return 1
    docker rename "$name" "$name-2" || return 1
    docker kill "$name-2" >/dev/null || return 1
    docker rm "$name-2" >/dev/null
}

test_wait_returns_the_exit_code() {
    local id
    id=$(run -d alpine sh -c 'sleep 1; exit 7') || return 1
    [[ "$(docker wait "$id")" == 7 ]] || return 1
    docker rm "$id" >/dev/null
}

test_ports_published_and_random() {
    local name="$PREFIX-ports"
    run -d --name "$name" -p 18089:80 -P nginx:alpine >/dev/null || return 1
    local ok=1
    for _ in $(seq 1 50); do
        curl -sf -m 2 http://127.0.0.1:18089/ | has nginx && { ok=0; break; }
        sleep 0.2
    done
    [[ $ok -eq 0 ]] || return 1
    docker port "$name" 80 | has 18089 || return 1
    docker rm -f "$name" >/dev/null
}

test_env_workdir_user() {
    run --rm -e FOO=bar -w /tmp -u nobody alpine sh -c 'echo "$FOO $(pwd) $(id -u)"' | has -x 'bar /tmp 65534'
}

test_restart_policy_on_failure() {
    local name="$PREFIX-restart"
    run -d --name "$name" --restart on-failure:2 alpine sh -c 'exit 1' >/dev/null || return 1
    for _ in $(seq 1 60); do
        [[ "$(docker inspect -f '{{.RestartCount}}/{{.State.Status}}' "$name")" == 2/exited ]] && break
        sleep 0.5
    done
    [[ "$(docker inspect -f '{{.RestartCount}}/{{.State.Status}}' "$name")" == 2/exited ]] || return 1
    docker rm -f "$name" >/dev/null
}

test_healthcheck_goes_healthy() {
    local name="$PREFIX-health"
    run -d --name "$name" --health-cmd 'test -f /tmp/ok' --health-interval 1s --health-retries 30 \
        alpine sh -c 'sleep 2; touch /tmp/ok; sleep 300' >/dev/null || return 1
    for _ in $(seq 1 30); do
        [[ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" == healthy ]] && break
        sleep 0.5
    done
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" == healthy ]] || return 1
    docker rm -f "$name" >/dev/null
}

test_copy_in_and_out() {
    local name="$PREFIX-cp"
    run -d --name "$name" alpine sleep 300 >/dev/null || return 1
    echo copied >"$WORK/in.txt"
    docker cp "$WORK/in.txt" "$name:/tmp/" || return 1
    docker exec "$name" cat /tmp/in.txt | has -x copied || return 1
    docker cp "$name:/etc/alpine-release" "$WORK/out.txt" || return 1
    [[ -s "$WORK/out.txt" ]] || return 1
    docker rm -f "$name" >/dev/null
}

test_copy_before_start() {
    local id
    id=$(docker create --label "$PREFIX" alpine cat /etc/staged.txt) || return 1
    echo staged >"$WORK/staged.txt"
    docker cp "$WORK/staged.txt" "$id:/etc/" || return 1
    [[ "$(docker start -a "$id")" == staged ]] || return 1
    docker rm "$id" >/dev/null
}

test_events_stream_lifecycle() {
    local out="$WORK/events.txt"
    docker events --filter "label=$PREFIX" --format '{{.Action}}' >"$out" &
    local ev=$!
    sleep 0.5
    run --rm alpine true
    sleep 1
    kill $ev 2>/dev/null || true
    grep -q '^start$' "$out" && grep -q '^die$' "$out" && grep -q '^destroy$' "$out"
}

test_filters_and_labels() {
    local id
    id=$(run -d --label "role=probe" alpine sleep 300) || return 1
    docker ps -q --filter "label=role=probe" | has "${id:0:12}" || return 1
    docker ps -q --filter "label=role=other" | has . && return 1
    docker ps -aq --filter "status=running" --filter "ancestor=alpine" | has "${id:0:12}" || return 1
    docker rm -f "$id" >/dev/null
}

# --- images ------------------------------------------------------------------

test_image_list_inspect_tag_remove() {
    docker images --format '{{.Repository}}:{{.Tag}}' | has -x alpine:latest || return 1
    docker image inspect -f '{{.Os}}' alpine | has -x linux || return 1
    docker tag alpine "$PREFIX-tag:v1" || return 1
    docker images --format '{{.Repository}}' | has -x "$PREFIX-tag" || return 1
    docker rmi "$PREFIX-tag:v1" | has Untagged || return 1
    docker image inspect alpine >/dev/null
}

test_build_is_refused_clearly() {
    printf 'FROM alpine\n' >"$WORK/Dockerfile"
    local out
    out=$(DOCKER_BUILDKIT=0 docker build -q "$WORK" 2>&1) && return 1
    echo "$out" | has 'does not build images yet'
}

# --- volumes and mounts --------------------------------------------------------

test_named_volume_persists() {
    local vol="$PREFIX-vol"
    docker volume create --label "$PREFIX" "$vol" >/dev/null || return 1
    run --rm -v "$vol:/data" alpine sh -c 'echo kept > /data/f' || return 1
    [[ "$(run --rm -v "$vol:/data" alpine cat /data/f)" == kept ]] || return 1
    docker volume inspect -f '{{.Driver}}' "$vol" | has -x local
}

test_new_volume_takes_the_image_content() {
    local vol="$PREFIX-copyup"
    docker volume create --label "$PREFIX" "$vol" >/dev/null || return 1
    run --rm -v "$vol:/etc/apk" alpine ls /etc/apk | has repositories
}

test_bind_mounts_dir_file_readonly() {
    mkdir -p "$WORK/dir" && echo from-host >"$WORK/dir/f"
    echo single >"$WORK/single.conf"
    [[ "$(run --rm -v "$WORK/dir:/b" alpine cat /b/f)" == from-host ]] || return 1
    run --rm -v "$WORK/dir:/b" alpine sh -c 'echo from-guest > /b/g' || return 1
    [[ "$(cat "$WORK/dir/g")" == from-guest ]] || return 1
    [[ "$(run --rm -v "$WORK/single.conf:/etc/single.conf:ro" alpine cat /etc/single.conf)" == single ]] || return 1
    run --rm -v "$WORK/dir:/b:ro" alpine sh -c 'echo x > /b/h' 2>/dev/null && return 1
    return 0
}

test_tmpfs() {
    run --rm --tmpfs /scratch:size=8m alpine sh -c 'mount | grep -q "/scratch type tmpfs"'
}

# --- networks --------------------------------------------------------------------

test_default_bridge_by_address_without_names() {
    run -d --name "$PREFIX-ba" alpine sleep 300 >/dev/null || return 1
    local a_ip
    a_ip=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$PREFIX-ba")
    [[ "$a_ip" == 172.17.* ]] || return 1
    run --rm alpine ping -c1 -W2 "$a_ip" >/dev/null || return 1
    # The default network resolves no names, as Docker's; a link does.
    run --rm alpine getent hosts "$PREFIX-ba" >/dev/null 2>&1 && return 1
    run --rm --link "$PREFIX-ba:peer" alpine ping -c1 -W2 peer >/dev/null
}

test_host_docker_internal() {
    python3 -m http.server 18766 --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
    local srv=$!
    sleep 1
    local rc=0
    run --rm alpine wget -q -O /dev/null -T 3 http://host.docker.internal:18766/ || rc=$?
    kill $srv 2>/dev/null || true
    [[ $rc -eq 0 ]]
}

run_test "ping, version, info" test_ping_version_info || true
run_test "versioned API paths" test_versioned_paths || true
run_test "run echo and exit codes" test_run_echo_and_exit_codes || true
run_test "missing command exits 127" test_missing_command_is_127 || true
run_test "stdin and tty" test_stdin_and_tty || true
run_test "detached logs, exec, top, stats" test_detached_logs_exec_top_stats || true
run_test "stop, start, restart, pause, rename, kill" test_lifecycle_stop_start_restart_pause || true
run_test "wait returns the exit code" test_wait_returns_the_exit_code || true
run_test "published and random ports" test_ports_published_and_random || true
run_test "env, workdir, user" test_env_workdir_user || true
run_test "restart policy on-failure" test_restart_policy_on_failure || true
run_test "health check goes healthy" test_healthcheck_goes_healthy || true
run_test "copy in and out" test_copy_in_and_out || true
run_test "copy before the first start" test_copy_before_start || true
run_test "events stream the lifecycle" test_events_stream_lifecycle || true
run_test "filters and labels" test_filters_and_labels || true
run_test "images list, inspect, tag, remove" test_image_list_inspect_tag_remove || true
run_test "build is refused clearly" test_build_is_refused_clearly || true
run_test "named volume persists" test_named_volume_persists || true
run_test "new volume takes the image content" test_new_volume_takes_the_image_content || true
run_test "bind mounts: dir, file, read-only" test_bind_mounts_dir_file_readonly || true
run_test "tmpfs" test_tmpfs || true
run_test "default bridge: by address, no names" test_default_bridge_by_address_without_names || true
run_test "host.docker.internal reaches the host" test_host_docker_internal || true

print_summary "engine"
