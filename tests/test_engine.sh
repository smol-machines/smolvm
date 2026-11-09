#!/usr/bin/env bash
#
# The Docker Engine API that `smolvm engine` serves, driven by the docker CLI
# and Docker Compose exactly as users run them: containers, images, ports,
# volumes, exec, logs, networks between containers, Compose with health-check
# dependencies, and the Docker socket inside a container.
#
# Needs the docker CLI with the compose plugin. With DOCKER_HOST set, the
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

# The host's own address on its LAN, to tell a loopback-only port from one
# on every interface.
host_lan_ip() {
    python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])'
}

test_ports_listen_where_asked() {
    local name="$PREFIX-listen" lan ok=1
    lan=$(host_lan_ip)
    run -d --name "$name" -p 127.0.0.1:18090:80 -p 18091:80 nginx:alpine >/dev/null || return 1
    for _ in $(seq 1 50); do
        curl -sf -m 2 http://127.0.0.1:18090/ | has nginx && { ok=0; break; }
        sleep 0.2
    done
    [[ $ok -eq 0 ]] || return 1
    # Asked for loopback: not reachable on the LAN address.
    curl -sf -m 2 "http://$lan:18090/" >/dev/null 2>&1 && return 1
    # No address: every interface, IPv4 and IPv6, as with Docker.
    curl -sf -m 2 "http://$lan:18091/" | has nginx || return 1
    curl -gsf -m 2 "http://[::1]:18091/" | has nginx || return 1
    docker port "$name" 80 | has '127.0.0.1:18090' || return 1
    docker port "$name" 80 | has '0.0.0.0:18091' || return 1
    docker port "$name" 80 | has '\[::\]:18091' || return 1
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

# commit (with a change and a deleted file), save and load back, export and
# import, push to a registry running in a container, and pull it back: the
# image moves the ways Docker moves it, and runs the same each time.
test_image_commit_save_load_export_import_push() {
    local img="$PREFIX-img:1" imported="$PREFIX-imported:1" out
    local reg="localhost:15000/$PREFIX/img:1"
    run --name "$PREFIX-src" alpine sh -c 'echo committed > /hello; rm /etc/motd' || return 1
    docker commit -c 'CMD ["cat", "/hello"]' "$PREFIX-src" "$img" >/dev/null || return 1
    [[ "$(run --rm "$img")" == committed ]] || return 1
    run --rm "$img" test ! -e /etc/motd || return 1

    docker save "$img" -o "$WORK/img.tar" || return 1
    docker rmi "$img" >/dev/null || return 1
    docker load -i "$WORK/img.tar" | has "Loaded image: $img" || return 1
    [[ "$(run --rm "$img")" == committed ]] || return 1
    docker save alpine | docker load | has 'Loaded image: alpine:latest' || return 1

    docker export "$PREFIX-src" -o "$WORK/fs.tar" || return 1
    docker import -c 'CMD ["cat", "/hello"]' "$WORK/fs.tar" "$imported" >/dev/null || return 1
    [[ "$(run --rm "$imported")" == committed ]] || return 1

    # The registry's data needs no volume for this.
    run -d --name "$PREFIX-registry" --tmpfs /var/lib/registry -p 127.0.0.1:15000:5000 registry:2 >/dev/null || return 1
    local ok=1
    for _ in $(seq 1 50); do
        curl -sf -m 2 http://127.0.0.1:15000/v2/ >/dev/null && { ok=0; break; }
        sleep 0.2
    done
    [[ $ok -eq 0 ]] || return 1
    docker tag "$img" "$reg" || return 1
    docker push "$reg" | has 'digest: sha256:' || return 1
    docker rmi "$reg" >/dev/null || return 1
    docker pull "$reg" >/dev/null || return 1
    out=$(run --rm "$reg") || return 1
    docker rmi -f "$img" "$imported" "$reg" >/dev/null 2>&1
    [[ "$out" == committed ]]
}

# The engine builds nothing itself, but buildx's own builder (a BuildKit
# container it starts through the engine and talks to over `docker exec`)
# builds, and `--load` hands the image back through `docker load`.
test_buildx_container_builder_builds_and_loads() {
    docker buildx version >/dev/null 2>&1 || return 0
    local builder="$PREFIX-bx" img="$PREFIX-built:1" out
    mkdir -p "$WORK/bx"
    echo built-by-buildkit > "$WORK/bx/hello.txt"
    printf 'FROM scratch\nCOPY hello.txt /hello.txt\n' > "$WORK/bx/Dockerfile"
    docker buildx create --name "$builder" --driver docker-container >/dev/null || return 1
    docker buildx build --builder "$builder" --load -t "$img" "$WORK/bx" >/dev/null 2>&1 || {
        docker buildx rm "$builder" >/dev/null 2>&1
        return 1
    }
    local id
    id=$(docker create "$img" /none) || return 1
    out=$(docker cp "$id:/hello.txt" - | tar -xO) || return 1
    docker rm "$id" >/dev/null
    docker buildx rm "$builder" >/dev/null 2>&1
    docker rmi "$img" >/dev/null 2>&1
    [[ "$out" == built-by-buildkit ]]
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

# `VOLUME /data` in redis's image: an anonymous volume, as with Docker, that
# starts with the image's directory (owner included), outlives a restart and
# goes with `rm -v`; `--volumes-from` mounts it in another container; and
# Compose keeps it across a recreate.
test_image_volumes_are_anonymous_volumes() {
    local name="$PREFIX-imgvol" vol
    run -d --name "$name" redis:7-alpine >/dev/null || return 1
    vol=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$name")
    [[ ${#vol} -eq 64 ]] || return 1
    docker volume inspect -f '{{json .Labels}}' "$vol" | has com.docker.volume.anonymous || return 1
    [[ "$(docker exec "$name" stat -c %U /data)" == redis ]] || return 1
    docker exec "$name" sh -c 'echo kept > /data/marker' || return 1
    docker restart -t 1 "$name" >/dev/null || return 1
    [[ "$(docker exec "$name" cat /data/marker)" == kept ]] || return 1
    [[ "$(run --rm --volumes-from "$name:ro" alpine cat /data/marker)" == kept ]] || return 1
    run --rm --volumes-from "$name:ro" alpine sh -c 'echo x > /data/other' 2>/dev/null && return 1
    docker rm -f -v "$name" >/dev/null || return 1
    docker volume inspect "$vol" >/dev/null 2>&1 && return 1

    mkdir -p "$WORK/imgvol"
    cat >"$WORK/imgvol/compose.yaml" <<EOF
name: ${PREFIX}-imgvol
services:
  cache:
    image: redis:7-alpine
    labels: ["$PREFIX"]
EOF
    (cd "$WORK/imgvol" && docker compose up -d) >/dev/null 2>&1 || return 1
    (cd "$WORK/imgvol" && docker compose exec -T cache sh -c 'echo kept > /data/marker') || return 1
    (cd "$WORK/imgvol" && docker compose up -d --force-recreate) >/dev/null 2>&1 || return 1
    local out
    out=$(cd "$WORK/imgvol" && docker compose exec -T cache cat /data/marker) || return 1
    (cd "$WORK/imgvol" && docker compose down -v) >/dev/null 2>&1
    [[ "$out" == kept ]]
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

test_networks_names_aliases_isolation() {
    local n1="$PREFIX-n1" n2="$PREFIX-n2"
    docker network create --label "$PREFIX" "$n1" >/dev/null || return 1
    docker network create --label "$PREFIX" "$n2" >/dev/null || return 1
    run -d --name "$PREFIX-a" --network "$n1" --network-alias alpha alpine sleep 300 >/dev/null || return 1
    run -d --name "$PREFIX-b" --network "$n2" alpine sleep 300 >/dev/null || return 1
    run --rm --network "$n1" alpine sh -c "ping -c1 -W2 $PREFIX-a && ping -c1 -W2 alpha" >/dev/null || return 1
    # Not on n2: neither its names nor its addresses are reachable.
    run --rm --network "$n1" alpine getent hosts "$PREFIX-b" >/dev/null 2>&1 && return 1
    local b_ip
    b_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$n2\").IPAddress}}" "$PREFIX-b")
    [[ -n "$b_ip" ]] || return 1
    run --rm --network "$n1" alpine ping -c1 -W2 "$b_ip" >/dev/null 2>&1 && return 1
    return 0
}

test_network_connect_and_disconnect_live() {
    local n1="$PREFIX-n1" n2="$PREFIX-n2"
    run -d --name "$PREFIX-both" --network "$n1" alpine sleep 300 >/dev/null || return 1
    docker network connect --alias bee "$n2" "$PREFIX-both" || return 1
    docker exec "$PREFIX-both" ping -c1 -W2 "$PREFIX-b" >/dev/null || return 1
    run --rm --network "$n2" alpine ping -c1 -W2 bee >/dev/null || return 1
    docker network disconnect "$n2" "$PREFIX-both" || return 1
    docker exec "$PREFIX-both" ping -c1 -W2 "$PREFIX-b" >/dev/null 2>&1 && return 1
    return 0
}

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

# `--network container:<id>` (and Compose's `network_mode: service:x`): the
# sidecar shares the other container's network, loopback included, and its
# name, keeps its own filesystem and mounts, and stops on its own.
test_network_container_mode() {
    local host="$PREFIX-nethost" side="$PREFIX-side"
    mkdir -p "$WORK/side"
    echo from-host-dir > "$WORK/side/f"
    run -d --name "$host" nginx:alpine >/dev/null || return 1
    run -d --name "$side" --network "container:$host" -v "$WORK/side:/data" alpine sleep 300 >/dev/null || return 1
    local ok=1
    for _ in $(seq 1 50); do
        docker exec "$side" wget -qO- http://127.0.0.1/ 2>/dev/null | has nginx && { ok=0; break; }
        sleep 0.2
    done
    [[ $ok -eq 0 ]] || return 1
    [[ "$(docker exec "$side" hostname)" == "$(docker exec "$host" hostname)" ]] || return 1
    [[ "$(docker exec "$side" cat /data/f)" == from-host-dir ]] || return 1
    docker exec "$side" test ! -e /usr/sbin/nginx || return 1
    run --rm --network "container:$host" -p 18093:80 alpine true >/dev/null 2>&1 && return 1
    docker stop -t 1 "$side" >/dev/null || return 1
    docker exec "$host" true || return 1
    docker start "$side" >/dev/null || return 1
    docker exec "$side" wget -qO- http://127.0.0.1/ | has nginx || return 1

    mkdir -p "$WORK/sidecar"
    cat >"$WORK/sidecar/compose.yaml" <<EOF
name: ${PREFIX}-sidecar
services:
  web:
    image: nginx:alpine
    labels: ["$PREFIX"]
  probe:
    image: alpine
    labels: ["$PREFIX"]
    network_mode: "service:web"
    command: ["sleep", "300"]
EOF
    (cd "$WORK/sidecar" && docker compose up -d) >/dev/null 2>&1 || return 1
    ok=1
    for _ in $(seq 1 50); do
        (cd "$WORK/sidecar" && docker compose exec -T probe wget -qO- http://127.0.0.1/ 2>/dev/null) | has nginx && { ok=0; break; }
        sleep 0.2
    done
    (cd "$WORK/sidecar" && docker compose down -t 1) >/dev/null 2>&1
    [[ $ok -eq 0 ]]
}

# IPv6 networks: `--ipv6` with a unique-local subnet or the client's own,
# addresses reachable from the other containers on the network, and names
# answering AAAA.
test_ipv6_networks() {
    local net="$PREFIX-v6" net2="$PREFIX-v6b" a6
    docker network create --ipv6 --label "$PREFIX" "$net" >/dev/null || return 1
    run -d --name "$PREFIX-v6a" --network "$net" nginx:alpine >/dev/null || return 1
    a6=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").GlobalIPv6Address}}" "$PREFIX-v6a")
    [[ "$a6" == fd* ]] || return 1
    docker network inspect -f '{{.EnableIPv6}}' "$net" | has true || return 1
    run --rm --network "$net" alpine sh -c "
        ip -6 addr show eth0 | grep -q '${a6%::*}' &&
        ping -6 -c1 -W2 $a6 >/dev/null &&
        nslookup -type=AAAA $PREFIX-v6a 2>/dev/null | grep -q '$a6' &&
        for i in 1 2 3 4 5 6 7 8 9 10; do wget -qO- http://[$a6]/ 2>/dev/null | grep -q nginx && exit 0; sleep 0.3; done; exit 1" || return 1
    docker network create --ipv6 --subnet fd00:dead::/64 --label "$PREFIX" "$net2" >/dev/null || return 1
    run --rm --network "$net2" alpine ip -6 addr show eth0 | has 'fd00:dead::' || return 1
    # Not on the network: its IPv6 address is out of reach too.
    run --rm --network "$net2" alpine ping -6 -c1 -W2 "$a6" >/dev/null 2>&1 && return 1
    return 0
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

# --- compose -----------------------------------------------------------------------

test_compose_healthcheck_dependency_two_networks() {
    mkdir -p "$WORK/stack"
    cat >"$WORK/stack/compose.yaml" <<EOF
name: ${PREFIX}-stack
services:
  db:
    image: alpine
    command: ["sh", "-c", "sleep 2; touch /tmp/ready; nc -lk -p 5000 -e echo db-ok"]
    healthcheck:
      test: ["CMD", "test", "-f", "/tmp/ready"]
      interval: 1s
      retries: 30
    networks: [backend]
    labels: ["$PREFIX"]
  api:
    image: alpine
    command: ["sh", "-c", "nc -lk -p 8000 -e sh -c 'nc db 5000'"]
    depends_on:
      db:
        condition: service_healthy
    networks:
      backend: {}
      frontend:
        aliases: [api-alias]
    labels: ["$PREFIX"]
  web:
    image: alpine
    command: ["sleep", "300"]
    depends_on: [api]
    networks: [frontend]
    labels: ["$PREFIX"]
networks:
  backend:
    labels: ["$PREFIX"]
  frontend:
    labels: ["$PREFIX"]
EOF
    (cd "$WORK/stack" && docker compose up -d --wait) >/dev/null 2>&1 || return 1
    local out
    out=$(cd "$WORK/stack" && docker compose exec -T web sh -c 'nc api-alias 8000 </dev/null') || true
    [[ "$out" == db-ok ]] || { (cd "$WORK/stack" && docker compose ps); return 1; }
    (cd "$WORK/stack" && docker compose exec -T web sh -c 'nc -z -w 2 db 5000') 2>/dev/null && return 1
    (cd "$WORK/stack" && docker compose ps --format '{{.Service}} {{.Health}}') | has 'db healthy' || return 1
    (cd "$WORK/stack" && docker compose logs db) >/dev/null || return 1
    (cd "$WORK/stack" && docker compose down -v) >/dev/null 2>&1
}

# --- warm bases ------------------------------------------------------------------------

# Once a few containers of one image run, later ones branch from a warm
# base where the host supports it. Each must still get its own address and
# resolver on its own network, and reach the others by name.
test_repeated_starts_keep_their_own_addresses() {
    local net="$PREFIX-warm" i ip inside
    docker network create --label "$PREFIX" "$net" >/dev/null || return 1
    for i in 1 2 3; do
        run -d --name "$PREFIX-w$i" --network "$net" alpine sleep 300 >/dev/null || return 1
    done
    # The third start has the engine boot the base; give it time to be ready.
    sleep 5
    for i in 4 5 6; do
        run -d --name "$PREFIX-w$i" --network "$net" alpine sleep 300 >/dev/null || return 1
    done
    for i in 1 2 3 4 5 6; do
        ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$PREFIX-w$i")
        inside=$(docker exec "$PREFIX-w$i" sh -c "ip -4 -o addr show eth0" | awk '{print $4}' | cut -d/ -f1)
        [[ -n "$ip" && "$ip" == "$inside" ]] || return 1
        docker exec "$PREFIX-w$i" grep -q "nameserver ${ip%.*}.1" /etc/resolv.conf || return 1
    done
    docker exec "$PREFIX-w6" ping -c1 -W2 "$PREFIX-w1" >/dev/null || return 1
    docker exec "$PREFIX-w1" ping -c1 -W2 "$PREFIX-w6" >/dev/null
}

# --- the Docker socket inside a container --------------------------------------------

test_socket_inside_container() {
    run --rm -v "$SOCKET_PATH:/var/run/docker.sock" alpine sh -c \
        'apk add -q curl >/dev/null 2>&1; curl -s --unix-socket /var/run/docker.sock http://d/_ping' | has -x OK || return 1
    # The conventional path names the engine's socket too.
    run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine sh -c \
        'apk add -q curl >/dev/null 2>&1; curl -s --unix-socket /var/run/docker.sock http://d/version' | has ApiVersion
}

test_container_starts_a_sibling_through_the_socket() {
    local out
    out=$(run --rm -v "$SOCKET_PATH:/var/run/docker.sock" alpine sh -c \
        "apk add -q docker-cli >/dev/null 2>&1; docker run --rm --label $PREFIX alpine echo from-sibling") || return 1
    [[ "$out" == from-sibling ]]
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
run_test "ports listen where asked" test_ports_listen_where_asked || true
run_test "env, workdir, user" test_env_workdir_user || true
run_test "restart policy on-failure" test_restart_policy_on_failure || true
run_test "health check goes healthy" test_healthcheck_goes_healthy || true
run_test "copy in and out" test_copy_in_and_out || true
run_test "copy before the first start" test_copy_before_start || true
run_test "events stream the lifecycle" test_events_stream_lifecycle || true
run_test "filters and labels" test_filters_and_labels || true
run_test "images list, inspect, tag, remove" test_image_list_inspect_tag_remove || true
run_test "commit, save, load, export, import, push" test_image_commit_save_load_export_import_push || true
run_test "buildx container builder builds and loads" test_buildx_container_builder_builds_and_loads || true
run_test "build is refused clearly" test_build_is_refused_clearly || true
run_test "named volume persists" test_named_volume_persists || true
run_test "new volume takes the image content" test_new_volume_takes_the_image_content || true
run_test "image volumes are anonymous volumes" test_image_volumes_are_anonymous_volumes || true
run_test "bind mounts: dir, file, read-only" test_bind_mounts_dir_file_readonly || true
run_test "tmpfs" test_tmpfs || true
run_test "networks: names, aliases, isolation" test_networks_names_aliases_isolation || true
run_test "network connect and disconnect while running" test_network_connect_and_disconnect_live || true
run_test "default bridge: by address, no names" test_default_bridge_by_address_without_names || true
run_test "--network container: shares a network" test_network_container_mode || true
run_test "IPv6 networks" test_ipv6_networks || true
run_test "host.docker.internal reaches the host" test_host_docker_internal || true
run_test "compose: health-check dependency, two networks" test_compose_healthcheck_dependency_two_networks || true
run_test "repeated starts keep their own addresses" test_repeated_starts_keep_their_own_addresses || true
run_test "docker socket inside a container" test_socket_inside_container || true
run_test "container starts a sibling through the socket" test_container_starts_a_sibling_through_the_socket || true

print_summary "engine"
