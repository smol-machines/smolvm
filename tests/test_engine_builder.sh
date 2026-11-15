#!/usr/bin/env bash
# Exercise the native builder through the real Buildx client and OS socket activation.
source "$(dirname "$0")/common.sh"
init_smolvm
if ! docker buildx version >/dev/null 2>&1; then
    log_skip "docker CLI with buildx is required"
    exit 0
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/smol-builder-XXXXXX")
# macOS /tmp is a symlink; durable machine identity uses the canonical path.
WORK=$(cd "$WORK" && pwd -P)
SOCKET="$WORK/docker.sock"
ROOT="$WORK/engine"
BUILDER="smol-native-test-$$"
IMAGE="$BUILDER:result"
MACHINE="buildkit-$(printf %s "$ROOT/buildkit" | shasum -a 256 | cut -c1-16)"
export DOCKER_HOST="unix://$SOCKET"
unset DOCKER_CONTEXT BUILDX_BUILDER
cleanup() {
    local status=$?
    if [[ $status != 0 ]]; then
        cat "$WORK/build.log" "$ROOT/buildkit/adapter.log" 2>/dev/null || true
    fi
    docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
    docker image rm -f "$IMAGE" "$BUILDER:fast" "$BUILDER:slow" >/dev/null 2>&1 || true
    "$SMOLVM" engine unregister --socket "$SOCKET" --root "$ROOT" >/dev/null 2>&1 || true
    "$SMOLVM" machine delete --name "$MACHINE" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
"$SMOLVM" engine register --socket "$SOCKET" --root "$ROOT"
mkdir "$WORK/context"
cat > "$WORK/context/Dockerfile" <<'DOCKERFILE'
FROM alpine AS build
ARG SEQUENCE
RUN --mount=type=cache,target=/cache \
    echo "$SEQUENCE" >/sequence && \
    n=$(cat /cache/count 2>/dev/null || echo 0) && n=$((n+1)) && \
    echo "$n" >/cache/count && mkdir /result && cp /cache/count /result/count
RUN touch /result/deleted && chmod 000 /result/count
RUN rm /result/deleted && cat /result/count && chmod 644 /result/count
FROM alpine
COPY --from=build /result /result
USER 65534:65534
CMD ["cat", "/result/count"]
DOCKERFILE
register_builder() {
    docker buildx create --name "$BUILDER" --driver remote \
        --driver-opt default-load=true \
        "unix://$WORK/docker.buildkit.sock" >>"$WORK/build.log" 2>&1
}
build_and_check() {
    docker buildx build --builder "$BUILDER" --build-arg "SEQUENCE=$1" \
        -t "$IMAGE" "$WORK/context" >>"$WORK/build.log" 2>&1
    local container="$BUILDER-check-$1" actual
    docker create --name "$container" "$IMAGE" >/dev/null
    if ! actual=$(docker start -a "$container"); then
        docker inspect "$container" >&2
        docker rm -f "$container" >/dev/null
        return 1
    fi
    docker rm "$container" >/dev/null
    if [[ "$actual" != "$1" ]]; then
        printf 'Expected cache count %s; got %s\n' "$1" "$actual" >&2
        return 1
    fi
    docker run --rm "$IMAGE" sh -c 'test ! -e /result/deleted'
}
wait_stopped() {
    local i out
    for i in $(seq 1 40); do
        out=$("$SMOLVM" machine status --name "$MACHINE" 2>&1)
        if printf '%s\n' "$out" | grep -i 'stopped' >/dev/null &&
            ! ps -axo args= | grep 'engine buildkit-serve' | grep -F "$ROOT/buildkit" >/dev/null; then return 0; fi
        sleep 1
    done
    printf '%s\n' "$out" >&2
    return 1
}
register_builder
build_and_check 1
"$SMOLVM" machine exec --name "$MACHINE" -- sh -c \
    'grep " /workspace ext4 " /proc/mounts && buildctl debug workers -v' >"$WORK/worker.log"
grep 'snapshotter:.*overlayfs' "$WORK/worker.log" >/dev/null
# Idle shutdown releases the VM, but the disk and cache remain.
wait_stopped
build_and_check 2
# Remote registrations do not own server state: both removal variants retain it.
docker buildx rm --keep-state "$BUILDER" >>"$WORK/build.log" 2>&1
register_builder
build_and_check 3
docker buildx rm "$BUILDER" >>"$WORK/build.log" 2>&1
register_builder
build_and_check 4
# A cached solve must not rerun the cache-mount increment.
build_and_check 4
# One client finishing must not idle-stop another client's active build.
mkdir "$WORK/concurrent"
cat > "$WORK/concurrent/Dockerfile" <<'DOCKERFILE'
FROM alpine
ARG DELAY
RUN sleep "$DELAY" && echo "$DELAY" >/delay
CMD ["cat", "/delay"]
DOCKERFILE
docker buildx build --builder "$BUILDER" --build-arg DELAY=15 -t "$BUILDER:slow" "$WORK/concurrent" >>"$WORK/build.log" 2>&1 &
slow=$!
docker buildx build --builder "$BUILDER" --build-arg DELAY=0 -t "$BUILDER:fast" "$WORK/concurrent" >>"$WORK/build.log" 2>&1
wait "$slow"
[[ $(docker run --rm "$BUILDER:slow") == 15 ]]
[[ $(docker run --rm "$BUILDER:fast") == 0 ]]
docker buildx prune --builder "$BUILDER" --all --force >>"$WORK/build.log" 2>&1
build_and_check 1
wait_stopped
printf 'PASS: default load, multi-stage whiteouts, idle shutdown/restart, and cache retention across both registration removal modes, concurrent builds, and prune\n'
