#!/usr/bin/env bash
#
# Local / Offline Image Tests
#
# Exercises booting a machine from a local image source with NO registry:
#   - a `docker save` archive passed as a file (--image ./image.tar)
#   - the same archive streamed on stdin (--image -)
#   - an unpacked rootfs directory (--image ./rootfs/)
# plus persistent create/start/restart from an archive and the stdin-conflict
# guard. None of these tests pass --net: booting without networking proves the
# image is sourced locally and no pull happens.
#
# Requires docker (to produce the archive/rootfs fixtures). Skips cleanly when
# docker is unavailable.
#
# Part of the smolvm test suite. Run with: ./tests/test_machine_local_image.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Fixtures built once for the whole suite.
FIXTURE_DIR=""
ARCHIVE=""
ROOTFS_DIR=""

build_fixtures() {
    FIXTURE_DIR=$(mktemp -d)
    ARCHIVE="$FIXTURE_DIR/alpine-save.tar"
    ROOTFS_DIR="$FIXTURE_DIR/alpine-rootfs"

    # docker-save archive (OCI image tarball, multi-layer with config).
    docker save alpine:latest -o "$ARCHIVE" 2>/dev/null || return 1

    # Unpacked rootfs (flat filesystem) via docker export.
    mkdir -p "$ROOTFS_DIR"
    local cid
    cid=$(docker create alpine:latest 2>/dev/null) || return 1
    docker export "$cid" 2>/dev/null | tar -x -C "$ROOTFS_DIR" 2>/dev/null
    docker rm "$cid" >/dev/null 2>&1 || true

    [[ -s "$ARCHIVE" ]] && [[ -d "$ROOTFS_DIR/bin" ]]
}

cleanup_local_image() {
    $SMOLVM machine stop --name "$PERSIST_VM" 2>/dev/null || true
    $SMOLVM machine delete --name "$PERSIST_VM" -f 2>/dev/null || true
    [[ -n "$FIXTURE_DIR" ]] && rm -rf "$FIXTURE_DIR"
}
PERSIST_VM="local-image-persist-$$"
trap cleanup_local_image EXIT

echo ""
echo "=========================================="
echo "  Local / Offline Image Tests"
echo "=========================================="
echo ""

if ! command -v docker >/dev/null 2>&1; then
    log_skip "docker not available — local-image fixtures cannot be built"
    print_summary "Local Image Tests"
    exit 0
fi

if ! build_fixtures; then
    log_skip "could not build docker fixtures (is the docker daemon running?)"
    print_summary "Local Image Tests"
    exit 0
fi

# Ephemeral run from a docker-save archive file. No --net: proves offline.
test_ephemeral_from_archive_file() {
    local output
    output=$(run_with_timeout 90 $SMOLVM machine run --image "$ARCHIVE" \
        -- sh -c 'cat /etc/os-release | head -1' 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT booting from archive file"; return 1; }
    echo "$output" | grep -q "Alpine" || {
        echo "FAIL: expected Alpine rootfs from archive, got: $output"
        return 1
    }
}

# Same archive, streamed on stdin via --image -.
test_ephemeral_from_stdin() {
    local output
    output=$(run_with_timeout 90 bash -c \
        "cat '$ARCHIVE' | '$SMOLVM' machine run --image - -- sh -c 'cat /etc/alpine-release'" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT booting from stdin archive"; return 1; }
    # alpine-release is a bare version string like 3.24.0
    echo "$output" | grep -qE '^[0-9]+\.[0-9]+' || {
        echo "FAIL: expected an alpine-release version from stdin archive, got: $output"
        return 1
    }
}

# Unpacked rootfs directory (#398). The directory IS the rootfs (single lowerdir).
test_ephemeral_from_rootfs_dir() {
    local output
    output=$(run_with_timeout 90 $SMOLVM machine run --image "$ROOTFS_DIR" \
        -- sh -c 'cat /etc/os-release | head -1' 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT booting from rootfs dir"; return 1; }
    echo "$output" | grep -q "Alpine" || {
        echo "FAIL: expected Alpine rootfs from directory, got: $output"
        return 1
    }
}

# `--image -` and -i/-t both consume stdin: reject before any VM boots.
test_stdin_guard_rejects_interactive() {
    local output exit_code=0
    output=$(echo "" | $SMOLVM machine run --image - -it 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "FAIL: --image - with -it should have been rejected"
        return 1
    }
    echo "$output" | grep -q "cannot be" || {
        echo "FAIL: expected a stdin-conflict error, got: $output"
        return 1
    }
    # The rejection must happen before launch — no VM should have started.
    echo "$output" | grep -q "Starting ephemeral machine" && {
        echo "FAIL: VM started before the guard fired"
        return 1
    }
    return 0
}

# A Dockerfile is not an image — reject with a build-first hint, not a flatten error.
test_dockerfile_rejected_with_hint() {
    local dockerfile="$FIXTURE_DIR/Dockerfile"
    printf 'FROM alpine:3.20\nRUN apk add curl\n' > "$dockerfile"

    local output exit_code=0
    output=$($SMOLVM machine run --image "$dockerfile" -- true 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "FAIL: a Dockerfile should be rejected"
        return 1
    }
    echo "$output" | grep -qi "Dockerfile" || {
        echo "FAIL: expected a build-first hint, got: $output"
        return 1
    }
}

# Persistent lifecycle from an archive: create, start, exec, stop, restart.
# Restart re-derives the local source and reopens the same on-disk rootfs.
test_persistent_create_start_restart() {
    $SMOLVM machine delete --name "$PERSIST_VM" -f 2>/dev/null || true

    $SMOLVM machine create --name "$PERSIST_VM" --image "$ARCHIVE" 2>&1 || {
        echo "FAIL: create from archive failed"; return 1
    }

    run_with_timeout 90 $SMOLVM machine start --name "$PERSIST_VM" 2>&1 || {
        echo "FAIL: first start failed"; return 1
    }

    local first
    first=$(run_with_timeout 30 $SMOLVM machine exec --name "$PERSIST_VM" \
        -- cat /etc/os-release 2>&1)
    echo "$first" | grep -q "Alpine" || {
        echo "FAIL: not Alpine after first start: $first"; return 1
    }

    # Write a marker, then stop + start: a persistent local image keeps its disk.
    run_with_timeout 30 $SMOLVM machine exec --name "$PERSIST_VM" \
        -- sh -c 'echo persisted > /root/marker' 2>&1 || {
        echo "FAIL: could not write marker"; return 1
    }

    $SMOLVM machine stop --name "$PERSIST_VM" 2>&1 || { echo "FAIL: stop failed"; return 1; }
    run_with_timeout 90 $SMOLVM machine start --name "$PERSIST_VM" 2>&1 || {
        echo "FAIL: restart failed (overlay/disk did not reopen)"; return 1
    }

    local marker
    marker=$(run_with_timeout 30 $SMOLVM machine exec --name "$PERSIST_VM" \
        -- cat /root/marker 2>&1)
    echo "$marker" | grep -q "persisted" || {
        echo "FAIL: marker not persisted across restart: $marker"; return 1
    }

    $SMOLVM machine stop --name "$PERSIST_VM" 2>/dev/null || true
    $SMOLVM machine delete --name "$PERSIST_VM" -f 2>/dev/null || true
}

run_test "Ephemeral: boot from docker-save archive file (offline)" test_ephemeral_from_archive_file || true
run_test "Ephemeral: boot from archive on stdin (--image -)" test_ephemeral_from_stdin || true
run_test "Ephemeral: boot from unpacked rootfs dir (#398)" test_ephemeral_from_rootfs_dir || true
run_test "Guard: --image - with -it rejected before boot" test_stdin_guard_rejects_interactive || true
run_test "Guard: Dockerfile rejected with build-first hint" test_dockerfile_rejected_with_hint || true
run_test "Persistent: create/start/restart from archive" test_persistent_create_start_restart || true

print_summary "Local Image Tests"
