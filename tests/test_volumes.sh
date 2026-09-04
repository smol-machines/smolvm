#!/usr/bin/env bash
#
# Volume Mount Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_volumes.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Volume Mount Tests"
echo "=========================================="
echo ""

test_machine_volume_mount_visible_to_exec() {
    local vm_name="test-vm-volmnt"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create a host directory with a test file
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "volume-mount-marker-54321" > "$tmpdir/testfile.txt"

    # Create and start VM with volume mount
    $SMOLVM machine create --name "$vm_name" -v "$tmpdir:/mnt/hostdata" 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    }

    # Read the file via machine exec (VmExec) — this exercises boot-time mount
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /mnt/hostdata/testfile.txt 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ "$output" == *"volume-mount-marker-54321"* ]]
}

test_volume_mount_workspace_is_virtiofs_not_symlink() {
    local vm_name="vol-ws-virtiofs-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)
    echo "host-workspace-content" > "$tmpdir/host.txt"

    $SMOLVM machine create --name "$vm_name" -v "$tmpdir:/workspace" 2>&1 || {
        rm -rf "$tmpdir"; return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"; return 1
    }

    # /workspace must NOT be a symlink
    local link_check
    link_check=$($SMOLVM machine exec --name "$vm_name" -- sh -c '[ -L /workspace ] && echo SYMLINK || echo MOUNT' 2>&1)
    if [[ "$link_check" == *"SYMLINK"* ]]; then
        echo "FAIL: /workspace is a symlink, expected virtiofs bind mount"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"
        return 1
    fi

    # Host file must be visible
    local content
    content=$($SMOLVM machine exec --name "$vm_name" -- cat /workspace/host.txt 2>&1)
    if [[ "$content" != *"host-workspace-content"* ]]; then
        echo "FAIL: host file not visible at /workspace: $content"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"
        return 1
    fi

    # Guest write must propagate to host
    $SMOLVM machine exec --name "$vm_name" -- sh -c 'echo guest-wrote > /workspace/guest.txt' 2>&1
    if [[ ! -f "$tmpdir/guest.txt" ]] || [[ "$(cat "$tmpdir/guest.txt")" != *"guest-wrote"* ]]; then
        echo "FAIL: guest write not visible on host"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"
        return 1
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
}

test_volume_mount_arbitrary_path() {
    local vm_name="vol-arb-path-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)
    echo "arbitrary-path-content" > "$tmpdir/data.txt"

    $SMOLVM machine create --name "$vm_name" -v "$tmpdir:/data" 2>&1 || {
        rm -rf "$tmpdir"; return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"; return 1
    }

    local content
    content=$($SMOLVM machine exec --name "$vm_name" -- cat /data/data.txt 2>&1)

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"

    [[ "$content" == *"arbitrary-path-content"* ]]
}

test_trusted_system_mount_is_explicit_and_readonly() {
    # The trusted system-mount profile currently targets Linux and macOS.
    [[ "$(uname -s)" == "Linux" || "$(uname -s)" == "Darwin" ]] || return 0

    local vm_name="vol-system-ro-$$"
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local rejected
    rejected=$($SMOLVM machine create --name "$vm_name" \
        -v /etc:/host/etc:ro 2>&1) && {
        echo "FAIL: protected host mount succeeded without explicit opt-in"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$rejected" == *"protected system path"* ]] || {
        echo "FAIL: unexpected default rejection: $rejected"
        return 1
    }

    $SMOLVM machine create --name "$vm_name" --allow-system-mounts \
        -v /etc:/host/etc:ro 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    local host_identity guest_identity
    host_identity=$(cat /etc/hosts)
    guest_identity=$($SMOLVM machine exec --name "$vm_name" -- \
        cat /host/etc/hosts 2>&1)
    if [[ "$guest_identity" != "$host_identity" ]]; then
        echo "FAIL: host /etc was not visible in the guest: $guest_identity"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    local probe=".smolvm-system-mount-write-probe-$$"
    if $SMOLVM machine exec --name "$vm_name" -- touch "/host/etc/$probe" 2>/dev/null; then
        echo "FAIL: trusted system mount accepted a guest write"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    [[ ! -e "/etc/$probe" ]]
}

test_volume_mount_hot_reload_and_dax() {
    local vm_name="vol-hot-reload-$$"
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "before" > "$tmpdir/watched.txt"

    $SMOLVM machine create --name "$vm_name" --cpus 2 --mem 512 \
        -v "$tmpdir:/work" >/dev/null 2>&1 || { rm -rf "$tmpdir"; return 1; }
    SMOLVM_MOUNT_DAX=1 $SMOLVM machine start --name "$vm_name" >/dev/null 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f >/dev/null 2>&1
        rm -rf "$tmpdir"
        return 1
    }

    local mount_options guest_arch
    mount_options=$($SMOLVM machine exec --name "$vm_name" -- \
        sh -lc "awk '\$2 == \"/work\" { print \$4 }' /proc/mounts")
    guest_arch=$($SMOLVM machine exec --name "$vm_name" -- uname -m)
    if [[ "$guest_arch" == "x86_64" && "$mount_options" != *"dax=always"* ]]; then
        echo "FAIL: DAX was requested but /work options were: $mount_options"
        $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || true
        $SMOLVM machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
        rm -rf "$tmpdir"
        return 1
    fi

    local watcher_pid
    watcher_pid=$($SMOLVM machine exec --name "$vm_name" --detach -- \
        sh -lc 'exec inotifyd - /work >/tmp/host-events')
    sleep 1
    echo "after" > "$tmpdir/watched.txt.tmp"
    mv "$tmpdir/watched.txt.tmp" "$tmpdir/watched.txt"
    sleep 1

    local content events
    content=$($SMOLVM machine exec --name "$vm_name" -- cat /work/watched.txt)
    events=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/host-events)
    $SMOLVM machine exec --name "$vm_name" -- kill "$watcher_pid" >/dev/null 2>&1 || true
    $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || true
    $SMOLVM machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
    rm -rf "$tmpdir"

    [[ "$content" == "after" && "$events" == *"watched.txt"* ]]
}

test_default_workspace_symlink_without_volume() {
    local vm_name="vol-ws-default-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }

    # /workspace should be a symlink to /storage/workspace
    local target
    target=$($SMOLVM machine exec --name "$vm_name" -- readlink /workspace 2>&1)

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    [[ "$target" == *"/storage/workspace"* ]]
}

test_image_exec_volume_mount_visible() {
    local vm_name="imgexec-vol-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)
    echo "exec-volume-regression-marker" > "$tmpdir/marker.txt"

    $SMOLVM machine create --name "$vm_name" --image alpine:latest --net \
        -v "$tmpdir:/hostdata" 2>&1 || { rm -rf "$tmpdir"; return 1; }

    local start_out
    start_out=$(run_with_timeout 90 $SMOLVM machine start --name "$vm_name" 2>&1)
    if [[ $? -eq 124 ]]; then
        echo "TIMEOUT on start"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    fi

    local exec_out
    exec_out=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- cat /hostdata/marker.txt 2>&1)
    local exec_rc=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"

    [[ $exec_rc -eq 124 ]] && { echo "TIMEOUT on exec"; return 1; }
    [[ "$exec_out" == *"exec-volume-regression-marker"* ]]
}

test_image_exec_volume_mount_visible_smolfile() {
    local vm_name="imgexec-sf-vol-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)
    echo "smolfile-exec-volume-regression-marker" > "$tmpdir/marker.txt"

    # Write a Smolfile that uses a relative path (.:/app) — same shape as the
    # user's repro. We cd into tmpdir so "." resolves to it.
    cat > "$tmpdir/Smolfile.toml" <<'EOF'
image = "alpine:latest"
net = true
cpus = 1
memory = 512

[dev]
volumes = [".:/app"]
EOF

    (
        cd "$tmpdir"
        $SMOLVM machine create --name "$vm_name" -s Smolfile.toml 2>&1
    ) || { rm -rf "$tmpdir"; return 1; }

    local start_out
    start_out=$(run_with_timeout 90 $SMOLVM machine start --name "$vm_name" 2>&1)
    if [[ $? -eq 124 ]]; then
        echo "TIMEOUT on start"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    fi

    local exec_out
    exec_out=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- cat /app/marker.txt 2>&1)
    local exec_rc=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"

    [[ $exec_rc -eq 124 ]] && { echo "TIMEOUT on exec"; return 1; }
    [[ "$exec_out" == *"smolfile-exec-volume-regression-marker"* ]]
}

test_staged_volume_sync_and_restart() {
    local vm_name="vol-staged-$$"
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "staged-seed" > "$tmpdir/input.txt"

    $SMOLVM machine create --name "$vm_name" --cpus 2 --mem 512 \
        -v "$tmpdir:/workspace:staged" >/dev/null 2>&1 || { rm -rf "$tmpdir"; return 1; }
    $SMOLVM machine start --name "$vm_name" >/dev/null 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
        rm -rf "$tmpdir"
        return 1
    }

    $SMOLVM machine exec --name "$vm_name" -- sh -lc \
        'test "$(cat /workspace/input.txt)" = staged-seed && printf staged-output > /workspace/output.txt' \
        >/dev/null 2>&1 || return 1
    [[ ! -e "$tmpdir/output.txt" ]] || return 1
    $SMOLVM machine sync --name "$vm_name" >/dev/null 2>&1 || return 1
    [[ "$(cat "$tmpdir/output.txt")" == "staged-output" ]] || return 1

    $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" >/dev/null 2>&1 || return 1
    $SMOLVM machine exec --name "$vm_name" -- sh -lc \
        'test "$(cat /workspace/output.txt)" = staged-output && printf stop-sync > /workspace/final.txt' \
        >/dev/null 2>&1 || return 1
    $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || return 1

    local ok=0
    [[ "$(cat "$tmpdir/final.txt")" == "stop-sync" ]] && ok=1
    $SMOLVM machine delete --name "$vm_name" -f >/dev/null 2>&1 || true
    rm -rf "$tmpdir"
    [[ $ok -eq 1 ]]
}


# The at/below-/workspace volume matrix against a registry --image machine.
# The driver and the reasoning live in common.sh.
test_image_volume_targets_resolve_inside_guest() {
    assert_volume_targets_resolve img --image alpine:latest --net
}

run_test "Volume: mount visible to exec" test_machine_volume_mount_visible_to_exec || true
run_test "Volume: -v host:/workspace is virtiofs not symlink" test_volume_mount_workspace_is_virtiofs_not_symlink || true
run_test "Volume: arbitrary mount path (/data)" test_volume_mount_arbitrary_path || true
run_test "Volume: trusted host system mount is explicit and read-only" test_trusted_system_mount_is_explicit_and_readonly || true
run_test "Volume: host changes notify guest and DAX is consistent" test_volume_mount_hot_reload_and_dax || true
run_test "Volume: default /workspace symlink without -v" test_default_workspace_symlink_without_volume || true
run_test "Create with --image: volume mount visible to exec" test_image_exec_volume_mount_visible || true
run_test "Create with --image: Smolfile volumes visible to exec" test_image_exec_volume_mount_visible_smolfile || true
run_test "Create with --image: volume targets at/below /workspace resolve in guest" test_image_volume_targets_resolve_inside_guest || true
run_test "Volume: staged sync and restart persistence" test_staged_volume_sync_and_restart || true

print_summary "Volume Tests"
