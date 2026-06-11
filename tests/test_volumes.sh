#!/bin/bash
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


run_test "Volume: mount visible to exec" test_machine_volume_mount_visible_to_exec || true
run_test "Volume: -v host:/workspace is virtiofs not symlink" test_volume_mount_workspace_is_virtiofs_not_symlink || true
run_test "Volume: arbitrary mount path (/data)" test_volume_mount_arbitrary_path || true
run_test "Volume: default /workspace symlink without -v" test_default_workspace_symlink_without_volume || true
run_test "Create with --image: volume mount visible to exec" test_image_exec_volume_mount_visible || true
run_test "Create with --image: Smolfile volumes visible to exec" test_image_exec_volume_mount_visible_smolfile || true

print_summary "Volume Tests"
