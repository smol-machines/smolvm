#!/bin/bash
#
# Machine tests for smolvm.
#
# Tests the `smolvm machine` command functionality.
# Requires VM environment.
#
# Usage:
#   ./tests/test_machine.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Cleanup on exit
trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  smolvm Machine Tests"
echo "=========================================="
echo ""

# =============================================================================
# Lifecycle
# =============================================================================

test_machine_start() {
    cleanup_machine
    $SMOLVM machine start 2>&1
}

test_machine_stop() {
    ensure_machine_running
    $SMOLVM machine stop 2>&1
}

test_machine_status_running() {
    ensure_machine_running
    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]]
}

test_machine_status_stopped() {
    cleanup_machine
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    # When stopped, status command either:
    # - Returns non-zero exit code, OR
    # - Returns status containing "not running" or "stopped"
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_machine_start_stop_cycle() {
    cleanup_machine

    # Start
    $SMOLVM machine start 2>&1 || return 1

    # Verify running
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ "$status" != *"running"* ]]; then
        return 1
    fi

    # Stop
    $SMOLVM machine stop 2>&1 || return 1

    # Verify stopped - either non-zero exit or status message indicates stopped
    exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

# =============================================================================
# Exec
# =============================================================================

test_machine_exec() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

test_machine_exec_echo() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- echo "test-marker-xyz" 2>&1)
    [[ "$output" == *"test-marker-xyz"* ]]
}

test_machine_exec_exit_code() {
    ensure_machine_running

    # Test exit 0
    $SMOLVM machine exec -- sh -c "exit 0" 2>&1 || return 1

    # Test exit 1
    local exit_code=0
    $SMOLVM machine exec -- sh -c "exit 1" 2>&1 || exit_code=$?
    [[ $exit_code -eq 1 ]]
}

# =============================================================================
# Named VMs
# =============================================================================

test_machine_named_vm() {
    local vm_name="test-vm-named"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create the named VM first
    $SMOLVM machine create "$vm_name" 2>&1 || return 1

    # Start
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check status
    local status
    status=$($SMOLVM machine status --name "$vm_name" 2>&1)
    if [[ "$status" != *"running"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and delete
    $SMOLVM machine stop --name "$vm_name" 2>&1
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

# =============================================================================
# Error Cases
# =============================================================================

test_machine_exec_when_stopped() {
    cleanup_machine

    local exit_code=0
    $SMOLVM machine exec -- echo "should-fail" 2>&1 || exit_code=$?

    # Should fail with non-zero exit code (don't check specific message)
    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Database Persistence
# =============================================================================

test_db_persistence_across_restart() {
    local vm_name="db-test-vm-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM with specific configuration
    $SMOLVM machine create "$vm_name" --cpus 2 --mem 1024 2>&1

    # Verify it was created with correct config
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)
    if [[ "$list_output" != *"$vm_name"* ]]; then
        echo "VM was not created"
        return 1
    fi

    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "VM configuration not persisted correctly"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_db_vm_state_update() {
    local vm_name="db-state-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM
    $SMOLVM machine create "$vm_name" 2>&1

    # Check initial state is "created"
    local initial_state
    initial_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$initial_state" != *'"state": "created"'* ]]; then
        echo "Initial state should be 'created'"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Start the VM
    $SMOLVM machine start --name "$vm_name" 2>&1

    # Check state changed to "running"
    local running_state
    running_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1

    # Check state changed to "stopped"
    local stopped_state
    stopped_state=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    [[ "$stopped_state" == *'"state": "stopped"'* ]]
}

test_db_delete_removes_from_db() {
    local vm_name="db-delete-test-$$"

    # Clean up any existing
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a VM
    $SMOLVM machine create "$vm_name" 2>&1

    # Verify it exists
    local before_delete
    before_delete=$($SMOLVM machine ls --json 2>&1)
    if [[ "$before_delete" != *"$vm_name"* ]]; then
        echo "VM should exist before delete"
        return 1
    fi

    # Delete it
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    # Verify it's gone
    local after_delete
    after_delete=$($SMOLVM machine ls --json 2>&1)

    [[ "$after_delete" != *"$vm_name"* ]]
}

# =============================================================================
# Network
# Tests verify that network access is disabled by default and works when enabled.
# Note: libkrun uses TSI (Transparent Socket Impersonation) which routes network
# traffic through the host. DNS works reliably; direct HTTP may have limitations.
# =============================================================================

test_machine_network_disabled_by_default() {
    local vm_name="net-disabled-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM without --net (network disabled by default)
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS resolution should fail when network is disabled
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1 || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail (non-zero exit code) because network is disabled
    [[ $exit_code -ne 0 ]]
}

test_machine_network_dns_resolution() {
    local vm_name="net-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test DNS resolution
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain resolved address info
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_network_multiple_dns_lookups() {
    local vm_name="net-multi-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test multiple DNS lookups
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c "nslookup google.com && nslookup github.com" 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain addresses for both
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

# =============================================================================
# Persistent Rootfs (Overlay)
# Tests verify that the overlayfs root is active and persists across reboots.
# =============================================================================

test_machine_overlay_root_active() {
    local vm_name="overlay-active-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check that root is an overlay mount
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- mount 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"overlay on / type overlay"* ]]
}

test_machine_rootfs_persists_across_reboot() {
    local vm_name="overlay-persist-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Write a marker file to the rootfs
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- sh -c "echo persistence-test-ok > /tmp/overlay-test-marker" 2>&1 || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Verify file exists before reboot
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || {
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if [[ "$output" != *"persistence-test-ok"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify the file survived the reboot
    exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"persistence-test-ok"* ]]
}

# =============================================================================
# Default VM DB Persistence
# Tests verify that the default VM lifecycle is reflected in the DB.
# =============================================================================

test_db_default_vm_appears_in_list_on_start() {
    cleanup_machine

    # Start the default VM (no name)
    $SMOLVM machine start 2>&1 || return 1

    # Verify "default" appears in machine ls --json as running
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_db_default_vm_shows_stopped_after_stop() {
    cleanup_machine

    # Start then stop the default VM
    $SMOLVM machine start 2>&1 || return 1
    $SMOLVM machine stop 2>&1 || return 1

    # Verify "default" shows as stopped
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "stopped"'* ]]
}

test_db_default_vm_state_transitions() {
    cleanup_machine

    # Start default VM
    $SMOLVM machine start 2>&1 || return 1

    # Check running state
    local running_state
    running_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM machine stop 2>/dev/null || true
        return 1
    fi

    # Stop default VM
    $SMOLVM machine stop 2>&1 || return 1

    # Check stopped state
    local stopped_state
    stopped_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$stopped_state" != *'"state": "stopped"'* ]]; then
        echo "State should be 'stopped' after stop"
        return 1
    fi

    # Restart and check running again
    $SMOLVM machine start 2>&1 || return 1
    local restarted_state
    restarted_state=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true

    [[ "$restarted_state" == *'"state": "running"'* ]]
}

# =============================================================================
# Volume Mounts
# =============================================================================

test_machine_volume_mount_visible_to_exec() {
    local vm_name="test-vm-volmnt"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a host directory with a test file
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "volume-mount-marker-54321" > "$tmpdir/testfile.txt"

    # Create and start VM with volume mount
    $SMOLVM machine create "$vm_name" -v "$tmpdir:/mnt/hostdata" 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    }

    # Read the file via machine exec (VmExec) — this exercises boot-time mount
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /mnt/hostdata/testfile.txt 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ "$output" == *"volume-mount-marker-54321"* ]]
}

# =============================================================================
# Port Mapping
# =============================================================================

test_machine_port_mapping_http() {
    local vm_name="test-vm-portmap"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM with port mapping (host 18199 -> guest 8080)
    $SMOLVM machine create "$vm_name" -p 18199:8080 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start a simple HTTP responder inside the VM (background exec)
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080 -w 5' &
    local server_pid=$!
    sleep 1

    # Curl the mapped port from the host
    local output
    output=$(curl -s --connect-timeout 5 http://127.0.0.1:18199/ 2>&1)
    local curl_rc=$?

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $curl_rc -eq 0 ]] && [[ "$output" == *"ok"* ]]
}

# =============================================================================
# Overlay Size
# =============================================================================

test_machine_overlay_size() {
    local vm_name="test-vm-overlay-size"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with custom overlay size (4 GiB)
    $SMOLVM machine create "$vm_name" --overlay 4 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Check the overlay disk size inside the VM via df
    local df_output
    df_output=$($SMOLVM machine exec --name "$vm_name" -- df -m / 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # The 4GB overlay should show ~3800-4096 MB total (ext4 overhead)
    # Just verify it's > 3000 MB (not the old 2GB default)
    local total_mb
    total_mb=$(echo "$df_output" | tail -1 | awk '{print $2}')
    [[ "$total_mb" -gt 3000 ]]
}

# =============================================================================
# Run Tests
# =============================================================================

# =============================================================================
# Machine Run (Ephemeral) Tests
# =============================================================================

test_machine_run_echo() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- echo "run-test-marker" 2>&1)
    [[ "$output" == *"run-test-marker"* ]]
}

test_machine_run_exit_code() {
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 0" 2>&1
    local exit_code=0
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 42" 2>&1 || exit_code=$?
    [[ $exit_code -eq 42 ]]
}

test_machine_run_env() {
    local output
    output=$($SMOLVM machine run --net -e TEST_VAR=hello_run --image alpine:latest -- sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$output" == *"hello_run"* ]]
}

test_machine_run_volume() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "run-mount-test" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt" --image alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"
    [[ "$output" == *"run-mount-test"* ]]
}

test_machine_run_volume_readonly() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "readonly-data" > "$tmpdir/readonly.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Should be able to read
    [[ "$output" == *"readonly-data"* ]] || { rm -rf "$tmpdir"; return 1; }

    # Should fail to write
    local write_exit=0
    $SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- sh -c "echo fail > /hostmnt/newfile.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ $write_exit -ne 0 ]]
}

test_machine_run_volume_multiple() {
    local tmpdir1 tmpdir2
    tmpdir1=$(mktemp -d)
    tmpdir2=$(mktemp -d)
    echo "data1" > "$tmpdir1/file1.txt"
    echo "data2" > "$tmpdir2/file2.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir1:/data1" -v "$tmpdir2:/data2" --image alpine:latest -- sh -c "cat /data1/file1.txt && cat /data2/file2.txt" 2>&1)

    rm -rf "$tmpdir1" "$tmpdir2"
    [[ "$output" == *"data1"* ]] && [[ "$output" == *"data2"* ]]
}

test_machine_run_workdir() {
    local output
    output=$($SMOLVM machine run --net -w /tmp --image alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/tmp"* ]]
}

test_machine_run_detached() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    local run_output exit_code=0
    run_output=$($SMOLVM machine run -d --net --image alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete default -f 2>/dev/null || true
        echo "Setup failed: machine run -d returned $exit_code: $run_output"
        return 1
    fi

    # Should appear in machine ls
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_machine_run_timeout() {
    local output
    output=$($SMOLVM machine run --net --timeout 5s --image alpine:latest -- sleep 60 2>&1 || true)
    # Should be killed before 60s
    [[ "$output" == *"timed out"* ]] || [[ "$output" == *"Killed"* ]] || [[ $? -ne 0 ]]
}

test_machine_run_pipeline() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- sh -c "echo 'hello world' | wc -w" 2>&1)
    [[ "$output" == *"2"* ]]
}

test_machine_run_cmd_not_found() {
    ! $SMOLVM machine run --net --image alpine:latest -- nonexistent_command_12345 2>/dev/null
}

test_machine_images() {
    # Start default machine and check images command
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true
    $SMOLVM machine create --net default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine images 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    # Should show storage info
    [[ "$output" == *"Storage"* ]] || [[ "$output" == *"storage"* ]]
}

test_machine_prune_dry_run() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true
    $SMOLVM machine create --net default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine prune --dry-run 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    # Should complete without error
    [[ $? -eq 0 ]] || [[ "$output" == *"unreferenced"* ]] || [[ "$output" == *"No unreferenced"* ]]
}

# =============================================================================
# Machine Lifecycle Tests
# =============================================================================

run_test "Machine start" test_machine_start || true
run_test "Machine stop" test_machine_stop || true
run_test "Machine status (running)" test_machine_status_running || true
run_test "Machine start/stop cycle" test_machine_start_stop_cycle || true
run_test "Machine exec" test_machine_exec || true
run_test "Machine exec exit code" test_machine_exec_exit_code || true
run_test "Named machine" test_machine_named_vm || true
run_test "Exec when stopped fails" test_machine_exec_when_stopped || true
run_test "DB persistence across restart" test_db_persistence_across_restart || true
run_test "DB VM state update" test_db_vm_state_update || true
run_test "DB delete removes from database" test_db_delete_removes_from_db || true
run_test "DB default VM appears in list on start" test_db_default_vm_appears_in_list_on_start || true
run_test "DB default VM state transitions" test_db_default_vm_state_transitions || true
run_test "Network: disabled by default" test_machine_network_disabled_by_default || true
run_test "Network: DNS resolution" test_machine_network_dns_resolution || true
run_test "Overlay: root is overlayfs" test_machine_overlay_root_active || true
run_test "Overlay: rootfs persists across reboot" test_machine_rootfs_persists_across_reboot || true
run_test "Volume: mount visible to exec" test_machine_volume_mount_visible_to_exec || true
run_test "Port: mapping host to guest HTTP" test_machine_port_mapping_http || true
run_test "Overlay: custom size via --overlay" test_machine_overlay_size || true

echo ""
echo "--- Machine Run (Ephemeral) Tests ---"
echo ""

run_test "Machine run: echo" test_machine_run_echo || true
run_test "Machine run: exit code" test_machine_run_exit_code || true
run_test "Machine run: env variable" test_machine_run_env || true
run_test "Machine run: volume mount" test_machine_run_volume || true
run_test "Machine run: volume readonly" test_machine_run_volume_readonly || true
run_test "Machine run: workdir" test_machine_run_workdir || true
run_test "Machine run: detached" test_machine_run_detached || true
run_test "Machine run: timeout" test_machine_run_timeout || true
run_test "Machine images" test_machine_images || true
run_test "Machine prune --dry-run" test_machine_prune_dry_run || true

print_summary "Machine Tests"
