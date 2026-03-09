#!/bin/bash
#
# MicroVM tests for smolvm.
#
# Tests the `smolvm microvm` command functionality.
# Requires VM environment.
#
# Usage:
#   ./tests/test_microvm.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Cleanup on exit
trap cleanup_microvm EXIT

echo ""
echo "=========================================="
echo "  smolvm MicroVM Tests"
echo "=========================================="
echo ""

# =============================================================================
# Lifecycle
# =============================================================================

test_microvm_start() {
    cleanup_microvm
    $SMOLVM microvm start 2>&1
}

test_microvm_stop() {
    ensure_microvm_running
    $SMOLVM microvm stop 2>&1
}

test_microvm_status_running() {
    ensure_microvm_running
    local status
    status=$($SMOLVM microvm status 2>&1)
    [[ "$status" == *"running"* ]]
}

test_microvm_status_stopped() {
    cleanup_microvm
    local status exit_code=0
    status=$($SMOLVM microvm status 2>&1) || exit_code=$?
    # When stopped, status command either:
    # - Returns non-zero exit code, OR
    # - Returns status containing "not running" or "stopped"
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_microvm_start_stop_cycle() {
    cleanup_microvm

    # Start
    $SMOLVM microvm start 2>&1 || return 1

    # Verify running
    local status exit_code=0
    status=$($SMOLVM microvm status 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ "$status" != *"running"* ]]; then
        return 1
    fi

    # Stop
    $SMOLVM microvm stop 2>&1 || return 1

    # Verify stopped - either non-zero exit or status message indicates stopped
    exit_code=0
    status=$($SMOLVM microvm status 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

# =============================================================================
# Exec
# =============================================================================

test_microvm_exec() {
    ensure_microvm_running
    local output
    output=$($SMOLVM microvm exec -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

test_microvm_exec_echo() {
    ensure_microvm_running
    local output
    output=$($SMOLVM microvm exec -- echo "test-marker-xyz" 2>&1)
    [[ "$output" == *"test-marker-xyz"* ]]
}

test_microvm_exec_exit_code() {
    ensure_microvm_running

    # Test exit 0
    $SMOLVM microvm exec -- sh -c "exit 0" 2>&1 || return 1

    # Test exit 1
    local exit_code=0
    $SMOLVM microvm exec -- sh -c "exit 1" 2>&1 || exit_code=$?
    [[ $exit_code -eq 1 ]]
}

# =============================================================================
# Named VMs
# =============================================================================

test_microvm_named_vm() {
    local vm_name="test-vm-named"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create the named VM first
    $SMOLVM microvm create "$vm_name" 2>&1 || return 1

    # Start
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check status
    local status
    status=$($SMOLVM microvm status "$vm_name" 2>&1)
    if [[ "$status" != *"running"* ]]; then
        $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and delete
    $SMOLVM microvm stop "$vm_name" 2>&1
    $SMOLVM microvm delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

# =============================================================================
# Error Cases
# =============================================================================

test_microvm_exec_when_stopped() {
    cleanup_microvm

    local exit_code=0
    $SMOLVM microvm exec -- echo "should-fail" 2>&1 || exit_code=$?

    # Should fail with non-zero exit code (don't check specific message)
    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Database Persistence
# =============================================================================

test_db_persistence_across_restart() {
    local vm_name="db-test-vm-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM with specific configuration
    $SMOLVM microvm create "$vm_name" --cpus 2 --mem 1024 2>&1

    # Verify it was created with correct config
    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$list_output" != *"$vm_name"* ]]; then
        echo "VM was not created"
        return 1
    fi

    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "VM configuration not persisted correctly"
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Clean up
    $SMOLVM microvm delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_db_vm_state_update() {
    local vm_name="db-state-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM
    $SMOLVM microvm create "$vm_name" 2>&1

    # Check initial state is "created"
    local initial_state
    initial_state=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$initial_state" != *'"state": "created"'* ]]; then
        echo "Initial state should be 'created'"
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Start the VM
    $SMOLVM microvm start "$vm_name" 2>&1

    # Check state changed to "running"
    local running_state
    running_state=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop the VM
    $SMOLVM microvm stop "$vm_name" 2>&1

    # Check state changed to "stopped"
    local stopped_state
    stopped_state=$($SMOLVM microvm ls --json 2>&1)

    # Clean up
    $SMOLVM microvm delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    [[ "$stopped_state" == *'"state": "stopped"'* ]]
}

test_db_delete_removes_from_db() {
    local vm_name="db-delete-test-$$"

    # Clean up any existing
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create a VM
    $SMOLVM microvm create "$vm_name" 2>&1

    # Verify it exists
    local before_delete
    before_delete=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$before_delete" != *"$vm_name"* ]]; then
        echo "VM should exist before delete"
        return 1
    fi

    # Delete it
    $SMOLVM microvm delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    # Verify it's gone
    local after_delete
    after_delete=$($SMOLVM microvm ls --json 2>&1)

    [[ "$after_delete" != *"$vm_name"* ]]
}

# =============================================================================
# Network
# Tests verify that network access is disabled by default and works when enabled.
# Note: libkrun uses TSI (Transparent Socket Impersonation) which routes network
# traffic through the host. DNS works reliably; direct HTTP may have limitations.
# =============================================================================

test_microvm_network_disabled_by_default() {
    local vm_name="net-disabled-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM without --net (network disabled by default)
    $SMOLVM microvm create "$vm_name" 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS resolution should fail when network is disabled
    local exit_code=0
    $SMOLVM microvm exec --name "$vm_name" -- nslookup cloudflare.com 2>&1 || exit_code=$?

    # Clean up
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail (non-zero exit code) because network is disabled
    [[ $exit_code -ne 0 ]]
}

test_microvm_network_dns_resolution() {
    local vm_name="net-dns-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM microvm create "$vm_name" --net 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test DNS resolution
    local output exit_code=0
    output=$($SMOLVM microvm exec --name "$vm_name" -- nslookup cloudflare.com 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain resolved address info
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_microvm_network_multiple_dns_lookups() {
    local vm_name="net-multi-dns-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM microvm create "$vm_name" --net 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test multiple DNS lookups
    local output exit_code=0
    output=$($SMOLVM microvm exec --name "$vm_name" -- sh -c "nslookup google.com && nslookup github.com" 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain addresses for both
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

# =============================================================================
# Persistent Rootfs (Overlay)
# Tests verify that the overlayfs root is active and persists across reboots.
# =============================================================================

test_microvm_overlay_root_active() {
    local vm_name="overlay-active-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM microvm create "$vm_name" 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check that root is an overlay mount
    local output exit_code=0
    output=$($SMOLVM microvm exec --name "$vm_name" -- mount 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"overlay on / type overlay"* ]]
}

test_microvm_rootfs_persists_across_reboot() {
    local vm_name="overlay-persist-test-$$"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM microvm create "$vm_name" 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Write a marker file to the rootfs
    local exit_code=0
    $SMOLVM microvm exec --name "$vm_name" -- sh -c "echo persistence-test-ok > /tmp/overlay-test-marker" 2>&1 || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Verify file exists before reboot
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || {
        $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if [[ "$output" != *"persistence-test-ok"* ]]; then
        $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart the VM
    $SMOLVM microvm stop "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify the file survived the reboot
    exit_code=0
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"persistence-test-ok"* ]]
}

# =============================================================================
# Egress Policy (--allow-ip / --outbound-localhost-only)
# Tests verify IP/CIDR-based egress restrictions enforced at the TSI layer
# for persistent microVMs created with `microvm create`.
# =============================================================================

test_microvm_egress_allow_ip_permitted() {
    local vm_name="egress-allow-test-$$"

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only Cloudflare DNS
    $SMOLVM microvm create "$vm_name" --allow-ip 1.1.1.1/32 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS lookup to allowed IP should succeed
    local output exit_code=0
    output=$($SMOLVM microvm exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1) || exit_code=$?

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_microvm_egress_allow_ip_blocked() {
    local vm_name="egress-block-test-$$"

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only private range — external IPs should be blocked
    $SMOLVM microvm create "$vm_name" --allow-ip 10.0.0.0/8 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM microvm exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1 || exit_code=$?

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Should fail: 1.1.1.1 is NOT in the allowlist
    [[ $exit_code -ne 0 ]]
}

test_microvm_egress_outbound_localhost_only() {
    local vm_name="egress-localhost-test-$$"

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --outbound-localhost-only
    $SMOLVM microvm create "$vm_name" --outbound-localhost-only 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { $SMOLVM microvm delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM microvm exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1 || exit_code=$?

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Should fail: only localhost is allowed
    [[ $exit_code -ne 0 ]]
}

test_microvm_egress_invalid_cidr_rejected() {
    # Invalid CIDR should be rejected at create time
    local vm_name="egress-invalid-test-$$"
    local output exit_code=0
    output=$($SMOLVM microvm create "$vm_name" --allow-ip "not-a-cidr" 2>&1) || exit_code=$?

    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    [[ $exit_code -ne 0 ]] && [[ "$output" == *"invalid"* ]]
}

# =============================================================================
# Default VM DB Persistence
# Tests verify that the default VM lifecycle is reflected in the DB.
# =============================================================================

test_db_default_vm_appears_in_list_on_start() {
    cleanup_microvm

    # Start the default VM (no name)
    $SMOLVM microvm start 2>&1 || return 1

    # Verify "default" appears in microvm ls --json as running
    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)

    # Clean up
    $SMOLVM microvm stop 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_db_default_vm_shows_stopped_after_stop() {
    cleanup_microvm

    # Start then stop the default VM
    $SMOLVM microvm start 2>&1 || return 1
    $SMOLVM microvm stop 2>&1 || return 1

    # Verify "default" shows as stopped
    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "stopped"'* ]]
}

test_db_default_vm_state_transitions() {
    cleanup_microvm

    # Start default VM
    $SMOLVM microvm start 2>&1 || return 1

    # Check running state
    local running_state
    running_state=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM microvm stop 2>/dev/null || true
        return 1
    fi

    # Stop default VM
    $SMOLVM microvm stop 2>&1 || return 1

    # Check stopped state
    local stopped_state
    stopped_state=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$stopped_state" != *'"state": "stopped"'* ]]; then
        echo "State should be 'stopped' after stop"
        return 1
    fi

    # Restart and check running again
    $SMOLVM microvm start 2>&1 || return 1
    local restarted_state
    restarted_state=$($SMOLVM microvm ls --json 2>&1)

    # Clean up
    $SMOLVM microvm stop 2>/dev/null || true

    [[ "$restarted_state" == *'"state": "running"'* ]]
}

# =============================================================================
# Volume Mounts
# =============================================================================

test_microvm_volume_mount_visible_to_exec() {
    local vm_name="test-vm-volmnt"

    # Clean up any existing
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create a host directory with a test file
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "volume-mount-marker-54321" > "$tmpdir/testfile.txt"

    # Create and start VM with volume mount
    $SMOLVM microvm create "$vm_name" -v "$tmpdir:/mnt/hostdata" 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }
    $SMOLVM microvm start "$vm_name" 2>&1 || {
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    }

    # Read the file via microvm exec (VmExec) — this exercises boot-time mount
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /mnt/hostdata/testfile.txt 2>&1)

    # Cleanup
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ "$output" == *"volume-mount-marker-54321"* ]]
}

# =============================================================================
# Port Mapping
# =============================================================================

test_microvm_port_mapping_http() {
    local vm_name="test-vm-portmap"

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM with port mapping (host 18199 -> guest 8080)
    $SMOLVM microvm create "$vm_name" -p 18199:8080 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || {
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start a simple HTTP responder inside the VM (background exec)
    $SMOLVM microvm exec --name "$vm_name" -- \
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
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $curl_rc -eq 0 ]] && [[ "$output" == *"ok"* ]]
}

# =============================================================================
# Overlay Size
# =============================================================================

test_microvm_overlay_size() {
    local vm_name="test-vm-overlay-size"

    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true

    # Create VM with custom overlay size (4 GiB)
    $SMOLVM microvm create "$vm_name" --overlay 4 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || {
        $SMOLVM microvm delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Check the overlay disk size inside the VM via df
    local df_output
    df_output=$($SMOLVM microvm exec --name "$vm_name" -- df -m / 2>&1)

    # Cleanup
    $SMOLVM microvm stop "$vm_name" 2>/dev/null || true
    $SMOLVM microvm delete "$vm_name" -f 2>/dev/null || true
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

run_test "Microvm start" test_microvm_start || true
run_test "Microvm stop" test_microvm_stop || true
run_test "Microvm status (running)" test_microvm_status_running || true
run_test "Microvm status (stopped)" test_microvm_status_stopped || true
run_test "Microvm start/stop cycle" test_microvm_start_stop_cycle || true
run_test "Microvm exec" test_microvm_exec || true
run_test "Microvm exec echo" test_microvm_exec_echo || true
run_test "Microvm exec exit code" test_microvm_exec_exit_code || true
run_test "Named microvm" test_microvm_named_vm || true
run_test "Exec when stopped fails" test_microvm_exec_when_stopped || true
run_test "DB persistence across restart" test_db_persistence_across_restart || true
run_test "DB VM state update" test_db_vm_state_update || true
run_test "DB delete removes from database" test_db_delete_removes_from_db || true
run_test "DB default VM appears in list on start" test_db_default_vm_appears_in_list_on_start || true
run_test "DB default VM shows stopped after stop" test_db_default_vm_shows_stopped_after_stop || true
run_test "DB default VM state transitions" test_db_default_vm_state_transitions || true
run_test "Network: disabled by default" test_microvm_network_disabled_by_default || true
run_test "Network: DNS resolution" test_microvm_network_dns_resolution || true
run_test "Network: multiple DNS lookups" test_microvm_network_multiple_dns_lookups || true
run_test "Overlay: root is overlayfs" test_microvm_overlay_root_active || true
run_test "Overlay: rootfs persists across reboot" test_microvm_rootfs_persists_across_reboot || true
run_test "Egress: allow-ip permits matching traffic" test_microvm_egress_allow_ip_permitted || true
run_test "Egress: allow-ip blocks non-matching traffic" test_microvm_egress_allow_ip_blocked || true
run_test "Egress: --outbound-localhost-only blocks external" test_microvm_egress_outbound_localhost_only || true
run_test "Egress: invalid CIDR rejected at create" test_microvm_egress_invalid_cidr_rejected || true
run_test "Volume: mount visible to exec" test_microvm_volume_mount_visible_to_exec || true
run_test "Port: mapping host to guest HTTP" test_microvm_port_mapping_http || true
run_test "Overlay: custom size via --overlay" test_microvm_overlay_size || true

print_summary "MicroVM Tests"
