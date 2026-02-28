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

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"persistence-test-ok"* ]]
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

print_summary "MicroVM Tests"
