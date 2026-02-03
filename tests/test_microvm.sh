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

print_summary "MicroVM Tests"
