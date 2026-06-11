#!/bin/bash
#
# Database State Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_db.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Database State Tests"
echo "=========================================="
echo ""

test_db_persistence_across_restart() {
    local vm_name="db-test-vm-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create a named VM with specific configuration
    $SMOLVM machine create --name "$vm_name" --cpus 2 --mem 1024 2>&1

    # Verify it was created with correct config
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)
    if [[ "$list_output" != *"$vm_name"* ]]; then
        echo "VM was not created"
        return 1
    fi

    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "VM configuration not persisted correctly"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Clean up
    $SMOLVM machine delete --name "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_db_vm_state_update() {
    local vm_name="db-state-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create a named VM
    $SMOLVM machine create --name "$vm_name" 2>&1

    # Check initial state is "created"
    local initial_state
    initial_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$initial_state" != *'"state": "created"'* ]]; then
        echo "Initial state should be 'created'"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
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
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1

    # Check state changed to "stopped"
    local stopped_state
    stopped_state=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine delete --name "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    [[ "$stopped_state" == *'"state": "stopped"'* ]]
}

test_db_delete_removes_from_db() {
    local vm_name="db-delete-test-$$"

    # Clean up any existing
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create a VM
    $SMOLVM machine create --name "$vm_name" 2>&1

    # Verify it exists
    local before_delete
    before_delete=$($SMOLVM machine ls --json 2>&1)
    if [[ "$before_delete" != *"$vm_name"* ]]; then
        echo "VM should exist before delete"
        return 1
    fi

    # Delete it
    $SMOLVM machine delete --name "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    # Verify it's gone
    local after_delete
    after_delete=$($SMOLVM machine ls --json 2>&1)

    [[ "$after_delete" != *"$vm_name"* ]]
}

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


run_test "DB persistence across restart" test_db_persistence_across_restart || true
run_test "DB VM state update" test_db_vm_state_update || true
run_test "DB delete removes from database" test_db_delete_removes_from_db || true
run_test "DB default VM appears in list on start" test_db_default_vm_appears_in_list_on_start || true
run_test "DB default VM shows stopped after stop" test_db_default_vm_shows_stopped_after_stop || true
run_test "DB default VM state transitions" test_db_default_vm_state_transitions || true

print_summary "DB State Tests"
