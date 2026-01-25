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
    local status
    status=$($SMOLVM microvm status 2>&1) || true
    [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_microvm_start_stop_cycle() {
    cleanup_microvm

    # Start
    $SMOLVM microvm start 2>&1 || return 1

    # Verify running
    local status
    status=$($SMOLVM microvm status 2>&1)
    [[ "$status" == *"running"* ]] || return 1

    # Stop
    $SMOLVM microvm stop 2>&1 || return 1

    # Verify stopped
    status=$($SMOLVM microvm status 2>&1) || true
    [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
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
# Volume Mounts (via sandbox run, since microvm doesn't have run command)
# NOTE: These tests may fail due to a known libkrun TSI bug where virtiofs
# operations are incorrectly intercepted as network calls, causing
# "Connection reset by network" errors. See DESIGN.md for details.
# =============================================================================

test_volume_mount_read() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "mount-test-content" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt" alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    [[ "$output" == *"mount-test-content"* ]]
}

test_volume_mount_write() {
    local tmpdir
    tmpdir=$(mktemp -d)

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt" alpine:latest -- sh -c "echo 'written-from-vm' > /hostmnt/written.txt" 2>&1)

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        rm -rf "$tmpdir"
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    local content
    content=$(cat "$tmpdir/written.txt" 2>/dev/null)

    rm -rf "$tmpdir"
    [[ "$content" == *"written-from-vm"* ]]
}

test_volume_mount_readonly() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "ro-content" > "$tmpdir/readonly.txt"

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt:ro" alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        rm -rf "$tmpdir"
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    local write_exit=0
    $SMOLVM sandbox run -v "$tmpdir:/hostmnt:ro" alpine:latest -- sh -c "echo 'fail' > /hostmnt/new.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ "$output" == *"ro-content"* ]] && [[ $write_exit -ne 0 ]]
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

    local output exit_code=0
    output=$($SMOLVM microvm exec -- echo "should-fail" 2>&1) || exit_code=$?

    # Should fail with error about not running
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"not running"* ]]
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
run_test "Volume mount read" test_volume_mount_read || true
run_test "Volume mount write" test_volume_mount_write || true
run_test "Volume mount readonly" test_volume_mount_readonly || true
run_test "Named microvm" test_microvm_named_vm || true
run_test "Exec when stopped fails" test_microvm_exec_when_stopped || true

print_summary "MicroVM Tests"
