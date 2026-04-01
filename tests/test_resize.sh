#!/bin/bash
#
# Resize feature tests for smolvm.
# Runs only the resize-related integration tests.
#
# Usage:
#   ./tests/test_resize.sh

set -euo pipefail

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes and clean up ALL test VMs
log_info "Pre-flight cleanup: killing orphan processes and removing test VMs..."
kill_orphan_smolvm_processes

# Clean up any leftover test VM directories
for vm_name in test-vm-resize-happy test-vm-resize-running test-vm-resize-shrink \
    nonexistent-vm-resize-test test-vm-resize-noparams test-vm-resize-storage-only \
    test-vm-resize-overlay-only; do
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"
done

# Cleanup on exit - stop default VM only (don't delete test VMs, they should be cleaned by each test)
trap 'cleanup_machine' EXIT

# Run only resize tests
echo ""
echo "=========================================="
echo "  smolvm Resize Feature Tests"
echo "=========================================="
echo ""

# =============================================================================
# Resize Tests
# =============================================================================

test_machine_resize_happy_path() {
    # Integration test: Happy path resize workflow (4.4)
    local vm_name="test-vm-resize-happy"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"

    # Create VM with small resources
    $SMOLVM machine create "$vm_name" --storage 5 --overlay 2 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }

    # Resize
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --storage 10 --overlay 5 2>&1)

    # Verify resize output contains expected messages
    if [[ "$resize_output" != *"Resizing machine"* ]]; then
        echo "Resize output should contain 'Resizing machine'"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    fi

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"
    ensure_data_dir_deleted "$vm_name"

    # Verify output mentions success
    [[ "$resize_output" == *"resized successfully"* ]]
}

test_machine_resize_running_vm_rejected() {
    # Integration test: Resize rejection - running VM (4.5)
    local vm_name="test-vm-resize-running"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create "$vm_name" --storage 5 --overlay 2 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Attempt resize on running VM - should fail
    local exit_code=0
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --storage 10 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail with non-zero exit code
    [[ $exit_code -ne 0 ]]
}

test_machine_resize_shrink_rejected() {
    # Integration test: Resize rejection - shrink disk (4.5)
    local vm_name="test-vm-resize-shrink"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with 10 GiB storage
    $SMOLVM machine create "$vm_name" --storage 10 --overlay 5 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Attempt to shrink to 5 GiB - should fail
    local exit_code=0
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --storage 5 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail with non-zero exit code and error message about shrinking
    [[ $exit_code -ne 0 ]] && [[ "$resize_output" == *"shrunk"* || "$resize_output" == *"larger"* ]]
}

test_machine_resize_nonexistent_vm_rejected() {
    # Integration test: Resize rejection - non-existent VM (4.5)
    local vm_name="nonexistent-vm-resize-test"

    # Attempt resize on non-existent VM
    local exit_code=0
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --storage 10 2>&1) || exit_code=$?

    # Should fail with non-zero exit code and "not found" message
    [[ $exit_code -ne 0 ]] && [[ "$resize_output" == *"not found"* ]]
}

test_machine_resize_default_vm() {
    # Integration test: Default VM resize (4.6)
    cleanup_machine

    # Start and stop default VM (created with defaults: 20 GiB storage, 10 GiB overlay)
    $SMOLVM machine start 2>&1 || return 1
    $SMOLVM machine stop 2>&1 || return 1

    # Resize default VM (no name argument) - must expand, not shrink
    local resize_output
    resize_output=$($SMOLVM machine resize --storage 30 --overlay 15 2>&1)

    # Verify resize output contains expected messages
    if [[ "$resize_output" != *"Resizing machine"* ]]; then
        echo "Resize output should contain 'Resizing machine'"
        echo "Got: $resize_output"
        $SMOLVM machine stop 2>/dev/null || true
        return 1
    fi

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true

    # Verify output mentions success
    [[ "$resize_output" == *"resized successfully"* ]]
}

test_machine_resize_no_params_rejected() {
    # Integration test: Resize with no parameters should fail
    local vm_name="test-vm-resize-noparams"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM
    $SMOLVM machine create "$vm_name" --storage 5 --overlay 2 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Attempt resize with no parameters - should fail
    local exit_code=0
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail with non-zero exit code
    [[ $exit_code -ne 0 ]]
}

test_machine_resize_storage_only() {
    # Integration test: Resize storage only (partial update)
    local vm_name="test-vm-resize-storage-only"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"

    # Create VM with small resources
    $SMOLVM machine create "$vm_name" --storage 5 --overlay 2 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }

    # Resize storage only
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --storage 15 2>&1)

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and mention storage expansion
    [[ "$resize_output" == *"Storage"* ]] && [[ "$resize_output" == *"resized successfully"* ]]
}

test_machine_resize_overlay_only() {
    # Integration test: Resize overlay only (partial update)
    local vm_name="test-vm-resize-overlay-only"

    # Aggressive cleanup - stop, delete, and remove directory
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"
    sleep 0.5

    # Create VM with small resources
    $SMOLVM machine create "$vm_name" --storage 5 --overlay 2 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    }

    # Verify disk sizes before resize (debug)
    local overlay_size
    overlay_size=$(ls -lh "$(vm_data_dir "$vm_name")/overlay.raw" 2>/dev/null | awk '{print $5}')
    if [[ "$overlay_size" != "2.0G" ]]; then
        echo "DEBUG: overlay disk is $overlay_size, expected 2.0G"
        echo "DEBUG: listing directory:"
        ls -lh "$(vm_data_dir "$vm_name")/" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        rm -rf "$(vm_data_dir "$vm_name")"
        return 1
    fi

    # Resize overlay only
    local resize_output
    resize_output=$($SMOLVM machine resize --name "$vm_name" --overlay 8 2>&1)
    echo "RESIZE OUTPUT: '$resize_output'"

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$(vm_data_dir "$vm_name")"
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and mention overlay expansion
    [[ "$resize_output" == *"Overlay"* ]] && [[ "$resize_output" == *"resized successfully"* ]]
}

run_test "Resize: happy path" test_machine_resize_happy_path || true
run_test "Resize: running VM rejected" test_machine_resize_running_vm_rejected || true
run_test "Resize: shrink rejected" test_machine_resize_shrink_rejected || true
run_test "Resize: non-existent VM rejected" test_machine_resize_nonexistent_vm_rejected || true
run_test "Resize: default VM" test_machine_resize_default_vm || true
run_test "Resize: no params rejected" test_machine_resize_no_params_rejected || true
run_test "Resize: storage only" test_machine_resize_storage_only || true
run_test "Resize: overlay only" test_machine_resize_overlay_only || true

print_summary "Resize Tests"
