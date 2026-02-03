#!/bin/bash
#
# Sandbox tests for smolvm.
#
# Tests the `smolvm sandbox run` command functionality.
# Requires VM environment.
#
# Usage:
#   ./tests/test_sandbox.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

echo ""
echo "=========================================="
echo "  smolvm Sandbox Tests"
echo "=========================================="
echo ""

# =============================================================================
# Basic Execution
# =============================================================================

test_sandbox_run_echo() {
    local output
    output=$($SMOLVM sandbox run alpine:latest -- echo "integration-test-marker" 2>&1)
    [[ "$output" == *"integration-test-marker"* ]]
}

test_sandbox_run_cat() {
    local output
    output=$($SMOLVM sandbox run alpine:latest -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

# =============================================================================
# Exit Codes
# =============================================================================

test_sandbox_exit_code_zero() {
    $SMOLVM sandbox run alpine:latest -- sh -c "exit 0" 2>&1
}

test_sandbox_exit_code_nonzero() {
    local exit_code=0
    $SMOLVM sandbox run alpine:latest -- sh -c "exit 42" 2>&1 || exit_code=$?
    [[ $exit_code -eq 42 ]]
}

# =============================================================================
# Environment Variables
# =============================================================================

test_sandbox_env_variable() {
    local output
    output=$($SMOLVM sandbox run -e TEST_VAR=hello_world alpine:latest -- sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$output" == *"hello_world"* ]]
}

test_sandbox_multiple_env_variables() {
    local output
    output=$($SMOLVM sandbox run -e VAR1=one -e VAR2=two alpine:latest -- sh -c 'echo $VAR1 $VAR2' 2>&1)
    [[ "$output" == *"one"* ]] && [[ "$output" == *"two"* ]]
}

# =============================================================================
# Timeout
# =============================================================================

test_sandbox_timeout() {
    local start_time end_time elapsed output
    start_time=$(date +%s)

    output=$($SMOLVM sandbox run --timeout 5s alpine:latest -- sleep 60 2>&1 || true)

    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    # Should complete in much less than 60 seconds (timeout is 5s + some overhead)
    # Allow up to 20 seconds for VM startup overhead
    if [[ $elapsed -ge 30 ]]; then
        echo "Timeout test failed: took $elapsed seconds (expected < 30)"
        return 1
    fi

    # Success: command was terminated before the 60 second sleep completed
    return 0
}

# =============================================================================
# Working Directory
# =============================================================================

test_sandbox_workdir() {
    local output
    output=$($SMOLVM sandbox run -w /tmp alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/tmp"* ]]
}

# =============================================================================
# Volume Mounts
# NOTE: These tests may fail due to a known libkrun TSI bug where virtiofs
# operations are incorrectly intercepted as network calls, causing
# "Connection reset by network" errors. See DESIGN.md for details.
# =============================================================================

test_sandbox_volume_mount_read() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "mount-test-content-12345" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt" alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    [[ "$output" == *"mount-test-content-12345"* ]]
}

test_sandbox_volume_mount_write() {
    local tmpdir
    tmpdir=$(mktemp -d)

    # Write from inside the container to mounted volume
    # NOTE: Must use top-level mount path (e.g., /workspace) not nested (e.g., /hostmnt)
    # Nested paths require creating dirs on overlayfs which triggers TSI bug
    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/workspace" alpine:latest -- sh -c "echo 'written-from-vm' > /workspace/output.txt" 2>&1)

    # Verify on host
    local content
    content=$(cat "$tmpdir/output.txt" 2>/dev/null)

    rm -rf "$tmpdir"
    [[ "$content" == *"written-from-vm"* ]]
}

test_sandbox_volume_mount_readonly() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "readonly-content" > "$tmpdir/readonly.txt"

    # Read should work
    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt:ro" alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        rm -rf "$tmpdir"
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    # Write should fail
    local write_exit=0
    $SMOLVM sandbox run -v "$tmpdir:/hostmnt:ro" alpine:latest -- sh -c "echo 'fail' > /hostmnt/newfile.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ "$output" == *"readonly-content"* ]] && [[ $write_exit -ne 0 ]]
}

test_sandbox_volume_mount_subdirectory() {
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/subdir/nested"
    echo "nested-file-content" > "$tmpdir/subdir/nested/deep.txt"

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir:/hostmnt" alpine:latest -- cat /hostmnt/subdir/nested/deep.txt 2>&1)

    rm -rf "$tmpdir"

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    [[ "$output" == *"nested-file-content"* ]]
}

test_sandbox_volume_mount_multiple() {
    local tmpdir1 tmpdir2
    tmpdir1=$(mktemp -d)
    tmpdir2=$(mktemp -d)
    echo "content-one" > "$tmpdir1/file1.txt"
    echo "content-two" > "$tmpdir2/file2.txt"

    local output
    output=$($SMOLVM sandbox run -v "$tmpdir1:/data1" -v "$tmpdir2:/data2" alpine:latest -- sh -c "cat /data1/file1.txt && cat /data2/file2.txt" 2>&1)

    rm -rf "$tmpdir1" "$tmpdir2"

    # Check for known libkrun TSI bug
    if [[ "$output" == *"Connection reset"* ]]; then
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    [[ "$output" == *"content-one"* ]] && [[ "$output" == *"content-two"* ]]
}

# =============================================================================
# TSI + Overlayfs Tests
# These tests verify that both overlayfs and virtiofs writes work correctly.
# (Previous libkrun versions had a TSI bug causing ENETRESET on overlayfs writes)
# =============================================================================

test_tsi_overlayfs_rootfs_write_works() {
    # Writing to container rootfs (overlayfs) should work
    local output exit_code=0
    output=$($SMOLVM sandbox run alpine:latest -- sh -c "echo 'test' > /tmp/rootfs-test.txt && cat /tmp/rootfs-test.txt" 2>&1) || exit_code=$?

    # Should succeed and contain the written content
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"test"* ]]
}

test_tsi_virtiofs_mount_write_works() {
    # Writing to virtiofs mount should work (bypasses overlayfs)
    local tmpdir
    tmpdir=$(mktemp -d)

    local output exit_code=0
    output=$($SMOLVM sandbox run -v "$tmpdir:/workspace" alpine:latest -- sh -c "echo 'virtiofs-write-test' > /workspace/test.txt" 2>&1) || exit_code=$?

    # Verify file was written
    local content
    content=$(cat "$tmpdir/test.txt" 2>/dev/null)

    rm -rf "$tmpdir"

    # Should succeed and file should contain expected content
    [[ $exit_code -eq 0 ]] && [[ "$content" == *"virtiofs-write-test"* ]]
}

test_tsi_coding_agent_workflow() {
    # Simulates a coding agent workflow:
    # - Read from mounted workspace
    # - Execute code
    # - Write results back to mounted workspace
    local tmpdir
    tmpdir=$(mktemp -d)

    # Create input file
    echo "input-data-12345" > "$tmpdir/input.txt"

    # Run "agent" that reads input, processes, and writes output
    local output exit_code=0
    output=$($SMOLVM sandbox run -v "$tmpdir:/workspace" alpine:latest -- sh -c "
        # Read input
        INPUT=\$(cat /workspace/input.txt)
        # Process (uppercase)
        OUTPUT=\$(echo \"\$INPUT\" | tr 'a-z' 'A-Z')
        # Write output
        echo \"\$OUTPUT\" > /workspace/output.txt
        # Create a new file
        echo 'agent-created-file' > /workspace/newfile.txt
    " 2>&1) || exit_code=$?

    # Verify outputs
    local output_content new_content
    output_content=$(cat "$tmpdir/output.txt" 2>/dev/null)
    new_content=$(cat "$tmpdir/newfile.txt" 2>/dev/null)

    rm -rf "$tmpdir"

    # All operations should succeed
    [[ $exit_code -eq 0 ]] && \
    [[ "$output_content" == *"INPUT-DATA-12345"* ]] && \
    [[ "$new_content" == *"agent-created-file"* ]]
}

# =============================================================================
# Command Execution
# =============================================================================

test_sandbox_shell_pipeline() {
    local output
    output=$($SMOLVM sandbox run alpine:latest -- sh -c "echo 'hello world' | wc -w" 2>&1)
    [[ "$output" == *"2"* ]]
}

test_sandbox_command_not_found() {
    ! $SMOLVM sandbox run alpine:latest -- nonexistent_command_12345 2>/dev/null
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Sandbox run echo" test_sandbox_run_echo || true
run_test "Sandbox run cat /etc/os-release" test_sandbox_run_cat || true
run_test "Exit code 0" test_sandbox_exit_code_zero || true
run_test "Exit code 42" test_sandbox_exit_code_nonzero || true
run_test "Environment variable" test_sandbox_env_variable || true
run_test "Multiple environment variables" test_sandbox_multiple_env_variables || true
run_test "Timeout" test_sandbox_timeout || true
run_test "Working directory" test_sandbox_workdir || true
run_test "Volume mount read" test_sandbox_volume_mount_read || true
run_test "Volume mount write" test_sandbox_volume_mount_write || true
run_test "Volume mount readonly" test_sandbox_volume_mount_readonly || true
run_test "Volume mount subdirectory" test_sandbox_volume_mount_subdirectory || true
run_test "Volume mount multiple" test_sandbox_volume_mount_multiple || true
run_test "Shell pipeline" test_sandbox_shell_pipeline || true
run_test "Command not found fails" test_sandbox_command_not_found || true
run_test "TSI: overlayfs rootfs write works" test_tsi_overlayfs_rootfs_write_works || true
run_test "TSI: virtiofs mount write works" test_tsi_virtiofs_mount_write_works || true
run_test "TSI: coding agent workflow" test_tsi_coding_agent_workflow || true

print_summary "Sandbox Tests"
