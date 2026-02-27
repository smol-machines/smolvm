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
    output=$($SMOLVM sandbox run --net alpine:latest -- echo "integration-test-marker" 2>&1)
    [[ "$output" == *"integration-test-marker"* ]]
}

test_sandbox_run_cat() {
    local output
    output=$($SMOLVM sandbox run --net alpine:latest -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

# =============================================================================
# Exit Codes
# =============================================================================

test_sandbox_exit_code_zero() {
    $SMOLVM sandbox run --net alpine:latest -- sh -c "exit 0" 2>&1
}

test_sandbox_exit_code_nonzero() {
    local exit_code=0
    $SMOLVM sandbox run --net alpine:latest -- sh -c "exit 42" 2>&1 || exit_code=$?
    [[ $exit_code -eq 42 ]]
}

# =============================================================================
# Environment Variables
# =============================================================================

test_sandbox_env_variable() {
    local output
    output=$($SMOLVM sandbox run --net -e TEST_VAR=hello_world alpine:latest -- sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$output" == *"hello_world"* ]]
}

test_sandbox_multiple_env_variables() {
    local output
    output=$($SMOLVM sandbox run --net -e VAR1=one -e VAR2=two alpine:latest -- sh -c 'echo $VAR1 $VAR2' 2>&1)
    [[ "$output" == *"one"* ]] && [[ "$output" == *"two"* ]]
}

# =============================================================================
# Timeout
# =============================================================================

test_sandbox_timeout() {
    local start_time end_time elapsed output
    start_time=$(date +%s)

    output=$($SMOLVM sandbox run --net --timeout 5s alpine:latest -- sleep 60 2>&1 || true)

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
    output=$($SMOLVM sandbox run --net -w /tmp alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/tmp"* ]]
}

# =============================================================================
# Volume Mounts
# =============================================================================

test_sandbox_volume_mount_read() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "mount-test-content-12345" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/hostmnt" alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"
    [[ "$output" == *"mount-test-content-12345"* ]]
}

test_sandbox_volume_mount_write() {
    local tmpdir
    tmpdir=$(mktemp -d)

    local output
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/workspace" alpine:latest -- sh -c "echo 'written-from-vm' > /workspace/output.txt" 2>&1)

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
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/hostmnt:ro" alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Write should fail
    local write_exit=0
    $SMOLVM sandbox run --net -v "$tmpdir:/hostmnt:ro" alpine:latest -- sh -c "echo 'fail' > /hostmnt/newfile.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ "$output" == *"readonly-content"* ]] && [[ $write_exit -ne 0 ]]
}

test_sandbox_volume_mount_subdirectory() {
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/subdir/nested"
    echo "nested-file-content" > "$tmpdir/subdir/nested/deep.txt"

    local output
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/hostmnt" alpine:latest -- cat /hostmnt/subdir/nested/deep.txt 2>&1)

    rm -rf "$tmpdir"
    [[ "$output" == *"nested-file-content"* ]]
}

test_sandbox_volume_mount_multiple() {
    local tmpdir1 tmpdir2
    tmpdir1=$(mktemp -d)
    tmpdir2=$(mktemp -d)
    echo "content-one" > "$tmpdir1/file1.txt"
    echo "content-two" > "$tmpdir2/file2.txt"

    local output
    output=$($SMOLVM sandbox run --net -v "$tmpdir1:/data1" -v "$tmpdir2:/data2" alpine:latest -- sh -c "cat /data1/file1.txt && cat /data2/file2.txt" 2>&1)

    rm -rf "$tmpdir1" "$tmpdir2"
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
    output=$($SMOLVM sandbox run --net alpine:latest -- sh -c "echo 'test' > /tmp/rootfs-test.txt && cat /tmp/rootfs-test.txt" 2>&1) || exit_code=$?

    # Should succeed and contain the written content
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"test"* ]]
}

test_tsi_virtiofs_mount_write_works() {
    # Writing to virtiofs mount should work (bypasses overlayfs)
    local tmpdir
    tmpdir=$(mktemp -d)

    local output exit_code=0
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/workspace" alpine:latest -- sh -c "echo 'virtiofs-write-test' > /workspace/test.txt" 2>&1) || exit_code=$?

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
    output=$($SMOLVM sandbox run --net -v "$tmpdir:/workspace" alpine:latest -- sh -c "
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
    output=$($SMOLVM sandbox run --net alpine:latest -- sh -c "echo 'hello world' | wc -w" 2>&1)
    [[ "$output" == *"2"* ]]
}

test_sandbox_command_not_found() {
    ! $SMOLVM sandbox run --net alpine:latest -- nonexistent_command_12345 2>/dev/null
}

# =============================================================================
# Network
# Tests verify that network access is disabled by default and works when enabled.
# Note: libkrun uses TSI (Transparent Socket Impersonation) which routes network
# traffic through the host. DNS works reliably; direct HTTP may have limitations.
# =============================================================================

test_network_disabled_by_default() {
    # Without --net, network should be disabled
    # First, ensure the image is cached by pulling with --net
    $SMOLVM sandbox run --net alpine:latest -- true 2>&1 >/dev/null || true

    # Now test without --net - DNS resolution should fail when network is disabled
    local exit_code=0
    $SMOLVM sandbox run alpine:latest -- nslookup cloudflare.com 2>&1 || exit_code=$?

    # Should fail (non-zero exit code) because network is disabled
    [[ $exit_code -ne 0 ]]
}

test_network_dns_resolution() {
    # With --net, DNS resolution should work
    local output exit_code=0
    output=$($SMOLVM sandbox run --net alpine:latest -- nslookup cloudflare.com 2>&1) || exit_code=$?

    # Should succeed and contain resolved address info
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_network_multiple_dns_lookups() {
    # With --net, multiple DNS lookups should work
    local output exit_code=0
    output=$($SMOLVM sandbox run --net alpine:latest -- sh -c "nslookup google.com && nslookup github.com" 2>&1) || exit_code=$?

    # Should succeed and contain addresses for both
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

# =============================================================================
# Detached Mode + DB Persistence
# =============================================================================

test_sandbox_run_detached_appears_in_list() {
    # Clean up any existing default sandbox
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    # Run in detached mode (defaults to sleep infinity)
    local run_output exit_code=0
    run_output=$($SMOLVM sandbox run -d --net alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Setup failed: sandbox run -d returned $exit_code: $run_output"
        return 1
    fi

    # Verify it appears in sandbox ls --json as running
    local list_output
    list_output=$($SMOLVM sandbox ls --json 2>&1)

    # Clean up
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

# =============================================================================
# Smolfile with sandbox run
# =============================================================================

SMOLFILE_TMPDIR=$(mktemp -d)

test_sandbox_run_smolfile_workdir_env() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.wdenv" <<'EOF'
workdir = "/tmp"
env = ["SMOL_TEST=from_smolfile"]
EOF

    local output
    output=$($SMOLVM sandbox run -s "$SMOLFILE_TMPDIR/Smolfile.wdenv" --net alpine:latest -- sh -c 'pwd && echo $SMOL_TEST' 2>&1)
    [[ "$output" == *"/tmp"* ]] && [[ "$output" == *"from_smolfile"* ]]
}

test_sandbox_run_smolfile_cli_overrides() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.override" <<'EOF'
workdir = "/tmp"
EOF

    local output
    output=$($SMOLVM sandbox run -s "$SMOLFILE_TMPDIR/Smolfile.override" -w /root --net alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/root"* ]]
}

test_sandbox_run_smolfile_init() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.init" <<'EOF'
init = ["echo marker > /tmp/init-ran.txt"]
EOF

    local output
    output=$($SMOLVM sandbox run -s "$SMOLFILE_TMPDIR/Smolfile.init" --net alpine:latest -- cat /tmp/init-ran.txt 2>&1)
    [[ "$output" == *"marker"* ]]
}

test_sandbox_run_smolfile_init_not_rerun() {
    # Start a detached sandbox with init that appends to a counter file
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    cat > "$SMOLFILE_TMPDIR/Smolfile.norerun" <<'EOF'
init = ["echo boot >> /tmp/init-count.txt"]
EOF

    # First run: detached, starts fresh VM, init should run
    local run_output exit_code=0
    run_output=$($SMOLVM sandbox run -d -s "$SMOLFILE_TMPDIR/Smolfile.norerun" --net alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Setup failed: sandbox run -d returned $exit_code: $run_output"
        return 1
    fi

    # Verify init ran once
    local count1
    count1=$($SMOLVM microvm exec -- cat /tmp/init-count.txt 2>&1)
    local lines1
    lines1=$(echo "$count1" | grep -c "boot" || true)
    if [[ "$lines1" -ne 1 ]]; then
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Expected 1 boot line after first run, got $lines1"
        return 1
    fi

    # Second run: also detached against already-running VM, init should NOT re-run.
    # Using -d keeps the VM alive so we can verify afterwards.
    local run2_output run2_exit=0
    run2_output=$($SMOLVM sandbox run -d -s "$SMOLFILE_TMPDIR/Smolfile.norerun" --net alpine:latest 2>&1) || run2_exit=$?

    if [[ $run2_exit -ne 0 ]]; then
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Second sandbox run -d failed ($run2_exit): $run2_output"
        return 1
    fi

    # Check that init-count.txt still has exactly 1 line (init did not re-run)
    local count2
    count2=$($SMOLVM microvm exec -- cat /tmp/init-count.txt 2>&1)

    # Clean up
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    local lines2
    lines2=$(echo "$count2" | grep -c "boot" || true)
    [[ "$lines2" -eq 1 ]]
}

test_sandbox_run_smolfile_detached_persists() {
    # Clean up any existing default sandbox
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    # Init command uses $BUILD_ENV (env) and writes to cwd (workdir=/tmp)
    cat > "$SMOLFILE_TMPDIR/Smolfile.detach" <<'EOF'
cpus = 2
net = true
init = ["echo setup-$BUILD_ENV > setup-marker.txt"]
env = ["BUILD_ENV=production"]
workdir = "/tmp"
EOF

    local run_output exit_code=0
    run_output=$($SMOLVM sandbox run -d -s "$SMOLFILE_TMPDIR/Smolfile.detach" --net alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Setup failed: sandbox run -d returned $exit_code: $run_output"
        return 1
    fi

    # Verify config was persisted in sandbox ls --json (cpus, init, env, workdir)
    local list_output
    list_output=$($SMOLVM sandbox ls --json 2>&1)

    if [[ "$list_output" != *'"cpus": 2'* ]]; then
        echo "cpus not persisted"
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        return 1
    fi

    # Verify init ran on first boot with env ($BUILD_ENV) and workdir (/tmp)
    # The init command writes "setup-production" to /tmp/setup-marker.txt
    local first_check
    first_check=$($SMOLVM microvm exec -- cat /tmp/setup-marker.txt 2>&1)
    if [[ "$first_check" != *"setup-production"* ]]; then
        echo "Init did not run correctly on first boot (env/workdir issue): $first_check"
        $SMOLVM microvm stop 2>/dev/null || true
        $SMOLVM microvm delete default -f 2>/dev/null || true
        return 1
    fi

    # Delete the marker file so we can prove init re-creates it after restart
    $SMOLVM microvm exec -- rm -f /tmp/setup-marker.txt 2>&1 || true

    # Stop and restart — init should re-run on restart
    $SMOLVM sandbox stop 2>&1 || true
    $SMOLVM sandbox start 2>&1 || {
        $SMOLVM microvm delete default -f 2>/dev/null || true
        echo "Setup failed: sandbox start after stop failed"
        return 1
    }

    # Verify init re-ran after restart: marker recreated with correct env+workdir
    local setup_output
    setup_output=$($SMOLVM microvm exec -- cat /tmp/setup-marker.txt 2>&1)

    # Clean up
    $SMOLVM microvm stop 2>/dev/null || true
    $SMOLVM microvm delete default -f 2>/dev/null || true

    # "setup-production" proves: init reran, $BUILD_ENV was set, workdir was /tmp
    [[ "$setup_output" == *"setup-production"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Sandbox run detached appears in list" test_sandbox_run_detached_appears_in_list || true
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
run_test "Network: disabled by default" test_network_disabled_by_default || true
run_test "Network: DNS resolution" test_network_dns_resolution || true
run_test "Network: multiple DNS lookups" test_network_multiple_dns_lookups || true
run_test "Smolfile: workdir + env" test_sandbox_run_smolfile_workdir_env || true
run_test "Smolfile: CLI overrides workdir" test_sandbox_run_smolfile_cli_overrides || true
run_test "Smolfile: init commands run" test_sandbox_run_smolfile_init || true
run_test "Smolfile: init not rerun on reuse" test_sandbox_run_smolfile_init_not_rerun || true
run_test "Smolfile: detached persists + restart" test_sandbox_run_smolfile_detached_persists || true

rm -rf "$SMOLFILE_TMPDIR"

print_summary "Sandbox Tests"
