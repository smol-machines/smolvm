#!/bin/bash
#
# Pack tests for smolvm.
#
# Tests the `smolvm pack` command and packed binary execution.
# Requires VM environment and sufficient disk space (~500MB for images).
#
# Usage:
#   ./tests/test_pack.sh [--quick]
#
# Options:
#   --quick    Skip slow tests (large image packing, daemon mode)

source "$(dirname "$0")/common.sh"
init_smolvm

QUICK_MODE=false
if [[ "${1:-}" == "--quick" ]]; then
    QUICK_MODE=true
fi

echo ""
echo "=========================================="
echo "  smolvm Pack Tests"
echo "=========================================="
echo ""

# Test output directory (cleaned up at end)
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT

# =============================================================================
# Pack Command - Basic Tests
# =============================================================================

test_pack_help() {
    # Verify pack command exists and shows help
    $SMOLVM pack --help 2>&1 | grep -q "Package an OCI image"
}

test_pack_requires_output() {
    # Pack should fail without -o flag
    local exit_code=0
    $SMOLVM pack alpine:latest 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]]
}

test_pack_alpine() {
    # Pack a minimal image
    local output="$TEST_DIR/test-alpine"
    local result
    result=$($SMOLVM pack alpine:latest -o "$output" 2>&1)

    # Binary should exist
    [[ -f "$output" ]]

    # Sidecar should exist
    [[ -f "$output.smoldata" ]]

    # Binary should be executable
    [[ -x "$output" ]]
}

test_pack_with_custom_resources() {
    # Pack with custom CPU/memory defaults
    local output="$TEST_DIR/test-resources"
    $SMOLVM pack alpine:latest -o "$output" --cpus 2 --mem 512 2>&1

    # Verify manifest has custom values
    local info
    info=$("$output" --info 2>&1)
    [[ "$info" == *"Default CPUs: 2"* ]] && [[ "$info" == *"Default Memory: 512"* ]]
}

# =============================================================================
# Packed Binary - Info and Version
# =============================================================================

test_packed_version() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local version_output
    version_output=$("$output" --version 2>&1)

    # Should show image info
    [[ "$version_output" == *"alpine:latest"* ]] || [[ "$version_output" == *"alpine"* ]]
}

test_packed_info() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local info_output
    info_output=$("$output" --info 2>&1)

    # Should show image, platform, assets
    [[ "$info_output" == *"Image:"* ]] && \
    [[ "$info_output" == *"Platform:"* ]] && \
    [[ "$info_output" == *"Assets:"* ]]
}

# =============================================================================
# Packed Binary - Ephemeral Execution (Requires VM)
# =============================================================================

test_packed_run_echo() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$("$output" echo "pack-test-marker-12345" 2>&1)
    [[ "$result" == *"pack-test-marker-12345"* ]]
}

test_packed_run_cat() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$("$output" cat /etc/os-release 2>&1)
    [[ "$result" == *"Alpine"* ]]
}

test_packed_exit_code() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Exit code 0
    "$output" sh -c "exit 0" 2>&1
    local exit_zero=$?

    # Exit code 42
    local exit_42=0
    "$output" sh -c "exit 42" 2>&1 || exit_42=$?

    [[ $exit_zero -eq 0 ]] && [[ $exit_42 -eq 42 ]]
}

test_packed_env_var() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$("$output" -e TEST_VAR=hello_pack sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$result" == *"hello_pack"* ]]
}

test_packed_volume_mount() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Create test file
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "mount-test-from-pack" > "$tmpdir/testfile.txt"

    local result
    result=$("$output" -v "$tmpdir:/workspace" cat /workspace/testfile.txt 2>&1)

    rm -rf "$tmpdir"

    # Check for known libkrun TSI bug
    if [[ "$result" == *"Connection reset"* ]]; then
        echo "SKIP: libkrun TSI bug (Connection reset)"
        return 0
    fi

    [[ "$result" == *"mount-test-from-pack"* ]]
}

test_packed_volume_write() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local tmpdir
    tmpdir=$(mktemp -d)

    # Write from container to host
    "$output" -v "$tmpdir:/workspace" sh -c "echo 'written-from-packed' > /workspace/output.txt" 2>&1

    local content
    content=$(cat "$tmpdir/output.txt" 2>/dev/null)

    rm -rf "$tmpdir"

    [[ "$content" == *"written-from-packed"* ]]
}

test_packed_workdir() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$("$output" -w /tmp pwd 2>&1)
    [[ "$result" == *"/tmp"* ]]
}

# =============================================================================
# Packed Binary - Daemon Mode (Requires VM)
# =============================================================================

test_packed_daemon_start_stop() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Start daemon
    local start_result
    start_result=$("$output" start 2>&1)
    if [[ $? -ne 0 ]]; then
        echo "start failed: $start_result"
        return 1
    fi

    # Give it a moment to start
    sleep 2

    # Check status
    local status_result
    status_result=$("$output" status 2>&1)
    if [[ "$status_result" != *"running"* ]] && [[ "$status_result" != *"Daemon running"* ]]; then
        echo "status check failed: $status_result"
        "$output" stop 2>/dev/null || true
        return 1
    fi

    # Stop daemon
    local stop_result
    stop_result=$("$output" stop 2>&1)
    if [[ $? -ne 0 ]]; then
        echo "stop failed: $stop_result"
        return 1
    fi

    return 0
}

test_packed_daemon_exec() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Start daemon
    "$output" start 2>&1
    sleep 2

    # Run exec commands
    local result1 result2
    result1=$("$output" exec echo "daemon-exec-test-1" 2>&1)
    result2=$("$output" exec echo "daemon-exec-test-2" 2>&1)

    # Stop daemon
    "$output" stop 2>&1

    [[ "$result1" == *"daemon-exec-test-1"* ]] && [[ "$result2" == *"daemon-exec-test-2"* ]]
}

test_packed_daemon_exec_latency() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Start daemon
    "$output" start 2>&1
    sleep 2

    # Measure exec latency
    local start_time end_time elapsed
    start_time=$(date +%s%3N 2>/dev/null || date +%s)

    "$output" exec echo "latency-test" 2>&1 >/dev/null

    end_time=$(date +%s%3N 2>/dev/null || date +%s)

    # Stop daemon
    "$output" stop 2>&1

    # Calculate elapsed time
    if [[ "$start_time" =~ ^[0-9]{10,}$ ]]; then
        # Milliseconds available
        elapsed=$((end_time - start_time))
        # Should be under 500ms (generous for slow systems)
        [[ $elapsed -lt 500 ]]
    else
        # Only seconds available, just pass
        return 0
    fi
}

# =============================================================================
# Sidecar File Tests
# =============================================================================

test_sidecar_exists() {
    local output="$TEST_DIR/test-sidecar"
    $SMOLVM pack alpine:latest -o "$output" 2>&1

    # Sidecar file should exist with .smoldata extension
    [[ -f "$output.smoldata" ]]
}

test_sidecar_size() {
    local output="$TEST_DIR/test-sidecar"

    if [[ ! -f "$output.smoldata" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Sidecar should be substantial (contains compressed assets)
    local size
    size=$(stat -f%z "$output.smoldata" 2>/dev/null || stat -c%s "$output.smoldata" 2>/dev/null)

    # Should be at least 1MB (kernel + libraries)
    [[ $size -gt 1000000 ]]
}

test_sidecar_required() {
    local output="$TEST_DIR/test-sidecar"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Remove sidecar
    rm -f "$output.smoldata"

    # Binary should fail without sidecar
    local exit_code=0
    "$output" --info 2>&1 || exit_code=$?

    # Restore sidecar for other tests
    $SMOLVM pack alpine:latest -o "$output" 2>&1 >/dev/null

    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Cache Directory Tests
# =============================================================================

test_cache_directory_created() {
    local output="$TEST_DIR/test-cache"
    $SMOLVM pack alpine:latest -o "$output" 2>&1

    # Run a command to trigger extraction
    "$output" echo "trigger-extraction" 2>&1 >/dev/null || true

    # Check cache directory exists
    local cache_base
    if [[ "$(uname)" == "Darwin" ]]; then
        cache_base="$HOME/Library/Caches/smolvm-pack"
    else
        cache_base="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm-pack"
    fi

    [[ -d "$cache_base" ]]
}

test_force_extract() {
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Run with debug to see extraction behavior
    local result
    result=$("$output" --debug --force-extract echo "force-test" 2>&1)

    # Should show extraction messages
    [[ "$result" == *"extract"* ]]
}

# =============================================================================
# Error Handling Tests
# =============================================================================

test_pack_nonexistent_image() {
    local output="$TEST_DIR/test-nonexistent"
    local exit_code=0
    $SMOLVM pack nonexistent-image-that-does-not-exist:v999 -o "$output" 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]]
}

test_packed_invalid_volume_syntax() {
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Invalid volume syntax should be ignored (no colon)
    local result
    result=$("$output" -v "invalid-volume-syntax" echo "test" 2>&1)

    # Command should still run (invalid volume ignored)
    [[ "$result" == *"test"* ]] || [[ $? -eq 0 ]]
}

# =============================================================================
# Python Image Test (Larger image, skip in quick mode)
# =============================================================================

test_pack_python() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-python"
    $SMOLVM pack python:3.12-slim -o "$output" 2>&1

    [[ -f "$output" ]] && [[ -f "$output.smoldata" ]]
}

test_packed_python_run() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-python"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack python:3.12-slim -o "$output" 2>&1
    fi

    local result
    result=$("$output" python -c "print('Hello from packed Python')" 2>&1)
    [[ "$result" == *"Hello from packed Python"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

echo "Running Pack Command Tests..."
echo ""

run_test "Pack help" test_pack_help || true
run_test "Pack requires output" test_pack_requires_output || true
run_test "Pack alpine" test_pack_alpine || true
run_test "Pack with custom resources" test_pack_with_custom_resources || true

echo ""
echo "Running Packed Binary Info Tests..."
echo ""

run_test "Packed --version" test_packed_version || true
run_test "Packed --info" test_packed_info || true

echo ""
echo "Running Sidecar Tests..."
echo ""

run_test "Sidecar exists" test_sidecar_exists || true
run_test "Sidecar size" test_sidecar_size || true
run_test "Sidecar required" test_sidecar_required || true

echo ""
echo "Running Packed Binary Execution Tests (requires VM)..."
echo ""

run_test "Packed run echo" test_packed_run_echo || true
run_test "Packed run cat" test_packed_run_cat || true
run_test "Packed exit code" test_packed_exit_code || true
run_test "Packed env variable" test_packed_env_var || true
run_test "Packed volume mount read" test_packed_volume_mount || true
run_test "Packed volume mount write" test_packed_volume_write || true
run_test "Packed workdir" test_packed_workdir || true

echo ""
echo "Running Daemon Mode Tests (requires VM)..."
echo ""

run_test "Daemon start/stop" test_packed_daemon_start_stop || true
run_test "Daemon exec" test_packed_daemon_exec || true
run_test "Daemon exec latency" test_packed_daemon_exec_latency || true

echo ""
echo "Running Cache Tests..."
echo ""

run_test "Cache directory created" test_cache_directory_created || true
run_test "Force extract" test_force_extract || true

echo ""
echo "Running Error Handling Tests..."
echo ""

run_test "Pack nonexistent image" test_pack_nonexistent_image || true
run_test "Invalid volume syntax" test_packed_invalid_volume_syntax || true

if [[ "$QUICK_MODE" != "true" ]]; then
    echo ""
    echo "Running Large Image Tests..."
    echo ""

    run_test "Pack Python image" test_pack_python || true
    run_test "Packed Python run" test_packed_python_run || true
fi

print_summary "Pack Tests"
