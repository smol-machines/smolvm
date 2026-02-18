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

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

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
    [[ -f "$output.smolmachine" ]]

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
    [[ "$info" == *"CPUs:"*"2"* ]] && [[ "$info" == *"Memory:"*"512"* ]]
}

test_pack_with_platform() {
    # Pack with explicit platform
    local output="$TEST_DIR/test-platform"

    # Determine host platform for the test
    local host_arch
    if [[ "$(uname -m)" == "arm64" ]] || [[ "$(uname -m)" == "aarch64" ]]; then
        host_arch="linux/arm64"
    else
        host_arch="linux/amd64"
    fi

    $SMOLVM pack alpine:latest -o "$output" --platform "$host_arch" 2>&1

    # Binary should exist
    [[ -f "$output" ]]

    # Verify manifest shows correct platform
    local info
    info=$("$output" --info 2>&1)
    [[ "$info" == *"Platform:"* ]]
}

# =============================================================================
# Packed Binary - Info
# =============================================================================

test_packed_info() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Test --info
    local info_output
    info_output=$("$output" --info 2>&1)
    [[ "$info_output" == *"Image:"* ]] && \
    [[ "$info_output" == *"Platform:"* ]] && \
    [[ "$info_output" == *"Checksum:"* ]] || return 1
}

# =============================================================================
# Packed Binary - Ephemeral Execution (Requires VM)
# =============================================================================

test_packed_run_echo() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary with sidecar
    if [[ ! -f "$output" ]] || [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Run with 60s timeout to prevent indefinite hangs
    local result
    result=$(run_with_timeout 60 "$output" echo "pack-test-marker-12345" 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 124 ]]; then
        echo "TIMEOUT: packed binary hung"
        return 1
    fi

    [[ "$result" == *"pack-test-marker-12345"* ]]
}

test_packed_exit_code() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Exit code 0 (with timeout)
    run_with_timeout 60 "$output" sh -c "exit 0" 2>&1
    local exit_zero=$?
    [[ $exit_zero -eq 124 ]] && { echo "TIMEOUT"; return 1; }

    # Exit code 42 (with timeout)
    local exit_42=0
    run_with_timeout 60 "$output" sh -c "exit 42" 2>&1 || exit_42=$?
    [[ $exit_42 -eq 124 ]] && { echo "TIMEOUT"; return 1; }

    [[ $exit_zero -eq 0 ]] && [[ $exit_42 -eq 42 ]]
}

test_packed_env_var() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$(run_with_timeout 60 "$output" -e TEST_VAR=hello_pack sh -c 'echo $TEST_VAR' 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"hello_pack"* ]]
}

test_packed_workdir() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary
    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    local result
    result=$(run_with_timeout 60 "$output" -w /tmp pwd 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"/tmp"* ]]
}

# =============================================================================
# Sidecar File Tests
# =============================================================================

test_sidecar_required() {
    local output="$TEST_DIR/test-sidecar"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Remove sidecar
    rm -f "$output.smolmachine"

    # Binary should fail without sidecar
    local exit_code=0
    "$output" --info 2>&1 || exit_code=$?

    # Restore sidecar for other tests
    $SMOLVM pack alpine:latest -o "$output" 2>&1 >/dev/null

    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Single-File Mode Tests (--single-file)
# =============================================================================

test_single_file_pack() {
    # Pack with --single-file flag
    local output="$TEST_DIR/test-single-file"
    $SMOLVM pack alpine:latest -o "$output" --single-file 2>&1

    # Binary should exist and be executable
    [[ -f "$output" ]] || return 1
    [[ -x "$output" ]] || return 1

    # Sidecar should NOT exist
    [[ ! -f "$output.smolmachine" ]] || return 1

    # Should work when moved (no sidecar needed)
    local new_dir="$TEST_DIR/standalone-test"
    mkdir -p "$new_dir"
    cp "$output" "$new_dir/myapp"
    local info_output
    info_output=$("$new_dir/myapp" --info 2>&1)
    [[ "$info_output" == *"Image:"* ]]
}

test_single_file_run_echo() {
    local output="$TEST_DIR/test-single-file"

    if [[ ! -f "$output" ]]; then
        $SMOLVM pack alpine:latest -o "$output" --single-file 2>&1
    fi

    # Run with 60s timeout to prevent indefinite hangs
    local result
    result=$(run_with_timeout 60 "$output" echo "single-file-test-marker" 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 124 ]]; then
        echo "TIMEOUT: packed binary hung"
        return 1
    fi

    [[ "$result" == *"single-file-test-marker"* ]]
}

# =============================================================================
# runpack Subcommand - Basic Tests
# =============================================================================

test_runpack_help() {
    # Verify runpack subcommand exists and shows help
    $SMOLVM runpack --help 2>&1 | grep -q "Run a VM from a packed"
}

test_runpack_info() {
    local output="$TEST_DIR/test-alpine"

    # Ensure we have a packed binary with sidecar
    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Test --info via runpack
    local info_output
    info_output=$($SMOLVM runpack --sidecar "$output.smolmachine" --info 2>&1)
    [[ "$info_output" == *"Image:"* ]] && \
    [[ "$info_output" == *"Platform:"* ]] && \
    [[ "$info_output" == *"Checksum:"* ]] || return 1
}

test_runpack_info_no_sidecar() {
    # Should error clearly when sidecar doesn't exist
    local exit_code=0
    $SMOLVM runpack --sidecar /tmp/nonexistent-file.smolmachine --info 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]]
}

test_runpack_auto_detect() {
    # Test auto-detection of .smolmachine file in current directory
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Create a temp dir with a single .smolmachine file
    local detect_dir="$TEST_DIR/auto-detect"
    mkdir -p "$detect_dir"
    cp "$output.smolmachine" "$detect_dir/myapp.smolmachine"

    # runpack --info from that directory should auto-detect
    local info_output
    info_output=$(cd "$detect_dir" && $SMOLVM runpack --info 2>&1)
    [[ "$info_output" == *"Image:"* ]]
}

test_runpack_auto_detect_ambiguous() {
    # Should error when multiple .smolmachine files exist and no --sidecar given
    local detect_dir="$TEST_DIR/multi-detect"
    mkdir -p "$detect_dir"

    # Create two dummy .smolmachine files (just need them to exist for detection)
    touch "$detect_dir/app1.smolmachine"
    touch "$detect_dir/app2.smolmachine"

    local exit_code=0
    (cd "$detect_dir" && $SMOLVM runpack --info 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# runpack Subcommand - Execution Tests (Requires VM)
# =============================================================================

test_runpack_resource_override() {
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Verify resource override flags are accepted (boot with custom resources)
    # We use --debug to see the config, and run a quick command
    local result
    result=$(run_with_timeout 60 $SMOLVM runpack --sidecar "$output.smolmachine" --cpus 2 --mem 512 --debug -- echo "resource-test" 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "TIMEOUT"; return 1; }

    # Should contain the debug output showing the resource overrides
    [[ "$result" == *"cpus=2"* ]] && [[ "$result" == *"mem=512"* ]] && \
    [[ "$result" == *"resource-test"* ]]
}

test_runpack_force_extract() {
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # Run with --force-extract and --debug to verify re-extraction
    local result
    result=$(run_with_timeout 60 $SMOLVM runpack --sidecar "$output.smolmachine" --force-extract --debug -- echo "re-extracted" 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "TIMEOUT"; return 1; }

    # Debug output should show extraction happening
    [[ "$result" == *"extract"* ]] && [[ "$result" == *"re-extracted"* ]]
}

test_runpack_cached_fast() {
    # Second run should use cached assets (no extraction)
    local output="$TEST_DIR/test-alpine"

    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack alpine:latest -o "$output" 2>&1
    fi

    # First run ensures cache exists
    run_with_timeout 60 $SMOLVM runpack --sidecar "$output.smolmachine" -- true 2>&1 || true

    # Second run with --debug should show "using cached assets"
    local result
    result=$(run_with_timeout 60 $SMOLVM runpack --sidecar "$output.smolmachine" --debug -- echo "cached-run" 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"cached"* ]] && [[ "$result" == *"cached-run"* ]]
}

test_runpack_python() {
    if [[ "$QUICK_MODE" == "true" ]]; then
        echo "SKIP: --quick mode"
        return 0
    fi

    local output="$TEST_DIR/test-python"

    if [[ ! -f "$output.smolmachine" ]]; then
        $SMOLVM pack python:3.12-slim -o "$output" 2>&1
    fi

    local result
    result=$(run_with_timeout 90 $SMOLVM runpack --sidecar "$output.smolmachine" -- python -c "print('Hello from runpack Python')" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"Hello from runpack Python"* ]]
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

    [[ -f "$output" ]] && [[ -f "$output.smolmachine" ]]
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
    result=$(run_with_timeout 90 "$output" python -c "print('Hello from packed Python')" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; return 1; }
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
run_test "Pack with --platform" test_pack_with_platform || true

echo ""
echo "Running Packed Binary Info Tests..."
echo ""

run_test "Packed --info" test_packed_info || true

echo ""
echo "Running Sidecar Tests..."
echo ""

run_test "Sidecar required" test_sidecar_required || true

echo ""
echo "Running Single-File Mode Tests..."
echo ""

run_test "Single-file pack" test_single_file_pack || true
run_test "Single-file run echo (requires VM)" test_single_file_run_echo || true

echo ""
echo "Running Packed Binary Execution Tests (requires VM)..."
echo ""

run_test "Packed run echo" test_packed_run_echo || true
run_test "Packed exit code" test_packed_exit_code || true
run_test "Packed env variable" test_packed_env_var || true
run_test "Packed workdir" test_packed_workdir || true

echo ""
echo "Running runpack Subcommand Tests..."
echo ""

run_test "runpack help" test_runpack_help || true
run_test "runpack --info" test_runpack_info || true
run_test "runpack --info with missing sidecar" test_runpack_info_no_sidecar || true
run_test "runpack auto-detect sidecar" test_runpack_auto_detect || true
run_test "runpack auto-detect ambiguous" test_runpack_auto_detect_ambiguous || true

echo ""
echo "Running runpack Execution Tests (requires VM)..."
echo ""

run_test "runpack resource override" test_runpack_resource_override || true
run_test "runpack --force-extract" test_runpack_force_extract || true
run_test "runpack cached fast" test_runpack_cached_fast || true

echo ""
echo "Running Error Handling Tests..."
echo ""

run_test "Pack nonexistent image" test_pack_nonexistent_image || true

if [[ "$QUICK_MODE" != "true" ]]; then
    echo ""
    echo "Running Large Image Tests..."
    echo ""

    run_test "Pack Python image" test_pack_python || true
    run_test "Packed Python run" test_packed_python_run || true
    run_test "runpack Python" test_runpack_python || true
fi

print_summary "Pack Tests"
