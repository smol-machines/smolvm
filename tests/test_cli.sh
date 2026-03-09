#!/bin/bash
#
# CLI tests for smolvm.
#
# Tests basic CLI functionality like --version and --help.
# Does not require VM environment.
#
# Usage:
#   ./tests/test_cli.sh

source "$(dirname "$0")/common.sh"
init_smolvm

echo ""
echo "=========================================="
echo "  smolvm CLI Tests"
echo "=========================================="
echo ""

# =============================================================================
# Version and Help
# =============================================================================

test_version() {
    local output
    output=$($SMOLVM --version 2>&1)
    [[ "$output" == *"smolvm"* ]]
}

test_help() {
    local output
    output=$($SMOLVM --help 2>&1)
    [[ "$output" == *"sandbox"* ]] && \
    [[ "$output" == *"microvm"* ]] && \
    [[ "$output" == *"container"* ]]
}

test_sandbox_help() {
    local output
    output=$($SMOLVM sandbox --help 2>&1)
    [[ "$output" == *"run"* ]]
}

test_sandbox_run_platform_flag() {
    # Verify --oci-platform flag exists in sandbox run help
    local output
    output=$($SMOLVM sandbox run --help 2>&1)
    [[ "$output" == *"--oci-platform"* ]] && \
    [[ "$output" == *"linux/arm64"* ]] && \
    [[ "$output" == *"linux/amd64"* ]]
}

test_pack_platform_flag() {
    # Verify --oci-platform flag exists in pack help
    local output
    output=$($SMOLVM pack create --help 2>&1)
    [[ "$output" == *"--oci-platform"* ]] && \
    [[ "$output" == *"linux/arm64"* ]] && \
    [[ "$output" == *"linux/amd64"* ]]
}

test_microvm_help() {
    local output
    output=$($SMOLVM microvm --help 2>&1)
    [[ "$output" == *"start"* ]] && \
    [[ "$output" == *"stop"* ]] && \
    [[ "$output" == *"status"* ]]
}

test_container_help() {
    local output
    output=$($SMOLVM container --help 2>&1)
    [[ "$output" == *"create"* ]] && \
    [[ "$output" == *"start"* ]] && \
    [[ "$output" == *"stop"* ]] && \
    [[ "$output" == *"list"* ]] && \
    [[ "$output" == *"remove"* ]]
}

# =============================================================================
# Invalid Commands
# =============================================================================

test_invalid_subcommand() {
    # Should fail for invalid subcommand
    ! $SMOLVM nonexistent-command 2>/dev/null
}

test_sandbox_run_missing_image() {
    # Should fail when image is not provided
    ! $SMOLVM sandbox run 2>/dev/null
}

# =============================================================================
# Disk Size Flags
# =============================================================================

test_microvm_create_overlay_flag() {
    # Verify --overlay flag exists in microvm create help
    local output
    output=$($SMOLVM microvm create --help 2>&1)
    [[ "$output" == *"--overlay"* ]] && \
    [[ "$output" == *"GiB"* ]]
}

test_microvm_create_storage_flag() {
    # Verify --storage flag exists in microvm create help
    local output
    output=$($SMOLVM microvm create --help 2>&1)
    [[ "$output" == *"--storage"* ]] && \
    [[ "$output" == *"GiB"* ]]
}

test_sandbox_create_overlay_flag() {
    # Verify --overlay flag exists in sandbox create help
    local output
    output=$($SMOLVM sandbox create --help 2>&1)
    [[ "$output" == *"--overlay"* ]] && \
    [[ "$output" == *"GiB"* ]]
}

test_sandbox_run_overlay_flag() {
    # Verify --overlay flag exists in sandbox run help
    local output
    output=$($SMOLVM sandbox run --help 2>&1)
    [[ "$output" == *"--overlay"* ]] && \
    [[ "$output" == *"GiB"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Version command" test_version || true
run_test "Help command" test_help || true
run_test "Sandbox help" test_sandbox_help || true
run_test "Sandbox run --oci-platform flag" test_sandbox_run_platform_flag || true
run_test "Pack --oci-platform flag" test_pack_platform_flag || true
run_test "Microvm help" test_microvm_help || true
run_test "Container help" test_container_help || true
run_test "Invalid subcommand fails" test_invalid_subcommand || true
run_test "Sandbox run without image fails" test_sandbox_run_missing_image || true
run_test "Microvm create --overlay flag" test_microvm_create_overlay_flag || true
run_test "Microvm create --storage flag" test_microvm_create_storage_flag || true
run_test "Sandbox create --overlay flag" test_sandbox_create_overlay_flag || true
run_test "Sandbox run --overlay flag" test_sandbox_run_overlay_flag || true

print_summary "CLI Tests"
