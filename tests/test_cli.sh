#!/bin/bash
#
# CLI tests for smolvm.
#
# Tests basic CLI functionality like --version, --help, and subcommand structure.
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
    [[ "$output" == *"machine"* ]] && \
    [[ "$output" == *"container"* ]] && \
    [[ "$output" == *"pack"* ]]
}

test_machine_help() {
    local output
    output=$($SMOLVM machine --help 2>&1)
    [[ "$output" == *"run"* ]] && \
    [[ "$output" == *"create"* ]] && \
    [[ "$output" == *"start"* ]] && \
    [[ "$output" == *"stop"* ]] && \
    [[ "$output" == *"exec"* ]] && \
    [[ "$output" == *"images"* ]] && \
    [[ "$output" == *"prune"* ]]
}

test_machine_run_help() {
    local output
    output=$($SMOLVM machine run --help 2>&1)
    [[ "$output" == *"IMAGE"* ]] && \
    [[ "$output" == *"--net"* ]] && \
    [[ "$output" == *"--detach"* ]] && \
    [[ "$output" == *"--oci-platform"* ]]
}

test_no_container_command() {
    # Container subcommand was removed — should not exist
    local exit_code=0
    $SMOLVM container --help 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]]
}

test_pack_help() {
    local output
    output=$($SMOLVM pack create --help 2>&1)
    [[ "$output" == *"--oci-platform"* ]] && \
    [[ "$output" == *"--output"* ]]
}

# =============================================================================
# Removed Commands
# =============================================================================


# =============================================================================
# Machine Aliases
# =============================================================================

test_vm_alias() {
    local output
    output=$($SMOLVM vm --help 2>&1)
    [[ "$output" == *"run"* ]] && \
    [[ "$output" == *"create"* ]]
}

# =============================================================================
# Invalid Commands
# =============================================================================

test_invalid_subcommand() {
    ! $SMOLVM nonexistent-command 2>/dev/null
}

# =============================================================================
# Flag Presence
# =============================================================================

test_machine_create_flags() {
    local output
    output=$($SMOLVM machine create --help 2>&1)
    [[ "$output" == *"--overlay"* ]] && \
    [[ "$output" == *"--storage"* ]] && \
    [[ "$output" == *"--net"* ]] && \
    [[ "$output" == *"--smolfile"* ]]
}

test_machine_run_flags() {
    local output
    output=$($SMOLVM machine run --help 2>&1)
    [[ "$output" == *"--overlay"* ]] && \
    [[ "$output" == *"--volume"* ]] && \
    [[ "$output" == *"--port"* ]] && \
    [[ "$output" == *"--smolfile"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Version command" test_version || true
run_test "Help command" test_help || true
run_test "Machine help" test_machine_help || true
run_test "Machine run help" test_machine_run_help || true
run_test "No container command" test_no_container_command || true
run_test "Pack help" test_pack_help || true
run_test "vm alias works" test_vm_alias || true
run_test "Invalid subcommand fails" test_invalid_subcommand || true
run_test "Machine create flags" test_machine_create_flags || true
run_test "Machine run flags" test_machine_run_flags || true

print_summary "CLI Tests"
