#!/bin/bash
#
# Container tests for smolvm.
#
# Tests the `smolvm container` command functionality.
# Requires VM environment.
#
# Usage:
#   ./tests/test_container.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Cleanup on exit
trap cleanup_microvm EXIT

echo ""
echo "=========================================="
echo "  smolvm Container Tests"
echo "=========================================="
echo ""

# =============================================================================
# Create
# =============================================================================

test_container_create() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        echo "Failed to extract container ID from: $output"
        return 1
    fi

    # Cleanup
    cleanup_container "$container_id"
    return 0
}

test_container_id_format() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 10 2>&1)
    container_id=$(extract_container_id "$output")

    # Cleanup first
    cleanup_container "$container_id"

    # Verify format: smolvm-{12 or 16 hex chars}
    # Old format: 7 (smolvm-) + 12 = 19
    # New format: 7 (smolvm-) + 16 = 23
    local id_len=${#container_id}
    if [[ $id_len -ne 19 ]] && [[ $id_len -ne 23 ]]; then
        echo "Container ID has wrong length: $id_len (expected 19 or 23)"
        return 1
    fi

    # Verify pattern
    if [[ ! "$container_id" =~ ^smolvm-[a-f0-9]{12,16}$ ]]; then
        echo "Container ID doesn't match expected pattern: $container_id"
        return 1
    fi

    return 0
}

# =============================================================================
# List
# =============================================================================

test_container_list() {
    ensure_microvm_running

    local output container_id list_output
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    list_output=$($SMOLVM container ls default 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    # Should contain the container
    [[ "$list_output" == *"$container_id"* ]] || [[ "$list_output" == *"${container_id:0:12}"* ]]
}

test_container_list_all() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    # Stop it
    $SMOLVM container stop default "$container_id" 2>&1

    # List with -a should show stopped containers
    local list_output
    list_output=$($SMOLVM container ls default -a 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$list_output" == *"stopped"* ]]
}

# =============================================================================
# Exec
# =============================================================================

test_container_exec() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    local exec_output
    exec_output=$($SMOLVM container exec default "$container_id" -- echo "exec-test-marker" 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$exec_output" == *"exec-test-marker"* ]]
}

test_container_exec_env() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    local exec_output
    exec_output=$($SMOLVM container exec default "$container_id" -e MY_VAR=test_value -- sh -c 'echo $MY_VAR' 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$exec_output" == *"test_value"* ]]
}

# =============================================================================
# Stop/Start (Restart)
# =============================================================================

test_container_stop() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    # Stop it
    $SMOLVM container stop default "$container_id" 2>&1

    # Verify it's stopped
    local list_output
    list_output=$($SMOLVM container ls default -a 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$list_output" == *"stopped"* ]]
}

test_container_restart() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    # Stop it
    $SMOLVM container stop default "$container_id" 2>&1

    # Verify stopped
    local list_output
    list_output=$($SMOLVM container ls default -a 2>&1)
    if [[ "$list_output" != *"stopped"* ]]; then
        cleanup_container "$container_id"
        return 1
    fi

    # Start it again (restart)
    $SMOLVM container start default "$container_id" 2>&1

    # Verify running
    list_output=$($SMOLVM container ls default 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$list_output" == *"running"* ]]
}

# =============================================================================
# Remove
# =============================================================================

test_container_remove() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    # Remove it (force)
    $SMOLVM container rm default "$container_id" -f 2>&1

    # Verify it's gone
    local list_output
    list_output=$($SMOLVM container ls default -a 2>&1)

    [[ "$list_output" != *"$container_id"* ]]
}

# =============================================================================
# Prefix Matching
# =============================================================================

test_container_prefix_matching() {
    ensure_microvm_running

    local output container_id
    output=$($SMOLVM container create default alpine:latest -- sleep 300 2>&1)
    container_id=$(extract_container_id "$output")

    if [[ -z "$container_id" ]]; then
        return 1
    fi

    # Use prefix for exec (first 15 chars should be unique enough)
    local prefix="${container_id:0:15}"
    local exec_output
    exec_output=$($SMOLVM container exec default "$prefix" -- echo "prefix-test" 2>&1)

    # Cleanup
    cleanup_container "$container_id"

    [[ "$exec_output" == *"prefix-test"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Container create" test_container_create || true
run_test "Container ID format" test_container_id_format || true
run_test "Container list" test_container_list || true
run_test "Container list all (-a)" test_container_list_all || true
run_test "Container exec" test_container_exec || true
run_test "Container exec with env" test_container_exec_env || true
run_test "Container stop" test_container_stop || true
run_test "Container restart" test_container_restart || true
run_test "Container remove" test_container_remove || true
run_test "Container prefix matching" test_container_prefix_matching || true

print_summary "Container Tests"
