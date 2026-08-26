#!/usr/bin/env bash
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
# Machine Options After `--`
# =============================================================================

test_create_warns_on_flags_after_separator() {
    local vm_name="flags-after-$$"
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Machine options written after `--` are workload arguments: they must be
    # named on stderr, and the machine must be created with the defaults rather
    # than silently reconfigured.
    local output
    output=$($SMOLVM machine create --name "$vm_name" -- \
        /bin/sh -c "sleep infinity" --mem 32768 --storage 120 --net 2>&1) || {
        echo "machine create failed: $output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    local fail=0
    [[ "$output" == *"note:"* ]] || { echo "no warning note in: $output"; fail=1; }
    [[ "$output" == *"--mem"* ]] || { echo "note does not name --mem: $output"; fail=1; }
    [[ "$output" == *"--storage"* ]] || { echo "note does not name --storage: $output"; fail=1; }
    [[ "$output" == *"--net"* ]] || { echo "note does not name --net: $output"; fail=1; }
    [[ "$output" == *"came after \`--\`"* ]] || {
        echo "note lacks the 'came after --' hint: $output"; fail=1
    }

    # None of the stray options configured the machine: memory stays at the
    # default, network stays off, storage stays unset, and the flags remain in
    # the workload command.
    local json mem network storage cmd
    json=$($SMOLVM machine ls --json 2>&1)
    mem=$(echo "$json" | jq -r --arg name "$vm_name" \
        '.[] | select(.name == $name) | .memory_mib')
    network=$(echo "$json" | jq -r --arg name "$vm_name" \
        '.[] | select(.name == $name) | .network')
    storage=$(echo "$json" | jq -r --arg name "$vm_name" \
        '.[] | select(.name == $name) | .storage_gb')
    cmd=$(echo "$json" | jq -r --arg name "$vm_name" \
        '.[] | select(.name == $name) | .cmd | join(" ")')
    [[ "$mem" == "8192" ]] || { echo "expected default 8192 MiB memory, got: $mem"; fail=1; }
    [[ "$network" == "false" ]] || { echo "expected network disabled, got: $network"; fail=1; }
    [[ "$storage" == "null" ]] || { echo "expected storage unset, got: $storage"; fail=1; }
    [[ "$cmd" == *"--mem"* && "$cmd" == *"--storage"* && "$cmd" == *"--net"* ]] || {
        echo "expected flags to stay in the workload command, got: $cmd"; fail=1
    }

    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    return $fail
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
run_test "Machine create warns on flags after --" test_create_warns_on_flags_after_separator || true

print_summary "CLI Tests"
