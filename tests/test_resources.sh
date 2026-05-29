#!/bin/bash
#
# Resource Validation and Naming Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_resources.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Resource Validation and Naming Tests"
echo "=========================================="
echo ""

test_resource_cpus_zero_rejected() {
    local exit_code=0
    $SMOLVM machine run --cpus 0 -- echo hello 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || return 1
}

test_resource_mem_zero_rejected() {
    local exit_code=0
    $SMOLVM machine run --mem 0 -- echo hello 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || return 1
}

test_resource_mem_below_minimum_rejected() {
    local exit_code=0
    local output
    output=$($SMOLVM machine run --mem 1 -- echo hello 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || return 1
    [[ "$output" == *"at least"* ]] || return 1
}

test_name_length_44_chars_accepted() {
    local name="sandbox-7f3e2d1c-9a8b-4e5f-b123-456789abcdef"
    [[ ${#name} -eq 44 ]] || { echo "test bug: expected 44 chars, got ${#name}"; return 1; }
    $SMOLVM machine delete "$name" -f 2>/dev/null || true

    local output exit_code=0
    output=$($SMOLVM machine create "$name" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "expected 44-char name to succeed, got error: $output"
        return 1
    fi
    $SMOLVM machine delete "$name" -f 2>/dev/null || true
}

test_name_length_75_chars_accepted_via_hash_path() {
    local name
    name=$(printf 'a%.0s' {1..75})
    [[ ${#name} -eq 75 ]] || return 1
    $SMOLVM machine delete "$name" -f 2>/dev/null || true

    local output exit_code=0
    output=$($SMOLVM machine create "$name" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "expected 75-char name to succeed (hash path keeps socket bounded), got: $output"
        return 1
    fi
    $SMOLVM machine delete "$name" -f 2>/dev/null || true
}

test_name_length_sanity_cap_rejects_absurd_names() {
    local name
    name=$(printf 'a%.0s' {1..200})
    [[ ${#name} -eq 200 ]] || return 1

    local output exit_code=0
    output=$($SMOLVM machine create "$name" 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "expected 200-char name to be rejected"; return 1; }
    [[ "$output" == *"too long"* ]] || {
        echo "expected length-cap error, got: $output"
        return 1
    }
}

test_start_nonexistent_name_rejected() {
    local exit_code=0
    $SMOLVM machine start --name nonexistent-vm-regression-test 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "expected error for nonexistent VM"; return 1; }

    # Verify no "default" VM was created
    local list
    list=$($SMOLVM machine ls --json 2>&1)
    [[ "$list" != *"nonexistent-vm-regression-test"* ]] || { echo "VM should not exist"; return 1; }
}

test_auto_generated_names() {
    # Auto-generate: create with no name, verify format + appears in list
    local result1 result2
    result1=$($SMOLVM machine create 2>&1) || return 1
    result2=$($SMOLVM machine create 2>&1) || return 1

    local name1 name2
    name1=$(echo "$result1" | grep "Created machine:" | grep -oE "vm-[a-f0-9]{8}" | head -1)
    name2=$(echo "$result2" | grep "Created machine:" | grep -oE "vm-[a-f0-9]{8}" | head -1)

    # Both should produce valid names
    [[ -n "$name1" ]] && [[ -n "$name2" ]] || { echo "No auto name found"; return 1; }

    # Names should differ
    [[ "$name1" != "$name2" ]] || { echo "Names should be unique: $name1"; return 1; }

    # Both should appear in list (use --json for full names, avoids truncation)
    local list_result
    list_result=$($SMOLVM machine ls --json 2>&1)
    [[ "$list_result" == *"$name1"* ]] && [[ "$list_result" == *"$name2"* ]] || {
        echo "Auto-named machines not in list"
        $SMOLVM machine delete "$name1" -f 2>/dev/null
        $SMOLVM machine delete "$name2" -f 2>/dev/null
        return 1
    }

    # Explicit name still works
    local explicit="explicit-test-$$"
    $SMOLVM machine create "$explicit" 2>&1 || { echo "Explicit name failed"; return 1; }
    list_result=$($SMOLVM machine ls --json 2>&1)
    [[ "$list_result" == *"$explicit"* ]] || { echo "Explicit name not in list"; return 1; }

    # Cleanup
    $SMOLVM machine delete "$name1" -f 2>/dev/null
    $SMOLVM machine delete "$name2" -f 2>/dev/null
    $SMOLVM machine delete "$explicit" -f 2>/dev/null
}


test_create_rejects_zero_valued_disks() {
    # `machine create` must reject zero-sized storage/overlay up front and
    # NOT persist a machine — otherwise the failure only surfaces later at
    # `machine start`, leaving an unstartable machine in the list.
    local name="zero-disk-test-$$"
    $SMOLVM machine delete "$name" -f 2>/dev/null || true

    local exit_code=0
    $SMOLVM machine create "$name" --storage 0 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "--storage 0 should be rejected at create"
        $SMOLVM machine delete "$name" -f 2>/dev/null
        return 1
    }

    exit_code=0
    $SMOLVM machine create "$name" --overlay 0 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "--overlay 0 should be rejected at create"
        $SMOLVM machine delete "$name" -f 2>/dev/null
        return 1
    }

    # Neither rejected create may have persisted the machine.
    local list
    list=$($SMOLVM machine ls --json 2>&1)
    [[ "$list" != *"$name"* ]] || {
        echo "a rejected create persisted the machine anyway"
        $SMOLVM machine delete "$name" -f 2>/dev/null
        return 1
    }
}

test_exec_nonexistent_machine_reports_not_found() {
    # exec/cp on a machine that does not exist must say "not found", not
    # "is not running" — the latter wrongly tells the user to run `start`.
    local name="missing-machine-test-$$"
    local output exit_code=0

    output=$($SMOLVM machine exec --name "$name" -- echo hi 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "exec on a nonexistent machine should fail"; return 1; }
    [[ "$output" == *"not found"* ]] || { echo "expected 'not found', got: $output"; return 1; }
    [[ "$output" != *"is not running"* ]] || {
        echo "must not report 'is not running' for a machine that does not exist"
        return 1
    }

    exit_code=0
    output=$($SMOLVM machine cp /etc/hostname "$name":/tmp/x 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "cp to a nonexistent machine should fail"; return 1; }
    [[ "$output" == *"not found"* ]] || { echo "cp: expected 'not found', got: $output"; return 1; }
}

test_status_json_output() {
    # `machine status` supports `--json`, mirroring `machine list --json`.
    local name="status-json-test-$$"
    $SMOLVM machine delete "$name" -f 2>/dev/null || true
    $SMOLVM machine create "$name" 2>&1 || { echo "setup: create failed"; return 1; }

    local output exit_code=0
    output=$($SMOLVM machine status --name "$name" --json 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "status --json should succeed, got: $output"
        $SMOLVM machine delete "$name" -f 2>/dev/null
        return 1
    fi
    [[ "$output" == "{"* && "$output" == *"\"name\""* && "$output" == *"$name"* ]] || {
        echo "status --json did not return the expected JSON object: $output"
        $SMOLVM machine delete "$name" -f 2>/dev/null
        return 1
    }
    $SMOLVM machine delete "$name" -f 2>/dev/null

    # `--json` on a machine that does not exist must error.
    exit_code=0
    $SMOLVM machine status --name "missing-$$" --json 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "status --json on a nonexistent machine should fail"; return 1; }
}

run_test "Resource: --cpus 0 rejected" test_resource_cpus_zero_rejected || true
run_test "Resource: --mem 0 rejected" test_resource_mem_zero_rejected || true
run_test "Name length: 44-char UUID name accepted (was rejected by old 40-char cap)" test_name_length_44_chars_accepted || true
run_test "Name length: 75-char name accepted via hash-derived socket path" test_name_length_75_chars_accepted_via_hash_path || true
run_test "Name length: absurd names rejected by sanity cap" test_name_length_sanity_cap_rejects_absurd_names || true
run_test "Resource: --mem below minimum rejected" test_resource_mem_below_minimum_rejected || true
run_test "Start --name nonexistent rejected" test_start_nonexistent_name_rejected || true
run_test "Auto-generated names" test_auto_generated_names || true
run_test "Create: zero-valued storage/overlay rejected, not persisted" test_create_rejects_zero_valued_disks || true
run_test "Exec/cp: nonexistent machine reports 'not found'" test_exec_nonexistent_machine_reports_not_found || true
run_test "Status: --json outputs a JSON object" test_status_json_output || true

print_summary "Resource Tests"
