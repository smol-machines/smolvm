#!/bin/bash
#
# Reliability and Concurrency Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_reliability.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Reliability and Concurrency Tests"
echo "=========================================="
echo ""

test_concurrent_machine_start() {
    local vm_a="conc-start-a-$$"
    local vm_b="conc-start-b-$$"

    $SMOLVM machine create --name "$vm_a" --cpus 1 --mem 256 2>&1 >/dev/null || return 1
    $SMOLVM machine create --name "$vm_b" --cpus 1 --mem 256 2>&1 >/dev/null || return 1

    # Start both simultaneously — previously the second would fail with DB lock error
    $SMOLVM machine start --name "$vm_a" 2>&1 >/dev/null &
    local pid_a=$!
    $SMOLVM machine start --name "$vm_b" 2>&1 >/dev/null &
    local pid_b=$!
    wait $pid_a; local exit_a=$?
    wait $pid_b; local exit_b=$?

    # Both should succeed
    [[ $exit_a -eq 0 ]] || { echo "FAIL: start a failed (exit $exit_a)"; }
    [[ $exit_b -eq 0 ]] || { echo "FAIL: start b failed (exit $exit_b)"; }

    # Both should be running
    local status_a status_b
    status_a=$($SMOLVM machine status --name "$vm_a" 2>&1)
    status_b=$($SMOLVM machine status --name "$vm_b" 2>&1)

    $SMOLVM machine stop --name "$vm_a" 2>/dev/null || true
    $SMOLVM machine stop --name "$vm_b" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_a" -f 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_b" -f 2>/dev/null || true

    [[ "$status_a" == *"running"* ]] && [[ "$status_b" == *"running"* ]]
}

test_machine_ls_does_not_kill_vm() {
    skip_if_slow && return 0
    # Regression test: state_probe's probe_agent() used to create a temporary
    # AgentManager without detaching it. When that manager was dropped, its
    # Drop impl sent a Shutdown command to the agent, killing the VM.
    # Every `machine ls` (and any state-checking command) triggered this.
    # The old bug killed VMs within 10-20 seconds; we verify survival for 60s.
    ensure_machine_running

    # Repeatedly call `machine ls` — each call probes the agent via
    # resolve_state → probe_agent. Before the fix, the first call
    # would kill the VM.
    for i in 1 2 3 4 5 6; do
        local output
        output=$($SMOLVM machine ls 2>&1)
        [[ "$output" == *"running"* ]] || { echo "VM died after ls call #$i: $output"; return 1; }
        sleep 10
    done

    # Exec must still work after 6 ls calls over 60 seconds
    local result
    result=$($SMOLVM machine exec -- echo "survived-ls-probe" 2>&1)
    [[ "$result" == *"survived-ls-probe"* ]] || { echo "exec failed after ls probes: $result"; return 1; }
}

test_named_vm_survives_ls() {
    skip_if_slow && return 0
    # Same regression test but with a named VM — the customer's exact scenario:
    # machine create --name X --from .smolmachine → machine start → machine ls shows stopped.
    # Verify over 60 seconds with interleaved ls + exec.
    local name="ls-probe-test"
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
    $SMOLVM machine create --name "$name" 2>&1 || return 1
    $SMOLVM machine start --name "$name" 2>&1 || return 1

    # Wait for agent to be fully ready
    sleep 2

    for i in 1 2 3 4 5 6; do
        local state
        state=$($SMOLVM machine ls 2>&1 | grep "$name" | awk '{print $2}')
        [[ "$state" == "running" ]] || { echo "VM '$name' died after ls #$i (state: $state)"; $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1; }
        sleep 10
    done

    # Exec must work after 60 seconds of ls probing
    local result
    result=$($SMOLVM machine exec --name "$name" -- echo "alive" 2>&1)
    [[ "$result" == *"alive"* ]] || { echo "exec failed: $result"; $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1; }

    $SMOLVM machine stop --name "$name" 2>&1 || true
    $SMOLVM machine delete --name "$name" -f 2>&1 || true
}

test_state_probe_tolerates_busy_agent() {
    ensure_machine_running

    # Fire a 1-second sleep exec in the background. The agent will be busy
    # with `sh -c 'sleep 1'` → crun startup → child wait.
    $SMOLVM machine exec -- sh -c 'sleep 1' &
    local exec_pid=$!

    # Give the exec time to reach the agent's busy-with-request state.
    sleep 0.2

    # While the exec is still running, `machine ls` must show "running".
    # With the old 100ms ping, it would show "unreachable".
    local state
    state=$($SMOLVM machine ls 2>&1 | grep "^default " | awk '{print $2}')

    # Wait for the background exec to finish before asserting, so we don't
    # leave a zombie if the test fails.
    wait "$exec_pid" 2>/dev/null

    [[ "$state" == "running" ]] || {
        echo "expected 'running' during busy agent, got '$state' — state probe regressed?"
        return 1
    }
}

test_concurrent_exec_does_not_flip_unreachable() {
    ensure_machine_running

    # Hold a long-running exec open in the background.
    $SMOLVM machine exec -- sh -c 'sleep 5' &
    local hold_pid=$!

    # Give it time to be accepted by the agent and block the old single thread.
    sleep 1

    # A second exec must succeed while the first is still running.
    local second_output
    second_output=$($SMOLVM machine exec -- echo concurrent_ok 2>&1)
    local second_exit=$?

    # Also verify state did not flip to unreachable.
    local state
    state=$($SMOLVM machine ls 2>&1 | grep "^default " | awk '{print $2}')

    wait "$hold_pid" 2>/dev/null

    if [[ $second_exit -ne 0 ]]; then
        echo "FAIL: second concurrent exec failed (exit $second_exit): $second_output"
        return 1
    fi
    if [[ "$second_output" != *"concurrent_ok"* ]]; then
        echo "FAIL: second exec output unexpected: $second_output"
        return 1
    fi
    if [[ "$state" != "running" ]]; then
        echo "FAIL: VM flipped to '$state' during concurrent exec (expected 'running')"
        return 1
    fi
}


run_test "Concurrent machine starts" test_concurrent_machine_start || true
run_test "State probe tolerates busy agent (no false unreachable)" test_state_probe_tolerates_busy_agent || true
run_test "Concurrent exec does not flip VM to unreachable" test_concurrent_exec_does_not_flip_unreachable || true
run_test "Listing: machine ls does not kill VM" test_machine_ls_does_not_kill_vm || true
run_test "Listing: named VM survives repeated ls" test_named_vm_survives_ls || true

print_summary "Reliability Tests"
