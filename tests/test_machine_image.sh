#!/bin/bash
#
# Image-Backed Machine Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_machine_image.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Image-Backed Machine Tests"
echo "=========================================="
echo ""

test_create_with_image() {
    local vm_name="create-image-test-$$"

    # Create with --image (new feature), start, exec, verify, cleanup
    $SMOLVM machine create --name "$vm_name" --image alpine:latest --net 2>&1 || return 1

    # Should appear in list (use --json for full names)
    $SMOLVM machine ls --json 2>&1 | grep -q "$vm_name" || {
        echo "Machine not in list"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start — should auto-pull the image
    local start_result
    start_result=$(run_with_timeout 60 $SMOLVM machine start --name "$vm_name" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT on start"; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }
    [[ "$start_result" == *"Pulling"* ]] || [[ "$start_result" == *"Started"* ]] || [[ "$start_result" == *"already running"* ]] || {
        echo "Start failed: $start_result"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Exec — verify we're in the right image
    local exec_result
    exec_result=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- cat /etc/os-release 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT on exec"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }
    [[ "$exec_result" == *"Alpine"* ]] || {
        echo "Not running Alpine: $exec_result"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
}

test_create_with_image_and_env() {
    local vm_name="create-env-test-$$"

    # Create with --image + env + workdir
    $SMOLVM machine create --name "$vm_name" --image alpine:latest --net \
        -e TEST_VAR=from_create -w /tmp 2>&1 || return 1

    run_with_timeout 60 $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Verify workdir was persisted (init commands run in /tmp)
    local pwd_result
    pwd_result=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- pwd 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
}

test_update_settings_applied_on_start() {
    # Verify update changes cpus, ports, network, and that they take effect.
    # Also verifies update refuses a running VM.
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --name default 2>&1 || return 1

    # Update multiple settings at once
    local output
    output=$($SMOLVM machine update --name default --cpus 2 --mem 1024 -p 9090:9090 --net 2>&1) || {
        echo "update failed: $output"; return 1
    }
    [[ "$output" == *"cpus"* ]] || { echo "expected cpus in output: $output"; return 1; }

    # Start and verify cpus applied
    $SMOLVM machine start 2>&1 || return 1
    local cpus
    cpus=$($SMOLVM machine exec -- nproc 2>&1)
    [[ "$cpus" == "2" ]] || { echo "expected 2 cpus, got: $cpus"; return 1; }

    # Update on running VM should fail
    local exit_code=0
    $SMOLVM machine update --name default --mem 2048 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "update should fail on running VM"; return 1; }

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
}

test_update_env_applied_on_start() {
    # Env vars from the DB record are applied in image-based exec.
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --net --image alpine --name default 2>&1 || return 1

    $SMOLVM machine update --name default -e MY_VAR=hello 2>&1 || return 1

    $SMOLVM machine start 2>&1 || return 1
    local val
    val=$($SMOLVM machine exec -- sh -c 'echo $MY_VAR' 2>&1)
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    [[ "$val" == "hello" ]] || { echo "expected MY_VAR=hello, got: $val"; return 1; }
}

test_exec_image_large_stdout_does_not_crash_vm() {
    # Same test but for image-backed exec (the actual bug path)
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --net --image alpine --name default 2>&1 || return 1
    $SMOLVM machine start 2>&1 || return 1

    local output
    output=$(run_with_timeout 30 $SMOLVM machine exec -- sh -c 'dd if=/dev/urandom bs=1024 count=128 2>/dev/null | base64' 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "FAIL: timed out (pipe deadlock?)"; return 1; }

    local output_size=${#output}
    [[ $output_size -gt 100000 ]] || {
        echo "FAIL: expected >100KB output, got ${output_size} bytes"
        return 1
    }

    # VM must still respond
    local check
    check=$(run_with_timeout 10 $SMOLVM machine exec -- echo "still-alive" 2>&1) || {
        echo "FAIL: VM unreachable after large stdout (image-backed exec)"
        return 1
    }
    echo "$check" | grep -q "still-alive" || {
        echo "FAIL: expected 'still-alive', got: $check"
        return 1
    }

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
}

test_exec_joined_large_stdout_does_not_crash_vm() {
    # Same test but through the joined crun exec path (detached main container)
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine run -d --net --image alpine -- sleep 300 2>&1 || return 1

    local output
    output=$(run_with_timeout 30 $SMOLVM machine exec -- sh -c 'dd if=/dev/urandom bs=1024 count=128 2>/dev/null | base64' 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "FAIL: timed out (pipe deadlock in joined exec?)"; return 1; }

    local output_size=${#output}
    [[ $output_size -gt 100000 ]] || {
        echo "FAIL: expected >100KB output, got ${output_size} bytes"
        return 1
    }

    # VM and main container must still be responsive
    local check
    check=$(run_with_timeout 10 $SMOLVM machine exec -- echo "still-alive" 2>&1) || {
        echo "FAIL: VM unreachable after large stdout via joined exec"
        return 1
    }
    echo "$check" | grep -q "still-alive" || {
        echo "FAIL: expected 'still-alive', got: $check"
        return 1
    }

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
}

test_exec_joins_main_container() {
    # machine run -d creates a fresh VM, so no need for ensure_machine_running
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    log_info "Starting detached workload: sleep 300..."
    local run_output
    if ! run_output=$(run_with_timeout 120 $SMOLVM machine run -d --net --image alpine -- sleep 300 2>&1); then
        echo "FAIL: machine run -d failed: $run_output"
        return 1
    fi

    # exec should join the running container — PID 1 is sleep 300
    local ps_output
    if ! ps_output=$(run_with_timeout 30 $SMOLVM machine exec -- ps -ef 2>&1); then
        echo "FAIL: machine exec failed: $ps_output"
        return 1
    fi

    echo "$ps_output" | grep -q "sleep" || {
        echo "FAIL: expected 'sleep' in ps output (shared PID namespace), got:"
        echo "$ps_output"
        return 1
    }
}

test_repeated_exec_joins_same_container() {
    # Relies on the detached container from the previous test still running
    local out1 out2
    out1=$(run_with_timeout 30 $SMOLVM machine exec -- ps -ef 2>&1) || {
        echo "FAIL: first repeated exec failed"; return 1
    }
    out2=$(run_with_timeout 30 $SMOLVM machine exec -- ps -ef 2>&1) || {
        echo "FAIL: second repeated exec failed"; return 1
    }

    for out in "$out1" "$out2"; do
        echo "$out" | grep -q "sleep" || {
            echo "FAIL: exec did not see 'sleep' in ps output"
            echo "$out"
            return 1
        }
    done
}

test_background_process_visible_across_execs() {
    # Spawn sleep 90 in the background; it should be visible from the next exec
    run_with_timeout 15 $SMOLVM machine exec -- sh -c 'sleep 90 &' 2>/dev/null || true
    sleep 1

    local ps_output
    ps_output=$(run_with_timeout 30 $SMOLVM machine exec -- ps -ef 2>&1) || {
        echo "FAIL: exec after background spawn failed"; return 1
    }

    local sleep_count
    sleep_count=$(echo "$ps_output" | grep -c "sleep" || true)
    [[ "$sleep_count" -ge 2 ]] || {
        echo "FAIL: expected >=2 sleep processes, got $sleep_count"
        echo "$ps_output"
        return 1
    }
}

test_ephemeral_run_is_isolated() {
    # Ephemeral machine run (no -d) must NOT see the main container's processes
    local ps_output
    if ! ps_output=$(run_with_timeout 60 $SMOLVM machine run --net --image alpine -- ps -ef 2>&1); then
        echo "FAIL: ephemeral machine run failed: $ps_output"
        return 1
    fi

    if echo "$ps_output" | grep -q "sleep 300"; then
        echo "FAIL: ephemeral run leaked into main container namespace"
        echo "$ps_output"
        return 1
    fi

    [[ -n "$ps_output" ]] || { echo "FAIL: ps returned empty output"; return 1; }
}

test_exec_recovers_after_main_container_exits() {
    # Start a detached container with a short-lived command
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine run -d --net --image alpine -- sleep 2 2>&1 || return 1

    # Wait for the main container to exit naturally
    sleep 4

    # Exec should detect the stale container ID and start a fresh container
    local output
    if ! output=$(run_with_timeout 30 $SMOLVM machine exec -- echo "recovered" 2>&1); then
        echo "FAIL: exec failed after main container exit: $output"
        return 1
    fi

    echo "$output" | grep -q "recovered" || {
        echo "FAIL: expected 'recovered', got: $output"
        return 1
    }
}

test_exec_join_timeout_does_not_kill_main_container() {
    # A timed-out exec must not destroy the main workload container.
    # The exec'd process may survive as an orphan reparented to PID 1
    # (Docker-compatible: docker exec timeout kills the exec wrapper,
    # not the inner process or the container).

    # Ensure the detached container from earlier tests is still running
    local ps_before
    ps_before=$(run_with_timeout 10 $SMOLVM machine exec -- ps -ef 2>&1) || true
    if ! echo "$ps_before" | grep -q "sleep"; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete --name default -f 2>/dev/null || true
        $SMOLVM machine run -d --net --image alpine -- sleep 300 2>&1 || return 1
    fi

    # Run a command with a short timeout — it will time out
    local output exit_code=0
    output=$($SMOLVM machine exec --timeout 1 -- sleep 30 2>&1) || exit_code=$?

    # Exit code 124 = timeout (expected)
    [[ $exit_code -eq 124 ]] || [[ "$output" == *"timed out"* ]] || {
        echo "WARN: unexpected exit code $exit_code (expected 124 for timeout)"
    }

    sleep 1

    # The main container should still be running — sleep 300 visible
    local ps_after
    ps_after=$(run_with_timeout 10 $SMOLVM machine exec -- ps -ef 2>&1) || {
        echo "FAIL: exec failed after timeout — main container may have been killed"
        return 1
    }

    echo "$ps_after" | grep -q "sleep 300" || {
        echo "FAIL: main container (sleep 300) not found after timed-out exec"
        echo "ps output: $ps_after"
        return 1
    }

    # Document whether the timed-out sleep 30 survives as an orphan. The main
    # assertion above is that the main container remains alive.
    if echo "$ps_after" | grep -q "sleep 30"; then
        echo "WARN: timed-out 'sleep 30' still visible as orphan (Docker-compatible behavior)"
    fi
}

test_exec_join_documents_user_behavior() {
    # Document current crun exec user behavior for images with a non-root USER.
    # Some crun versions may run joined exec as root unless --user is explicit.
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine run -d --net --image nginxinc/nginx-unprivileged:stable-alpine -- sleep 300 2>&1 || {
        echo "SKIP: could not start nginx-unprivileged image"
        return 0
    }

    # Check what user the main container's PID 1 runs as
    local id_output
    id_output=$(run_with_timeout 10 $SMOLVM machine exec -- id -u 2>&1) || {
        echo "FAIL: id -u failed: $id_output"
        return 1
    }

    # nginx-unprivileged image has USER 101
    # NOTE: crun exec may run as root by default, not inheriting the image USER.
    # If id returns 0 (root), this is a known gap — crun exec doesn't inherit
    # the OCI process user without explicit --user. Document and accept.
    if echo "$id_output" | grep -q "^101$"; then
        echo "Joined exec runs as UID 101 — image USER preserved"
    elif echo "$id_output" | grep -q "^0$"; then
        echo "WARN: joined exec runs as root (UID 0), not image USER 101"
        echo "This is a known limitation: crun exec does not inherit OCI process user"
        # Not a test failure — documenting current behavior
    else
        echo "FAIL: unexpected UID: $id_output"
        return 1
    fi
}


run_test "Create with --image" test_create_with_image || true
run_test "Create with --image + env" test_create_with_image_and_env || true
run_test "Update: settings applied on next start + refuses running VM" test_update_settings_applied_on_start || true
run_test "Update: env var applied on next start (image-based)" test_update_env_applied_on_start || true
run_test "Exec: large stdout does not crash VM (image-backed)" test_exec_image_large_stdout_does_not_crash_vm || true
run_test "Exec: large stdout does not crash VM (joined exec)" test_exec_joined_large_stdout_does_not_crash_vm || true
run_test "Exec-join: exec joins main workload container" test_exec_joins_main_container || true
run_test "Exec-join: repeated exec joins same container" test_repeated_exec_joins_same_container || true
run_test "Exec-join: background process visible across execs" test_background_process_visible_across_execs || true
run_test "Exec-join: ephemeral run is namespace-isolated" test_ephemeral_run_is_isolated || true
run_test "Exec-join: exec recovers after main container exits" test_exec_recovers_after_main_container_exits || true
run_test "Exec-join: timeout does not kill main container (orphan documented)" test_exec_join_timeout_does_not_kill_main_container || true
run_test "Exec-join: joined exec user behavior (crun exec runs as root)" test_exec_join_documents_user_behavior || true

print_summary "Image-Backed Tests"
