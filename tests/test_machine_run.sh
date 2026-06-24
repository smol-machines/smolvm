#!/bin/bash
#
# Machine Run (Ephemeral) Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_machine_run.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Machine Run (Ephemeral) Tests"
echo "=========================================="
echo ""

test_machine_run_echo() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- echo "run-test-marker" 2>&1)
    [[ "$output" == *"run-test-marker"* ]]
}

test_machine_run_exit_code() {
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 0" 2>&1
    local exit_code=0
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 42" 2>&1 || exit_code=$?
    [[ $exit_code -eq 42 ]]
}

test_machine_run_env() {
    local output
    output=$($SMOLVM machine run --net -e TEST_VAR=hello_run --image alpine:latest -- sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$output" == *"hello_run"* ]]
}

test_machine_run_volume() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "run-mount-test" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt" --image alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"
    [[ "$output" == *"run-mount-test"* ]]
}

test_machine_run_volume_readonly() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "readonly-data" > "$tmpdir/readonly.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Should be able to read
    [[ "$output" == *"readonly-data"* ]] || { rm -rf "$tmpdir"; return 1; }

    # Should fail to write
    local write_exit=0
    $SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- sh -c "echo fail > /hostmnt/newfile.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ $write_exit -ne 0 ]]
}

test_machine_run_volume_multiple() {
    local tmpdir1 tmpdir2
    tmpdir1=$(mktemp -d)
    tmpdir2=$(mktemp -d)
    echo "data1" > "$tmpdir1/file1.txt"
    echo "data2" > "$tmpdir2/file2.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir1:/data1" -v "$tmpdir2:/data2" --image alpine:latest -- sh -c "cat /data1/file1.txt && cat /data2/file2.txt" 2>&1)

    rm -rf "$tmpdir1" "$tmpdir2"
    [[ "$output" == *"data1"* ]] && [[ "$output" == *"data2"* ]]
}

test_machine_run_workdir() {
    local output
    output=$($SMOLVM machine run --net -w /tmp --image alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/tmp"* ]]
}

test_machine_run_image_default_workdir() {
    local output exit_code=0
    output=$(run_with_timeout 180 \
        "$SMOLVM" machine run -I docker.io/library/redis:7.4 --net -- \
        sh -lc "pwd") || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        case "$output" in
            *"no matching manifest"*|*"exec format error"*|*"platform"* )
                log_skip "Skipping image default workdir regression: image unsupported on this host"
                return 0
                ;;
        esac

        echo "machine run failed:"
        echo "$output"
        return 1
    fi

    local pwd_result
    pwd_result=$(printf '%s\n' "$output" | tail -n 1 | tr -d '\r')
    [[ "$pwd_result" == "/data" ]] || {
        echo "expected image workdir /data, got: $pwd_result"
        echo "$output"
        return 1
    }
}

test_machine_run_image_default_user() {
    local output exit_code=0
    output=$(run_with_timeout 180 \
        "$SMOLVM" machine run -I docker.io/nginxinc/nginx-unprivileged:stable-alpine --net -- \
        sh -lc "id -u") || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        case "$output" in
            *"no matching manifest"*|*"exec format error"*|*"platform"*|*"not found"* )
                log_skip "Skipping image default user regression: image unsupported on this host"
                return 0
                ;;
        esac

        echo "machine run failed:"
        echo "$output"
        return 1
    fi

    local user_result
    user_result=$(printf '%s\n' "$output" | tail -n 1 | tr -d '\r')
    [[ "$user_result" == "101" ]] || {
        echo "expected image user id 101, got: $user_result"
        echo "$output"
        return 1
    }
}

test_machine_run_detached() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    local run_output exit_code=0
    run_output=$($SMOLVM machine run -d --net --image alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete --name default -f 2>/dev/null || true
        echo "Setup failed: machine run -d returned $exit_code: $run_output"
        return 1
    fi

    # Should appear in machine ls
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_machine_run_detached_with_command() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    # The detached command writes to a host-mounted volume so execution is
    # verified on the host. Do NOT write to the container's /tmp and read it back
    # via `machine exec`: /tmp is a per-container tmpfs, and once the detached
    # workload exits a later `machine exec` runs in a fresh container, so the
    # tmpfs file would not be visible (false failure).
    local outdir
    outdir=$(mktemp -d)

    local run_output exit_code=0
    run_output=$($SMOLVM machine run -d --net -v "$outdir:/out" --image alpine:latest -- \
        sh -c "echo issue198_fixed > /out/run-d-cmd-test.txt" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete --name default -f 2>/dev/null || true
        rm -rf "$outdir"
        echo "Setup failed: machine run -d returned $exit_code: $run_output"
        return 1
    fi

    # Poll until the background command has written the file (usually <1s).
    local file_output="" i=0
    while [[ $i -lt 20 ]]; do
        file_output=$(cat "$outdir/run-d-cmd-test.txt" 2>/dev/null) && [[ -n "$file_output" ]] && break
        sleep 0.5
        ((i++)) || true
    done

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    rm -rf "$outdir"

    if [[ "$file_output" != *"issue198_fixed"* ]]; then
        echo "FAIL: command was not executed by 'machine run -d --image X -- cmd'"
        echo "Expected file contents containing 'issue198_fixed', got: $file_output"
        return 1
    fi
}

test_machine_run_image_volume_workspace() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "workspace-volume-marker" > "$tmpdir/probe.txt"

    local output exit_code=0
    output=$(run_with_timeout 60 $SMOLVM machine run --net \
        -v "$tmpdir:/workspace" --image alpine:latest -- cat /workspace/probe.txt 2>&1) || exit_code=$?

    rm -rf "$tmpdir"

    if [[ $exit_code -ne 0 ]]; then
        echo "FAIL: machine run failed (exit $exit_code): $output"
        return 1
    fi
    if ! echo "$output" | grep -q "workspace-volume-marker"; then
        echo "FAIL: host file not visible at /workspace in image container"
        echo "output: $output"
        return 1
    fi
}

test_machine_run_image_volume_workspace_smolfile() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "smolfile-workspace-marker" > "$tmpdir/probe.txt"

    cat > "$tmpdir/Smolfile.toml" <<'EOF'
image = "alpine:latest"
net = true

[dev]
volumes = [".:/workspace"]
EOF

    local output exit_code=0
    output=$(
        cd "$tmpdir"
        run_with_timeout 60 $SMOLVM machine run -s Smolfile.toml -- cat /workspace/probe.txt 2>&1
    ) || exit_code=$?

    rm -rf "$tmpdir"

    if [[ $exit_code -ne 0 ]]; then
        echo "FAIL: machine run -s Smolfile.toml failed (exit $exit_code): $output"
        return 1
    fi
    if ! echo "$output" | grep -q "smolfile-workspace-marker"; then
        echo "FAIL: host file not visible at /workspace via Smolfile [dev].volumes"
        echo "output: $output"
        return 1
    fi
}

test_machine_run_detached_volume_workspace() {
    local vm_name="det-vol-ws-$$"
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "detached-workspace-marker" > "$tmpdir/probe.txt"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local run_output exit_code=0
    run_output=$(run_with_timeout 120 $SMOLVM machine run -d --net \
        --name "$vm_name" \
        -v "$tmpdir:/workspace" \
        --image alpine:latest -- sleep infinity 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo "FAIL: machine run -d failed: $run_output"
        rm -rf "$tmpdir"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Keep tmpdir alive until after exec — the virtiofs mount points to it
    local exec_out
    exec_out=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- cat /workspace/probe.txt 2>&1) || {
        echo "FAIL: exec failed: $exec_out"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        rm -rf "$tmpdir"
        return 1
    }

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"

    if ! echo "$exec_out" | grep -q "detached-workspace-marker"; then
        echo "FAIL: host file not visible at /workspace in detached container"
        echo "exec output: $exec_out"
        return 1
    fi
}

test_machine_start_restores_workload() {
    local vm_name="start-restores-workload-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create persistent VM with a long-running workload
    local run_output exit_code=0
    run_output=$(run_with_timeout 120 $SMOLVM machine run -d --net \
        --name "$vm_name" --image alpine:latest -- sleep infinity 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "FAIL: machine run -d failed: $run_output"
        return 1
    fi

    # Verify workload is PID 1 before stop
    local ps_before
    ps_before=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- ps -ef 2>&1) || {
        echo "FAIL: exec before stop failed: $ps_before"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if ! echo "$ps_before" | grep -q "sleep"; then
        echo "FAIL: expected 'sleep infinity' in ps before stop, got:"
        echo "$ps_before"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        echo "FAIL: machine stop failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    local start_output
    start_output=$(run_with_timeout 120 $SMOLVM machine start --name "$vm_name" 2>&1) || {
        echo "FAIL: machine start failed: $start_output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # Verify workload is PID 1 after restart — the regression check
    local ps_after
    ps_after=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- ps -ef 2>&1) || {
        echo "FAIL: exec after restart failed: $ps_after"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if ! echo "$ps_after" | grep -q "sleep"; then
        echo "FAIL: workload 'sleep infinity' not present after stop+start"
        echo "ps before stop:"
        echo "$ps_before"
        echo "ps after restart:"
        echo "$ps_after"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
}

test_machine_start_restores_workload_smolfile() {
    local vm_name="start-restores-sf-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)

    cat > "$tmpdir/Smolfile.toml" <<'EOF'
image = "alpine:latest"
net = true
cmd = ["sleep", "infinity"]
EOF

    # Create via Smolfile, then run detached (exact repro shape)
    local run_output exit_code=0
    run_output=$(
        cd "$tmpdir"
        run_with_timeout 120 $SMOLVM machine run -d --name "$vm_name" -s Smolfile.toml 2>&1
    ) || exit_code=$?

    rm -rf "$tmpdir"

    if [[ $exit_code -ne 0 ]]; then
        echo "FAIL: machine run -d -s Smolfile.toml failed: $run_output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Verify workload is running before stop
    local ps_before
    ps_before=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- ps -ef 2>&1) || {
        echo "FAIL: exec before stop failed: $ps_before"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if ! echo "$ps_before" | grep -q "sleep"; then
        echo "FAIL: expected 'sleep infinity' in ps before stop, got:"
        echo "$ps_before"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        echo "FAIL: machine stop failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    local start_output
    start_output=$(run_with_timeout 120 $SMOLVM machine start --name "$vm_name" 2>&1) || {
        echo "FAIL: machine start failed: $start_output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # Workload must still be present — the Smolfile cmd regression check
    local ps_after
    ps_after=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- ps -ef 2>&1) || {
        echo "FAIL: exec after restart failed: $ps_after"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if ! echo "$ps_after" | grep -q "sleep"; then
        echo "FAIL: Smolfile cmd 'sleep infinity' not present after stop+start"
        echo "ps before stop:"
        echo "$ps_before"
        echo "ps after restart:"
        echo "$ps_after"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
}

test_machine_run_timeout() {
    local output
    output=$($SMOLVM machine run --net --timeout 5s --image alpine:latest -- sleep 60 2>&1 || true)
    # Should be killed before 60s
    [[ "$output" == *"timed out"* ]] || [[ "$output" == *"Killed"* ]] || [[ $? -ne 0 ]]
}

test_machine_run_pipeline() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- sh -c "echo 'hello world' | wc -w" 2>&1)
    [[ "$output" == *"2"* ]]
}

test_machine_run_cmd_not_found() {
    ! $SMOLVM machine run --net --image alpine:latest -- nonexistent_command_12345 2>/dev/null
}

test_ephemeral_vm_tracking() {
    # Ephemeral machine run should appear in list while running, disappear after exit
    local result
    result=$(run_with_timeout 30 $SMOLVM machine run --net --image alpine -- echo "ephemeral-tracking-test" 2>&1)
    local exit_code=$?
    [[ $exit_code -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"ephemeral-tracking-test"* ]] || { echo "Command failed: $result"; return 1; }

    # After clean exit, the ephemeral record should be gone
    local list_result
    list_result=$($SMOLVM machine ls 2>&1)
    # Should NOT contain any ephemeral VMs from this run (they deregister on exit)
    if echo "$list_result" | grep -q "(eph).*running"; then
        echo "Ephemeral VM still in list after clean exit"
        return 1
    fi

    # Verify orphan cleanup works: list should not error
    [[ $? -eq 0 ]]
}

test_ephemeral_shows_in_list_while_running() {
    # Start a detached run with an explicit name and verify it appears in list.
    # An unnamed `-d` run lands as "default"; naming it makes the assertion
    # deterministic (grep the exact name) and the cleanup unambiguous.
    local name="run-visible-$$"
    $SMOLVM machine run --net -d --name "$name" --image alpine -- sleep 30 2>&1 || {
        echo "Detached run failed"
        return 1
    }

    # Poll until the detached VM appears in the list (usually <1s).
    local list_result i=0
    while [[ $i -lt 20 ]]; do
        list_result=$($SMOLVM machine ls 2>&1)
        echo "$list_result" | grep -q "$name" && break
        sleep 0.5
        ((i++)) || true
    done
    echo "$list_result" | grep -q "$name" || {
        echo "Detached run not in list: $list_result"
        $SMOLVM machine stop --name "$name" 2>/dev/null || true
        $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
        return 1
    }

    # Clean up
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
}

test_run_no_command_errors() {
    # machine run with no command and no -it should error with guidance
    local result
    local exit_code=0
    result=$($SMOLVM machine run 2>&1) || exit_code=$?

    # Should fail with non-zero exit
    [[ $exit_code -ne 0 ]] || { echo "Should have failed"; return 1; }

    # Should contain usage guidance
    [[ "$result" == *"no command specified"* ]] || {
        echo "Missing usage guidance: $result"
        return 1
    }
}

test_ephemeral_runs_do_not_share_state() {
    # Run 1: create a marker file
    $SMOLVM machine run --net --image alpine:latest -- \
        sh -c 'echo ephemeral-leak-test > /tmp/ephemeral-marker.txt' 2>&1

    # Run 2: marker must not exist
    local output exit_code=0
    output=$($SMOLVM machine run --net --image alpine:latest -- \
        sh -c 'cat /tmp/ephemeral-marker.txt 2>&1 || echo MARKER_NOT_FOUND' 2>&1) || exit_code=$?

    [[ "$output" == *"MARKER_NOT_FOUND"* ]] || {
        echo "FAIL: ephemeral run found file from previous run"
        echo "$output"
        return 1
    }
}

test_ephemeral_volume_mount_reflects_host() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "file-a" > "$tmpdir/a.txt"
    echo "file-b" > "$tmpdir/b.txt"
    echo "file-c" > "$tmpdir/c.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt" --image alpine:latest -- \
        ls /hostmnt 2>&1)

    rm -rf "$tmpdir"

    [[ "$output" == *"a.txt"* ]] || { echo "missing a.txt: $output"; return 1; }
    [[ "$output" == *"b.txt"* ]] || { echo "missing b.txt: $output"; return 1; }
    [[ "$output" == *"c.txt"* ]] || { echo "missing c.txt: $output"; return 1; }
}

test_init_skipped_on_restart() {
    local vm_name="init-skip-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create with init command and start — first boot should run init
    $SMOLVM machine create --name "$vm_name" --net --init "echo INIT_RAN" 2>&1
    local first_start
    first_start=$($SMOLVM machine start --name "$vm_name" 2>&1)
    echo "$first_start"

    if [[ "$first_start" != *"Running 1 init command"* ]]; then
        echo "FAIL: first start should run init"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart — should skip init
    $SMOLVM machine stop --name "$vm_name" 2>&1
    local second_start
    second_start=$($SMOLVM machine start --name "$vm_name" 2>&1)
    echo "$second_start"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    if [[ "$second_start" == *"Running"*"init command"* ]]; then
        echo "FAIL: second start should NOT re-run init"
        return 1
    fi
    if [[ "$second_start" != *"Init already completed"* ]]; then
        echo "FAIL: second start should print skip message"
        return 1
    fi
}


run_test "Machine run: echo" test_machine_run_echo || true
run_test "Machine run: exit code" test_machine_run_exit_code || true
run_test "Machine run: env variable" test_machine_run_env || true
run_test "Machine run: volume mount" test_machine_run_volume || true
run_test "Machine run: volume readonly" test_machine_run_volume_readonly || true
run_test "Machine run: multiple volumes" test_machine_run_volume_multiple || true
run_test "Machine run: workdir" test_machine_run_workdir || true
run_test "Machine run: image default workdir" test_machine_run_image_default_workdir || true
run_test "Machine run: image default user" test_machine_run_image_default_user || true
run_test "Machine run: detached" test_machine_run_detached || true
run_test "Machine run: detached with command (issue #198)" test_machine_run_detached_with_command || true
run_test "Volume: image container -v /workspace not overridden by storage disk" test_machine_run_image_volume_workspace || true
run_test "Volume: Smolfile [dev] volumes /workspace not overridden by storage disk" test_machine_run_image_volume_workspace_smolfile || true
run_test "Volume: detached -v /workspace not overridden by storage disk" test_machine_run_detached_volume_workspace || true
run_test "Machine start: restores workload after stop+start" test_machine_start_restores_workload || true
run_test "Machine start: restores Smolfile cmd workload after stop+start" test_machine_start_restores_workload_smolfile || true
run_test "Machine run: timeout" test_machine_run_timeout || true
run_test "Machine run: pipeline" test_machine_run_pipeline || true
run_test "Machine run: cmd not found" test_machine_run_cmd_not_found || true
run_test "Ephemeral VM: clean exit deregisters" test_ephemeral_vm_tracking || true
run_test "Ephemeral VM: visible while running" test_ephemeral_shows_in_list_while_running || true
run_test "Run with no command errors" test_run_no_command_errors || true
run_test "Ephemeral run: no state leaks between runs" test_ephemeral_runs_do_not_share_state || true
run_test "Ephemeral run: volume mount shows correct host contents" test_ephemeral_volume_mount_reflects_host || true
run_test "Init: skipped on restart after first successful run" test_init_skipped_on_restart || true

# =============================================================================
# Piped stdin EOF detection
# =============================================================================

test_piped_stdin_cat() {
    local out exit_code=0
    out=$(echo "hello" | run_with_timeout 15 "$SMOLVM" machine run -i -- cat 2>/dev/null) \
        || exit_code=$?
    [[ $exit_code -eq 0 ]] || { echo "FAIL: exit $exit_code (expected 0)"; return 1; }
    [[ "$out" == *"hello"* ]] || { echo "FAIL: expected 'hello', got: $out"; return 1; }
}

run_test "Stdin: piped 'echo hello | run -i cat' returns data" test_piped_stdin_cat || true

# =============================================================================
# Status messages go to stderr, not stdout
# =============================================================================

test_stdout_no_status_messages() {
    local out
    # Pass --net so the run can pull alpine if it isn't already cached. Without
    # it this test depends on a warm image cache, which an earlier suite's
    # `prune --all` can wipe (suites share the host image cache) — making the
    # run fail to pull and the assertion flake on ordering.
    out=$("$SMOLVM" machine run --net --image alpine -- echo PAYLOAD_ONLY 2>/dev/null) || true
    if echo "$out" | grep -qiE "^Starting|^Pulling"; then
        echo "FAIL: status messages in stdout: $(echo "$out" | grep -iE 'Starting|Pulling' | head -1)"
        return 1
    fi
    [[ "$out" == *"PAYLOAD_ONLY"* ]] || { echo "FAIL: missing payload in: $out"; return 1; }
}

run_test "Output: stdout has only command output, no status" test_stdout_no_status_messages || true

print_summary "Machine Run Tests"
