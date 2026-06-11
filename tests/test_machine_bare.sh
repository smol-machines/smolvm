#!/bin/bash
#
# Bare VM Tests (lifecycle, exec, shell, file I/O, observability)
#
# Part of the smolvm test suite. Run with: ./tests/test_machine_bare.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Bare VM Tests (lifecycle, exec, shell, file I/O, observability)"
echo "=========================================="
echo ""

test_machine_start() {
    cleanup_machine
    $SMOLVM machine start 2>&1
}

test_machine_stop() {
    ensure_machine_running
    $SMOLVM machine stop 2>&1
}

test_machine_status_running() {
    ensure_machine_running
    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]]
}

test_machine_status_stopped() {
    cleanup_machine
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    # When stopped, status command either:
    # - Returns non-zero exit code, OR
    # - Returns status containing "not running" or "stopped"
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_machine_start_stop_cycle() {
    cleanup_machine

    # Start
    $SMOLVM machine start 2>&1 || return 1

    # Verify running
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ "$status" != *"running"* ]]; then
        return 1
    fi

    # Stop
    $SMOLVM machine stop 2>&1 || return 1

    # Verify stopped - either non-zero exit or status message indicates stopped
    exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_machine_exec() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

test_machine_exec_echo() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- echo "test-marker-xyz" 2>&1)
    [[ "$output" == *"test-marker-xyz"* ]]
}

test_machine_exec_binary_output_preserved() {
    ensure_machine_running

    # Fetch first 4 bytes of /bin/busybox — the ELF magic.
    # Pipe through xxd to render as hex so we're comparing ASCII strings
    # (bash can't easily compare binary blobs, but the agent→client→CLI
    # path is what we're exercising; the xxd happens host-side after the
    # bytes are already through the protocol).
    local hex
    hex=$($SMOLVM machine exec -- head -c 4 /bin/busybox 2>&1 | xxd -p | tr -d '\n')

    # ELF magic: 7f 45 4c 46  (.ELF)
    # If the 0x7f byte was dropped/replaced, we'd see "454c46" or "efbfbd454c46".
    [[ "$hex" == "7f454c46" ]] || {
        echo "expected ELF magic '7f454c46', got '$hex' — binary output corrupted"
        return 1
    }
}

test_machine_exec_exit_code() {
    ensure_machine_running

    # Test exit 0
    $SMOLVM machine exec -- sh -c "exit 0" 2>&1 || return 1

    # Test exit 1
    local exit_code=0
    $SMOLVM machine exec -- sh -c "exit 1" 2>&1 || exit_code=$?
    [[ $exit_code -eq 1 ]]
}

test_machine_exec_failed_does_not_kill_vm() {
    ensure_machine_running

    # Nonexistent binary — should fail but VM stays alive
    local exit_code=0
    $SMOLVM machine exec -- /nonexistent_binary_xyz 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "expected failure for nonexistent binary"; return 1; }

    # VM must still be running
    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM died after failed exec: $status"; return 1; }

    # Next exec must succeed
    local output
    output=$($SMOLVM machine exec -- echo "survived-failed-exec" 2>&1)
    [[ "$output" == *"survived-failed-exec"* ]] || { echo "exec after failure returned: $output"; return 1; }

    # Empty string command — should fail but VM stays alive
    exit_code=0
    $SMOLVM machine exec -- "" 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "expected failure for empty command"; return 1; }

    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM died after empty command exec: $status"; return 1; }

    # Final verification
    output=$($SMOLVM machine exec -- echo "still-alive" 2>&1)
    [[ "$output" == *"still-alive"* ]]
}

test_sigterm_during_exec_does_not_stall_vm() {
    local name="bug12-sigterm-$$"
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
    $SMOLVM machine create --name "$name" 2>&1 | tail -1 || return 1
    $SMOLVM machine start --name "$name" 2>&1 | tail -1 || {
        $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1
    }
    wait_vm_ready --name "$name" || {
        $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1
    }

    # Start a long-running exec, then SIGTERM the client mid-flight.
    $SMOLVM machine exec --name "$name" -- sh -c 'sleep 30' &
    local client_pid=$!
    # Wait long enough for the exec to have registered with the agent (vsock round-trip).
    sleep 1
    kill -TERM "$client_pid" 2>/dev/null
    wait "$client_pid" 2>/dev/null
    # Give the agent's 10ms poll loop a moment to detect the disconnect
    sleep 1

    # VM must still be reachable. Before the fix, state would be "unreachable"
    # and the next exec would take ~30s. Time the exec to detect the stall.
    local t_start t_end elapsed
    t_start=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
    local result
    result=$($SMOLVM machine exec --name "$name" -- echo "survived" 2>&1)
    t_end=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
    elapsed=$(python3 -c "print(f'{$t_end - $t_start:.1f}')" 2>/dev/null || echo "?")

    echo "  Next exec after SIGTERM: ${elapsed}s"

    [[ "$result" == *"survived"* ]] || {
        echo "FAIL: exec after SIGTERM failed: $result"
        $SMOLVM machine stop --name "$name" 2>/dev/null
        $SMOLVM machine delete --name "$name" -f 2>/dev/null
        return 1
    }

    # Must be fast — the old path took ~30s while the orphan sleep finished.
    local over_threshold
    over_threshold=$(python3 -c "print('yes' if $t_end - $t_start > 5 else 'no')" 2>/dev/null || echo "no")
    if [[ "$over_threshold" == "yes" ]]; then
        echo "FAIL: next exec took ${elapsed}s (>5s) — agent stalled on orphan child?"
        $SMOLVM machine stop --name "$name" 2>/dev/null
        $SMOLVM machine delete --name "$name" -f 2>/dev/null
        return 1
    fi

    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
}

test_exec_timeout_does_not_stall_vm() {
    local name="bug20-timeout-$$"
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
    $SMOLVM machine create --name "$name" 2>&1 | tail -1 || return 1
    $SMOLVM machine start --name "$name" 2>&1 | tail -1 || {
        $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1
    }
    wait_vm_ready --name "$name" || {
        $SMOLVM machine delete --name "$name" -f 2>/dev/null; return 1
    }

    # Short timeout, long-running command with sub-processes — timeout should
    # kill the whole tree without stalling the agent.
    local result
    result=$($SMOLVM machine exec --name "$name" --timeout 2s -- sh -c 'sleep 30' 2>&1)
    # Exit code 124 = timeout, expected behavior (don't assert — just note)

    # Next exec must be fast. If the agent stalled, this will take ~30s.
    local t_start t_end elapsed
    t_start=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
    result=$($SMOLVM machine exec --name "$name" -- echo "alive" 2>&1)
    t_end=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
    elapsed=$(python3 -c "print(f'{$t_end - $t_start:.1f}')" 2>/dev/null || echo "?")

    echo "  Next exec after timeout: ${elapsed}s"

    [[ "$result" == *"alive"* ]] || {
        echo "FAIL: exec after timeout failed: $result"
        $SMOLVM machine stop --name "$name" 2>/dev/null
        $SMOLVM machine delete --name "$name" -f 2>/dev/null
        return 1
    }

    local over_threshold
    over_threshold=$(python3 -c "print('yes' if $t_end - $t_start > 5 else 'no')" 2>/dev/null || echo "no")
    if [[ "$over_threshold" == "yes" ]]; then
        echo "FAIL: next exec took ${elapsed}s (>5s) — agent stalled after timeout?"
        $SMOLVM machine stop --name "$name" 2>/dev/null
        $SMOLVM machine delete --name "$name" -f 2>/dev/null
        return 1
    fi

    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
}

test_machine_named_vm() {
    local vm_name="test-vm-named"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create the named VM first
    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1

    # Start
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Check status
    local status
    status=$($SMOLVM machine status --name "$vm_name" 2>&1)
    if [[ "$status" != *"running"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and delete
    $SMOLVM machine stop --name "$vm_name" 2>&1
    $SMOLVM machine delete --name "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_machine_create_prints_named_start_hint() {
    local vm_name="create-hint-test-$$"
    local output

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    output=$($SMOLVM machine create --name "$vm_name" 2>&1) || return 1

    [[ "$output" == *"Use 'smolvm machine start --name $vm_name' to start the machine"* ]] || {
        echo "$output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    $SMOLVM machine delete --name "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_machine_exec_when_stopped() {
    cleanup_machine

    local exit_code=0
    $SMOLVM machine exec -- echo "should-fail" 2>&1 || exit_code=$?

    # Should fail with non-zero exit code (don't check specific message)
    [[ $exit_code -ne 0 ]]
}

test_bare_vm_workspace() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- ls -d /workspace 2>&1)
    [[ "$output" == *"/workspace"* ]] || { echo "FAIL: /workspace missing on bare VM"; return 1; }

    # Write and read back
    $SMOLVM machine exec -- sh -c 'echo ws-bare > /workspace/bare.txt' 2>&1 || return 1
    output=$($SMOLVM machine exec -- cat /workspace/bare.txt 2>&1)
    [[ "$output" == *"ws-bare"* ]]
}

test_file_upload_download() {
    local vm_name="cp-test-$$"

    # Create and start a machine
    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    run_with_timeout 30 $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }

    # Upload a file
    local upload_content="hello from host $(date +%s)"
    echo "$upload_content" > /tmp/smolvm-cp-test.txt
    $SMOLVM machine cp /tmp/smolvm-cp-test.txt "$vm_name":/tmp/uploaded.txt 2>&1 || {
        echo "Upload failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }

    # Verify upload via exec
    local exec_result
    exec_result=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/uploaded.txt 2>&1) || {
        echo "Exec after upload failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }
    [[ "$exec_result" == *"$upload_content"* ]] || {
        echo "Upload content mismatch: expected '$upload_content', got '$exec_result'"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }

    # Create file in VM and download
    $SMOLVM machine exec --name "$vm_name" -- sh -c "echo 'hello from VM' > /tmp/to-download.txt" 2>&1
    $SMOLVM machine cp "$vm_name":/tmp/to-download.txt /tmp/smolvm-downloaded.txt 2>&1 || {
        echo "Download failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
        return 1
    }
    local downloaded
    downloaded=$(cat /tmp/smolvm-downloaded.txt)
    [[ "$downloaded" == *"hello from VM"* ]] || {
        echo "Download content mismatch: '$downloaded'"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
    rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
}

test_streaming_exec() {
    # Start a machine, run a command with --stream, verify output arrives
    $SMOLVM machine stop 2>/dev/null || true

    $SMOLVM machine create --name stream-test-$$ 2>&1 || return 1
    run_with_timeout 30 $SMOLVM machine start --name stream-test-$$ 2>&1 || {
        $SMOLVM machine delete --name stream-test-$$ -f 2>/dev/null; return 1
    }

    # Streaming exec — output should contain the echoed text
    local result
    result=$(run_with_timeout 15 $SMOLVM machine exec --stream --name stream-test-$$ -- sh -c "echo 'stream-line-1' && echo 'stream-line-2' && echo 'done'" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; $SMOLVM machine stop --name stream-test-$$ 2>/dev/null; $SMOLVM machine delete --name stream-test-$$ -f 2>/dev/null; return 1; }

    [[ "$result" == *"stream-line-1"* ]] && [[ "$result" == *"stream-line-2"* ]] && [[ "$result" == *"done"* ]] || {
        echo "Missing streaming output: $result"
        $SMOLVM machine stop --name stream-test-$$ 2>/dev/null
        $SMOLVM machine delete --name stream-test-$$ -f 2>/dev/null
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name stream-test-$$ 2>/dev/null
    $SMOLVM machine delete --name stream-test-$$ -f 2>/dev/null
}

test_agent_json_logs() {
    local vm_name="observability-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Run a command to generate agent log entries
    $SMOLVM machine exec --name "$vm_name" -- echo "observability-test" 2>&1 || true

    # Find the console log using the platform-aware vm_data_dir helper
    local data_dir
    data_dir=$(vm_data_dir "$vm_name")
    local console_log="${data_dir}/agent-console.log"

    # Copy the log before stopping (stop/delete may remove the data dir)
    local saved_log
    saved_log=$(mktemp)
    cp "$console_log" "$saved_log" 2>/dev/null || true

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    if [[ ! -s "$saved_log" ]]; then
        echo "Console log not found or empty at $console_log"
        rm -f "$saved_log"
        return 1
    fi

    # Agent should write JSON — verify at least one line parses as JSON
    local json_lines
    json_lines=$(grep -c '^{' "$saved_log" 2>/dev/null || echo "0")
    if [[ "$json_lines" -eq 0 ]]; then
        echo "No JSON lines in console log ($console_log)"
        rm -f "$saved_log"
        return 1
    fi

    # Verify a tracing-formatted JSON line has expected structured fields.
    # Skip early boot_log lines (target=smolvm_agent::boot) which use a
    # simpler format without timestamps — they run before tracing is initialized.
    local first_json
    first_json=$(grep '^{' "$saved_log" | grep '"timestamp"' | head -1)
    rm -f "$saved_log"
    if [[ -z "$first_json" ]]; then
        echo "No tracing JSON lines with timestamp found in console log"
        return 1
    fi
    echo "$first_json" | python3 -c "
import sys, json
line = json.load(sys.stdin)
assert 'timestamp' in line, 'missing timestamp'
assert 'level' in line, 'missing level'
" 2>&1 || { echo "JSON log missing structured fields: $first_json"; return 1; }
}

test_machine_shell() {
    ensure_machine_running

    # shell opens an interactive PTY. Pipe "echo X; exit" through it.
    # Use a subshell with a watchdog kill to avoid hanging if the PTY blocks.
    local tmpout
    tmpout=$(mktemp)
    (echo "echo shell-test-ok; exit" | $SMOLVM machine shell > "$tmpout" 2>&1) &
    local pid=$!
    sleep 5
    kill $pid 2>/dev/null; wait $pid 2>/dev/null

    local output
    output=$(cat "$tmpout")
    rm -f "$tmpout"

    [[ "$output" == *"shell-test-ok"* ]] || {
        echo "FAIL: expected shell-test-ok, got: $output"
        return 1
    }
}

test_exec_large_stdout_does_not_crash_vm() {
    ensure_machine_running "true"

    # Generate 128KB of output — well above the ~64KB pipe buffer
    local output
    output=$(run_with_timeout 30 $SMOLVM machine exec -- sh -c 'dd if=/dev/urandom bs=1024 count=128 2>/dev/null | base64' 2>&1)
    local exit_code=$?

    [[ $exit_code -eq 124 ]] && { echo "FAIL: timed out (pipe deadlock?)"; return 1; }

    local output_size=${#output}
    [[ $output_size -gt 100000 ]] || {
        echo "FAIL: expected >100KB output, got ${output_size} bytes"
        return 1
    }

    # VM must still be responsive after large output
    local check
    check=$(run_with_timeout 10 $SMOLVM machine exec -- echo "still-alive" 2>&1) || {
        echo "FAIL: VM unreachable after large stdout"
        return 1
    }
    echo "$check" | grep -q "still-alive" || {
        echo "FAIL: expected 'still-alive', got: $check"
        return 1
    }
}

_docker_in_vm_start_dockerd() {
    local vm_name="$1"
    $SMOLVM machine exec --name "$vm_name" -- sh -c '
        mkdir -p /storage/docker /var/lib/docker
        mount --bind /storage/docker /var/lib/docker
        rm -f /var/run/docker.pid
        dockerd --storage-driver=overlay2 >/tmp/dockerd.log 2>&1 &
        for i in $(seq 1 40); do
            docker info >/dev/null 2>&1 && echo "dockerd-ready" && exit 0
            sleep 1
        done
        echo "FAIL: dockerd did not become ready"
        tail -5 /tmp/dockerd.log
        exit 1
    ' 2>&1
}

test_docker_in_vm() {
    skip_if_slow && return 0
    local vm_name="docker-in-vm-$$"
    local smolfile="$PROJECT_ROOT/examples/docker-in-vm/docker.smolfile"

    echo "phase: pre-cleanup"
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # ── Create ────────────────────────────────────────────────────────────────
    echo "phase: create"
    local output
    output=$($SMOLVM machine create --name "$vm_name" \
        -s "$smolfile" --net-backend virtio-net 2>&1) || {
        echo "FAIL: machine create --name failed"
        echo "$output"
        return 1
    }
    [[ "$output" == *"Init commands: 4"* ]] || {
        echo "FAIL: expected 4 init commands, got: $output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── First start (runs init: apk add docker + bind-mount) ─────────────────
    echo "phase: first-start (apk add docker — expect 30-90s)"
    output=$($SMOLVM machine start --name "$vm_name" 2>&1) || {
        echo "FAIL: first machine start failed"
        echo "$output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"Running 4 init command"* ]] || {
        echo "FAIL: expected 4 init commands to run on first start"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Start dockerd ─────────────────────────────────────────────────────────
    echo "phase: start-dockerd"
    output=$(_docker_in_vm_start_dockerd "$vm_name") || {
        echo "FAIL: dockerd failed to start"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"dockerd-ready"* ]] || {
        echo "FAIL: dockerd did not report ready"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Assert: overlay2 storage driver on ext4 ───────────────────────────────
    echo "phase: assert-overlay2-on-ext4"
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c '
        driver=$(docker info 2>/dev/null | grep "Storage Driver:" | awk "{print \$3}")
        [ "$driver" = "overlay2" ] || { echo "FAIL: storage driver=$driver"; exit 1; }
        echo "storage-driver-ok"
        mount | grep -q "/dev/vda on /var/lib/docker type ext4" || {
            echo "FAIL: /var/lib/docker not on ext4"
            mount | grep "var/lib/docker" || true
            exit 1
        }
        echo "bind-mount-ok"
    ' 2>&1) || {
        echo "FAIL: storage driver or bind-mount check failed"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"storage-driver-ok"* ]] || { echo "FAIL: $output"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true; return 1; }
    [[ "$output" == *"bind-mount-ok"* ]]    || { echo "FAIL: $output"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true; return 1; }

    # ── Assert: docker run executes a container ───────────────────────────────
    echo "phase: docker-run"
    output=$($SMOLVM machine exec --name "$vm_name" -- \
        docker run --rm alpine echo "docker-in-vm-ok" 2>&1) || {
        echo "FAIL: docker run failed"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"docker-in-vm-ok"* ]] || {
        echo "FAIL: expected docker-in-vm-ok, got: $output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Assert: bridge networking reaches the internet ────────────────────────
    echo "phase: docker-bridge-networking"
    output=$($SMOLVM machine exec --name "$vm_name" -- \
        docker run --rm alpine wget -qO- https://httpbin.org/get 2>&1) || {
        echo "FAIL: docker bridge networking failed"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *'"url"'* ]] || {
        echo "FAIL: expected JSON response with url field, got: $output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Assert: docker build produces a runnable image ────────────────────────
    echo "phase: docker-build"
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c '
        printf "FROM alpine\nRUN echo build-layer-ok" > /tmp/Dockerfile
        docker build -t smolvm-test-build /tmp 2>&1 | tail -3
        docker run --rm smolvm-test-build echo "built-image-run-ok"
    ' 2>&1) || {
        echo "FAIL: docker build or run of built image failed"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"built-image-run-ok"* ]] || {
        echo "FAIL: expected built-image-run-ok, got: $output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Stop → restart cycle ──────────────────────────────────────────────────
    echo "phase: stop"
    $SMOLVM machine stop --name "$vm_name" 2>&1 || {
        echo "FAIL: machine stop failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    echo "phase: restart"
    output=$($SMOLVM machine start --name "$vm_name" 2>&1) || {
        echo "FAIL: machine restart failed"
        echo "$output"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"Init already completed"* ]] || {
        echo "FAIL: init should be skipped on restart, got: $output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Re-start dockerd after restart ────────────────────────────────────────
    echo "phase: start-dockerd-after-restart"
    output=$(_docker_in_vm_start_dockerd "$vm_name") || {
        echo "FAIL: dockerd failed to start after VM restart"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"dockerd-ready"* ]] || {
        echo "FAIL: dockerd not ready after VM restart"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }

    # ── Assert: images persist across restart ─────────────────────────────────
    echo "phase: assert-persistence"
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c '
        docker images | grep -q "^alpine " || { echo "FAIL: alpine image missing after restart"; docker images; exit 1; }
        echo "alpine-persists"
        docker images | grep -q "smolvm-test-build" || { echo "FAIL: built image missing after restart"; docker images; exit 1; }
        echo "built-image-persists"
        docker run --rm alpine echo "post-restart-run-ok"
    ' 2>&1) || {
        echo "FAIL: post-restart image persistence check failed"
        echo "$output"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"alpine-persists"* ]]      || { echo "FAIL: $output"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true; return 1; }
    [[ "$output" == *"built-image-persists"* ]] || { echo "FAIL: $output"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true; return 1; }
    [[ "$output" == *"post-restart-run-ok"* ]]  || { echo "FAIL: $output"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true; return 1; }

    # ── Cleanup ───────────────────────────────────────────────────────────────
    echo "phase: cleanup"
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
}


run_test "Machine start" test_machine_start || true
run_test "Machine stop" test_machine_stop || true
run_test "Machine status (running)" test_machine_status_running || true
run_test "Machine status (stopped)" test_machine_status_stopped || true
run_test "Machine start/stop cycle" test_machine_start_stop_cycle || true
run_test "Machine exec" test_machine_exec || true
run_test "Machine exec: echo" test_machine_exec_echo || true
run_test "Machine exec: binary output preserved (BUG-23)" test_machine_exec_binary_output_preserved || true
run_test "Machine exec exit code" test_machine_exec_exit_code || true
run_test "Failed exec does not kill VM" test_machine_exec_failed_does_not_kill_vm || true
run_test "SIGTERM during exec does not stall VM" test_sigterm_during_exec_does_not_stall_vm || true
run_test "Exec timeout does not stall VM" test_exec_timeout_does_not_stall_vm || true
run_test "Named machine" test_machine_named_vm || true
run_test "Create prints named start hint" test_machine_create_prints_named_start_hint || true
run_test "Exec when stopped fails" test_machine_exec_when_stopped || true
run_test "Bare VM: /workspace exists" test_bare_vm_workspace || true
run_test "File upload and download" test_file_upload_download || true
run_test "Streaming exec" test_streaming_exec || true
run_test "Agent: structured JSON logs" test_agent_json_logs || true
run_test "Shell: machine shell opens interactive shell" test_machine_shell || true
run_test "Exec: large stdout does not crash VM (bare)" test_exec_large_stdout_does_not_crash_vm || true
run_test "Docker-in-VM: overlay2 + bridge networking + build + restart persistence" test_docker_in_vm || true

# =============================================================================
# Exec stdin null — stdin-blocking commands exit cleanly
# =============================================================================

_EXEC_STDIN_MACHINE="exec-stdin-$$"

test_exec_cat_no_interactive() {
    "$SMOLVM" machine stop --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_EXEC_STDIN_MACHINE" -f 2>/dev/null || true
    "$SMOLVM" machine create --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || return 1
    "$SMOLVM" machine start --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || return 1

    local out exit_code=0
    out=$(run_with_timeout 10 "$SMOLVM" machine exec --name "$_EXEC_STDIN_MACHINE" -- cat 2>&1) \
        || exit_code=$?

    "$SMOLVM" machine stop --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_EXEC_STDIN_MACHINE" -f 2>/dev/null || true

    if echo "$out" | grep -qi "connection closed"; then
        echo "FAIL: got 'connection closed'"
        return 1
    fi
    [[ $exit_code -eq 0 ]] || { echo "FAIL: exit $exit_code (expected 0)"; return 1; }
}

run_test "Exec: 'exec -- cat' exits cleanly with null stdin" test_exec_cat_no_interactive || true

test_exec_tty_piped_stdin_terminates() {
    # `--tty` runs the child on a PTY. A PTY cannot have one direction
    # closed, so when the feeding pipe (`echo`) closes, end-of-input must
    # still reach the child. Without EOF propagation a stdin reader (cat)
    # never terminates and the exec session hangs.
    "$SMOLVM" machine stop --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_EXEC_STDIN_MACHINE" -f 2>/dev/null || true
    "$SMOLVM" machine create --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || return 1
    "$SMOLVM" machine start --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || return 1

    # Newline-terminated input: the PTY line buffer is empty when EOF
    # arrives, so a single VEOF would already yield the zero-length read.
    local exit_code=0
    run_with_timeout 15 sh -c \
        "echo tty-input | '$SMOLVM' machine exec --name '$_EXEC_STDIN_MACHINE' --tty -i -- cat" \
        >/dev/null 2>&1 || exit_code=$?

    # Unterminated input (no trailing newline): the first VEOF only flushes
    # the partial line as data, so a second VEOF is required to deliver the
    # zero-length read. This is the case a single VEOF fails to terminate.
    local exit_code_partial=0
    run_with_timeout 15 sh -c \
        "printf no-newline | '$SMOLVM' machine exec --name '$_EXEC_STDIN_MACHINE' --tty -i -- cat" \
        >/dev/null 2>&1 || exit_code_partial=$?

    "$SMOLVM" machine stop --name "$_EXEC_STDIN_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_EXEC_STDIN_MACHINE" -f 2>/dev/null || true

    [[ $exit_code -ne 124 ]] || { echo "FAIL: 'exec --tty -i' with piped stdin timed out (PTY EOF not propagated)"; return 1; }
    [[ $exit_code_partial -ne 124 ]] || { echo "FAIL: 'exec --tty -i' with unterminated stdin timed out (PTY EOF not propagated)"; return 1; }
}

run_test "Exec: 'exec --tty -i' with piped stdin terminates (PTY EOF)" test_exec_tty_piped_stdin_terminates || true

# =============================================================================
# Named machine survives observer Drop
# =============================================================================

_DROP_MACHINE="drop-safe-$$"

test_machine_survives_rapid_exec() {
    "$SMOLVM" machine stop --name "$_DROP_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_DROP_MACHINE" -f 2>/dev/null || true
    "$SMOLVM" machine create --name "$_DROP_MACHINE" 2>/dev/null || return 1
    "$SMOLVM" machine start --name "$_DROP_MACHINE" 2>/dev/null || return 1

    local i
    for i in 1 2 3 4 5; do
        local out exit_code=0
        out=$(run_with_timeout 15 "$SMOLVM" machine exec --name "$_DROP_MACHINE" -- echo "alive-$i" 2>/dev/null) \
            || exit_code=$?
        [[ $exit_code -eq 0 ]] || {
            "$SMOLVM" machine delete --name "$_DROP_MACHINE" -f 2>/dev/null || true
            echo "FAIL: exec #$i failed (exit $exit_code)"; return 1
        }
    done

    "$SMOLVM" machine stop --name "$_DROP_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete --name "$_DROP_MACHINE" -f 2>/dev/null || true
}

run_test "Drop-safety: machine survives 5 rapid execs" test_machine_survives_rapid_exec || true

print_summary "Bare VM Tests"
