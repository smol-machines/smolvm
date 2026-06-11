#!/bin/bash
#
# Scale tests for smolvm.
#
# Verifies concurrent VM operations work correctly under contention:
# SQLite locking, per-VM flock, vsock connect retries, and concurrent exec.
#
# Usage:
#   ./tests/test_scale.sh
#   ./tests/run_tests.sh scale

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

echo ""
echo "=========================================="
echo "  smolvm Scale Tests"
echo "=========================================="
echo ""

# =============================================================================
# 10 concurrent VMs: create, start, exec, stop
# =============================================================================

test_10_concurrent_vms() {
    local COUNT=10
    local i

    for i in $(seq 1 $COUNT); do
        $SMOLVM machine stop --name "scale-$i" 2>/dev/null || true
        $SMOLVM machine delete --name "scale-$i" -f 2>/dev/null || true
    done

    # Create
    for i in $(seq 1 $COUNT); do
        $SMOLVM machine create --name "scale-$i" --mem 512 --cpus 1 2>/dev/null || {
            echo "FAIL: create scale-$i failed"; return 1
        }
    done

    # Start concurrently
    local pids=()
    for i in $(seq 1 $COUNT); do
        $SMOLVM machine start --name "scale-$i" 2>/dev/null &
        pids+=($!)
    done
    local start_fails=0
    for pid in "${pids[@]}"; do
        wait "$pid" || ((start_fails++))
    done
    sleep 1

    # Verify all running
    local running=0
    for i in $(seq 1 $COUNT); do
        if $SMOLVM machine status --name "scale-$i" 2>&1 | grep -q "running"; then
            ((running++))
        fi
    done

    # Exec on each
    local exec_pass=0
    for i in $(seq 1 $COUNT); do
        local out
        out=$($SMOLVM machine exec --name "scale-$i" -- echo "ok-$i" 2>&1) || true
        if echo "$out" | grep -q "ok-$i"; then
            ((exec_pass++))
        fi
    done

    # Cleanup
    for i in $(seq 1 $COUNT); do
        $SMOLVM machine stop --name "scale-$i" 2>/dev/null || true
        $SMOLVM machine delete --name "scale-$i" -f 2>/dev/null || true
    done

    echo "  running: $running/$COUNT, exec: $exec_pass/$COUNT, start_fails: $start_fails"
    [[ $running -eq $COUNT ]] || { echo "FAIL: only $running/$COUNT running"; return 1; }
    [[ $exec_pass -eq $COUNT ]] || { echo "FAIL: only $exec_pass/$COUNT exec passed"; return 1; }
}

run_test "Scale: 10 concurrent VMs start + exec" test_10_concurrent_vms || true

# =============================================================================
# Concurrent exec storm: 5 execs per VM across 10 VMs (50 total)
# =============================================================================

test_concurrent_exec_storm() {
    local COUNT=10
    local EXECS_PER_VM=5
    local i j

    for i in $(seq 1 $COUNT); do
        $SMOLVM machine stop --name "storm-$i" 2>/dev/null || true
        $SMOLVM machine delete --name "storm-$i" -f 2>/dev/null || true
    done

    # Create and start sequentially (scale test above covers concurrent start)
    for i in $(seq 1 $COUNT); do
        $SMOLVM machine create --name "storm-$i" --mem 512 --cpus 1 2>/dev/null || return 1
        $SMOLVM machine start --name "storm-$i" 2>/dev/null || return 1
    done

    # Storm: 50 concurrent execs
    local tmpdir
    tmpdir=$(mktemp -d)
    for i in $(seq 1 $COUNT); do
        for j in $(seq 1 $EXECS_PER_VM); do
            (
                out=$($SMOLVM machine exec --name "storm-$i" -- echo "s-${i}-${j}" 2>&1)
                if echo "$out" | grep -q "s-${i}-${j}"; then
                    touch "$tmpdir/pass-${i}-${j}"
                fi
            ) &
        done
    done
    wait
    local pass_count
    pass_count=$(find "$tmpdir" -name "pass-*" 2>/dev/null | wc -l)
    rm -rf "$tmpdir"

    # Cleanup
    for i in $(seq 1 $COUNT); do
        $SMOLVM machine stop --name "storm-$i" 2>/dev/null || true
        $SMOLVM machine delete --name "storm-$i" -f 2>/dev/null || true
    done

    local total=$((COUNT * EXECS_PER_VM))
    echo "  exec pass: $pass_count/$total"
    [[ $pass_count -eq $total ]] || { echo "FAIL: only $pass_count/$total execs passed"; return 1; }
}

run_test "Scale: 50 concurrent execs across 10 VMs" test_concurrent_exec_storm || true

# =============================================================================
# Rapid lifecycle: create-start-stop-delete x5
# =============================================================================

test_rapid_lifecycle() {
    local i
    for i in $(seq 1 5); do
        $SMOLVM machine create --name "rapid-$$" --mem 512 --cpus 1 2>/dev/null || {
            echo "FAIL: create iteration $i"; return 1
        }
        $SMOLVM machine start --name "rapid-$$" 2>/dev/null || {
            echo "FAIL: start iteration $i"
            $SMOLVM machine delete --name "rapid-$$" -f 2>/dev/null; return 1
        }
        $SMOLVM machine stop --name "rapid-$$" 2>/dev/null || true
        $SMOLVM machine delete --name "rapid-$$" -f 2>/dev/null || true
    done
    echo "  5 create-start-stop-delete cycles completed"
}

run_test "Scale: rapid lifecycle (5 iterations)" test_rapid_lifecycle || true

print_summary "Scale Tests"
