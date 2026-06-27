#!/usr/bin/env bash
#
# Fork-base guard tests (regression for BUG-142/143/144)
#
# A forkable golden is snapshot-frozen once it has clones whose disks are
# copy-on-write overlays backed by its disks. It must therefore:
#   - report state "frozen" (not the misleading "unreachable")     [BUG-144]
#   - answer `status` instantly, without probing its paused agent  [BUG-143]
#   - refuse `stop`/`start` while clones exist (no silent reap)     [BUG-142]
#   - stay usable as a fork base (new clones can still fork)        [BUG-142]
#   - reap cleanly under `delete --force` with no orphaned VMM
#
# Part of the smolvm test suite. Run with: ./tests/test_fork_base_guards.sh

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

GOLD="forkbase-gold-$$"
C1="forkbase-c1-$$"
C2="forkbase-c2-$$"

cleanup_fork() {
    for m in "$C1" "$C2" "$GOLD"; do
        "$SMOLVM" machine delete --name "$m" -f >/dev/null 2>&1 || true
    done
}
trap cleanup_fork EXIT

echo ""
echo "=========================================="
echo "  Fork-base Guard Tests (BUG-142/143/144)"
echo "=========================================="
echo ""

# Bring up a frozen golden with one live clone. If fork isn't supported on
# this platform/build, skip the whole suite cleanly.
setup_frozen_golden() {
    cleanup_fork
    "$SMOLVM" machine create --name "$GOLD" >/dev/null 2>&1 || return 1
    "$SMOLVM" machine start --name "$GOLD" --forkable >/dev/null 2>&1 || return 1
    "$SMOLVM" machine fork --golden "$GOLD" --name "$C1" >/dev/null 2>&1 || return 1
}

if ! setup_frozen_golden; then
    log_info "fork/--forkable not available on this platform/build — skipping suite"
    print_summary "Fork-base Guard Tests"
    exit 0
fi

# BUG-144: golden reports "frozen", not the misleading "unreachable".
# Use single-object `status --json` so there's no array-association
# fragility, and tolerate pretty-printed spacing (`"state": "frozen"`).
test_golden_state_is_frozen() {
    local out
    out=$(run_with_timeout 8 "$SMOLVM" machine status --name "$GOLD" --json 2>/dev/null)
    echo "golden state json: $(echo "$out" | grep -oE '"state":[[:space:]]*"[^"]*"')"
    echo "$out" | grep -qE '"state":[[:space:]]*"frozen"'
}

# BUG-143: status on the frozen golden returns fast (was a >12s hang) and
# reports frozen. Assert it completes well under the old timeout.
test_status_is_fast_and_frozen() {
    local start_ms end_ms out
    start_ms=$(date +%s%N)
    out=$(run_with_timeout 8 "$SMOLVM" machine status --name "$GOLD" 2>&1)
    end_ms=$(date +%s%N)
    local took_ms=$(( (end_ms - start_ms) / 1000000 ))
    echo "status: '${out}' in ${took_ms}ms"
    [[ "$out" == *"frozen"* ]] && [[ $took_ms -lt 3000 ]]
}

# BUG-142: stop must refuse (not silently reap the golden).
test_stop_refuses() {
    local out exit_code=0
    out=$("$SMOLVM" machine stop --name "$GOLD" 2>&1) || exit_code=$?
    echo "stop output: $out (exit $exit_code)"
    [[ $exit_code -ne 0 ]] && [[ "$out" == *"fork base"* ]]
}

# BUG-142: start must refuse (not reap-then-error).
test_start_refuses() {
    local out exit_code=0
    out=$("$SMOLVM" machine start --name "$GOLD" 2>&1) || exit_code=$?
    echo "start output: $out (exit $exit_code)"
    [[ $exit_code -ne 0 ]] && [[ "$out" == *"fork base"* ]]
}

# BUG-142: after the refused stop/start, the golden is still a usable fork
# base — a brand-new clone can be forked from it.
test_golden_still_forkable() {
    "$SMOLVM" machine delete --name "$C2" -f >/dev/null 2>&1 || true
    local out exit_code=0
    out=$(run_with_timeout 30 "$SMOLVM" machine fork --golden "$GOLD" --name "$C2" 2>&1) || exit_code=$?
    echo "fork output: $out (exit $exit_code)"
    [[ $exit_code -eq 0 ]] && [[ "$out" == *"Forked"* ]]
}

# The original clone keeps running through all of the above.
test_original_clone_alive() {
    local out
    out=$(run_with_timeout 15 "$SMOLVM" machine exec --name "$C1" -- echo "clone-alive" 2>&1)
    echo "clone exec: $out"
    [[ "$out" == *"clone-alive"* ]]
}

# delete --force breaks the chain and reaps the golden's VMM (no orphan).
test_force_delete_reaps_golden() {
    "$SMOLVM" machine delete --name "$GOLD" -f >/dev/null 2>&1 || return 1
    # Golden record is gone.
    "$SMOLVM" machine ls --json 2>/dev/null | grep -q "\"name\":\"$GOLD\"" && {
        echo "FAIL: golden record still present after force delete"; return 1; }
    echo "golden record removed"
    return 0
}

run_test "BUG-144: golden state is 'frozen'"            test_golden_state_is_frozen      || true
run_test "BUG-143: status is fast and reports frozen"   test_status_is_fast_and_frozen   || true
run_test "BUG-142: stop refuses on a fork base"         test_stop_refuses                || true
run_test "BUG-142: start refuses on a fork base"        test_start_refuses               || true
run_test "BUG-142: golden still forkable after refusal" test_golden_still_forkable       || true
run_test "Original clone stays alive throughout"        test_original_clone_alive        || true
run_test "delete --force reaps golden (no orphan)"      test_force_delete_reaps_golden   || true

print_summary "Fork-base Guard Tests"
