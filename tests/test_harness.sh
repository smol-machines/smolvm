#!/usr/bin/env bash
#
# Test Harness Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_harness.sh
#
# Covers common.sh itself. Its counters are incremented under `set -euo pipefail`,
# where the `((x++))` arithmetic command exits 1 on the first increment of a
# zero-initialized counter (post-increment yields the OLD value as the status).
# That aborted every suite at its first passing test, which read as the feature
# under test failing rather than as a harness fault.
#
# Probe suites run as subprocesses so these assertions hold regardless of what
# the harness does in-process; this file therefore carries its own small runner
# rather than sourcing common.sh.
#
# Pure harness test: no smolvm binary, no VM, no network.
#

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; FAILED_TESTS=()

run_test() {
    local test_name="$1" test_func="$2" output
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${YELLOW}[TEST]${NC} $test_name"
    if output=$($test_func 2>&1); then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}[PASS]${NC} $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        echo -e "${RED}[FAIL]${NC} $test_name"
        [[ -n "$output" ]] && echo "$output" | sed 's/^/    /'
    fi
}

# Write a probe suite that sources common.sh, and run it as a subprocess.
# Prints its output; returns its exit status.
run_probe() {
    local body="$1"
    local probe
    probe="$(mktemp "${TMPDIR:-/tmp}/smolvm-probe-XXXXXX.sh")"
    {
        echo "source \"$TESTS_DIR/common.sh\""
        echo "$body"
    } > "$probe"
    # Strip ANSI colors: print_summary wraps its counts in escapes, so a literal
    # "Tests passed: 2" would never match.
    bash "$probe" 2>&1 | sed $'s/\033\\[[0-9;]*m//g'
    local rc=${PIPESTATUS[0]}
    rm -f "$probe"
    return $rc
}

# Deliberately WITHOUT `|| true`: this is the case the counter fix enables. Before
# it, the suite died inside log_pass on the first pass, so only one test ran.
test_all_passing_tests_run() {
    local output rc=0
    output=$(run_probe '
t_ok() { return 0; }
run_test "first" t_ok
run_test "second" t_ok
run_test "third" t_ok
print_summary "Probe"
') || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "probe exited $rc, want 0"
        echo "$output"
        return 1
    fi
    if ! grep -q "Tests run:    3" <<<"$output"; then
        echo "expected all 3 tests to run; got:"
        echo "$output"
        return 1
    fi
    return 0
}

# A failing test makes run_test return 1 by design, so suites carry it past that
# with `|| true` — the idiom 338 of the 345 call sites in tests/ already use.
test_failing_test_is_counted_without_aborting() {
    local output rc=0
    output=$(run_probe '
t_ok() { return 0; }
t_bad() { return 1; }
run_test "passes" t_ok || true
run_test "fails" t_bad || true
run_test "also passes" t_ok || true
print_summary "Probe"
') || rc=$?

    # A suite with a failure must still exit non-zero...
    if [[ $rc -eq 0 ]]; then
        echo "probe exited 0, want non-zero for a suite containing a failure"
        return 1
    fi
    # ...but every test must have run, and the counts must be right.
    local expect
    for expect in "Tests run:    3" "Tests passed: 2" "Tests failed: 1"; do
        if ! grep -q "$expect" <<<"$output"; then
            echo "missing '$expect' in summary:"
            echo "$output"
            return 1
        fi
    done
    return 0
}

# run_with_timeout polls in a loop whose counter also starts at zero.
test_run_with_timeout_survives_its_poll_counter() {
    local output rc=0
    output=$(run_probe '
run_with_timeout 10 sleep 2
echo "REACHED_AFTER_TIMEOUT_HELPER"
') || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "probe exited $rc, want 0"
        echo "$output"
        return 1
    fi
    if ! grep -q "REACHED_AFTER_TIMEOUT_HELPER" <<<"$output"; then
        echo "run_with_timeout aborted the shell before returning:"
        echo "$output"
        return 1
    fi
    return 0
}

# A suite that skips its setup reports "no tests ran" rather than failing.
test_empty_suite_is_not_a_failure() {
    local output rc=0
    output=$(run_probe 'print_summary "Probe"') || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "an empty suite should exit 0, got $rc"
        echo "$output"
        return 1
    fi
    return 0
}

echo ""
echo "=========================================="
echo "  Test Harness Tests"
echo "=========================================="
echo ""

run_test "All passing tests run" test_all_passing_tests_run
run_test "Failing test is counted without aborting" test_failing_test_is_counted_without_aborting
run_test "run_with_timeout survives its poll counter" test_run_with_timeout_survives_its_poll_counter
run_test "Empty suite is not a failure" test_empty_suite_is_not_a_failure

echo ""
echo "=========================================="
echo "  Test Harness Tests Summary"
echo "=========================================="
echo ""
echo "Tests run:    $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    printf "  ${RED}✗${NC} %s\n" "${FAILED_TESTS[@]}"
    exit 1
fi
echo ""
echo -e "${GREEN}All tests passed!${NC}"
