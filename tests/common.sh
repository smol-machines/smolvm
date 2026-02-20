#!/bin/bash
#
# Common test utilities for smolvm integration tests.
#
# Source this file in test scripts:
#   source "$(dirname "$0")/common.sh"

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Find the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find smolvm binary
find_smolvm() {
    if [[ -n "${SMOLVM:-}" ]] && [[ -x "$SMOLVM" ]]; then
        echo "$SMOLVM"
        return
    fi

    # Prefer cargo build output (latest build) over dist
    local target_release="$PROJECT_ROOT/target/release/smolvm"
    if [[ -x "$target_release" ]]; then
        echo "$target_release"
        return
    fi

    # Fall back to dist directory
    local dist_dir="$PROJECT_ROOT/dist"
    if [[ -d "$dist_dir" ]]; then
        # Find the extracted distribution directory
        local smolvm_dir=$(find "$dist_dir" -maxdepth 1 -type d \( -name 'smolvm-*-darwin-*' -o -name 'smolvm-*-linux-*' \) 2>/dev/null | head -1)
        if [[ -n "$smolvm_dir" ]] && [[ -x "$smolvm_dir/smolvm" ]]; then
            echo "$smolvm_dir/smolvm"
            return
        fi
    fi

    echo ""
}

# Initialize SMOLVM variable
init_smolvm() {
    SMOLVM=$(find_smolvm)

    # Resolve to absolute path (tests cd into temp dirs)
    if [[ -n "$SMOLVM" ]] && [[ "$SMOLVM" != /* ]]; then
        SMOLVM="$(cd "$(dirname "$SMOLVM")" && pwd)/$(basename "$SMOLVM")"
    fi

    if [[ -z "$SMOLVM" ]]; then
        echo -e "${RED}Error: Could not find smolvm binary${NC}"
        echo "Either:"
        echo "  1. Build and extract the distribution: ./scripts/build-dist.sh"
        echo "  2. Set SMOLVM environment variable to the binary path"
        exit 1
    fi

    # Set library path to ensure we use bundled libkrun/libkrunfw.
    # This is needed when running from target/release since the system
    # may not have libkrun on its default library search path.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local lib_dir="$PROJECT_ROOT/lib"
        if [[ -d "$lib_dir" ]]; then
            export DYLD_LIBRARY_PATH="${lib_dir}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
        fi
    else
        local lib_dir="$PROJECT_ROOT/lib/linux-$(uname -m)"
        if [[ -d "$lib_dir" ]]; then
            export LD_LIBRARY_PATH="${lib_dir}:${LD_LIBRARY_PATH:-}"
        fi
    fi

    echo "Using smolvm: $SMOLVM"
}

# Log helpers
log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $1"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Track failed test names for summary
FAILED_TESTS=()

# Run a test function
run_test() {
    local test_name="$1"
    local test_func="$2"

    ((TESTS_RUN++))
    log_test "$test_name"

    if $test_func; then
        log_pass "$test_name"
        return 0
    else
        log_fail "$test_name"
        FAILED_TESTS+=("$test_name")
        return 1
    fi
}

# Print test summary
print_summary() {
    local test_suite="${1:-Tests}"

    echo ""
    echo "=========================================="
    echo "  $test_suite Summary"
    echo "=========================================="
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"

    if [[ $TESTS_FAILED -gt 0 ]] && [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Failed tests:${NC}"
        for test_name in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} $test_name"
        done
    fi

    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        return 1
    fi
}

# Cleanup helper - stop microvm
cleanup_microvm() {
    $SMOLVM microvm stop 2>/dev/null || true
}

# Ensure microvm is running
ensure_microvm_running() {
    $SMOLVM microvm start 2>/dev/null || true
}

# Extract container ID from output
extract_container_id() {
    local output="$1"
    echo "$output" | grep -oE 'smolvm-[a-f0-9]+' | head -1
}

# Cleanup container by ID
cleanup_container() {
    local container_id="$1"
    $SMOLVM container rm default "$container_id" -f 2>/dev/null || true
}

# Run a command with a timeout (default 60 seconds).
# Usage: run_with_timeout [timeout_seconds] command [args...]
# Returns the command's exit code, or 124 if timed out.
# Output is written to stdout.
run_with_timeout() {
    local timeout_secs="${1:-60}"
    shift

    # Create temp file for output
    local tmpfile
    tmpfile=$(mktemp)

    # Run command in background, redirecting output to temp file
    "$@" > "$tmpfile" 2>&1 &
    local pid=$!

    # Wait with timeout
    local count=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        ((count++))
        if [[ $count -ge $timeout_secs ]]; then
            echo "[TIMEOUT] Command timed out after ${timeout_secs}s: $*" >&2
            # Kill the process and all its children
            kill -9 "$pid" 2>/dev/null
            pkill -9 -P "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            cat "$tmpfile"
            rm -f "$tmpfile"
            return 124
        fi
    done

    # Get exit code and output
    wait "$pid"
    local exit_code=$?
    cat "$tmpfile"
    rm -f "$tmpfile"
    return $exit_code
}

# Kill any orphaned smolvm processes that might be holding the database lock.
# This includes:
#   - smolvm serve (API server)
#   - smolvm-bin microvm start (VM processes from previous test runs)
#   - Packed binaries running as daemons
#
# Call this before running tests to ensure clean state.
kill_orphan_smolvm_processes() {
    local killed=0

    # Kill any smolvm serve processes
    if pkill -f "smolvm serve" 2>/dev/null; then
        ((killed++)) || true
    fi
    if pkill -f "smolvm-bin serve" 2>/dev/null; then
        ((killed++)) || true
    fi

    # Kill any orphaned microvm processes (from smolvm-bin in dist/)
    if pkill -f "smolvm-bin microvm start" 2>/dev/null; then
        ((killed++)) || true
    fi

    # Kill any orphaned microvm processes (from target/release)
    if pkill -f "smolvm microvm start" 2>/dev/null; then
        ((killed++)) || true
    fi

    # Wait briefly for processes to die
    if [[ $killed -gt 0 ]]; then
        sleep 1
    fi
}

# Check if any smolvm processes are running that might interfere with tests
check_smolvm_processes() {
    local procs
    procs=$(pgrep -f "(smolvm serve|smolvm-bin microvm start|smolvm microvm start)" 2>/dev/null || true)
    if [[ -n "$procs" ]]; then
        return 1  # Processes found
    fi
    return 0  # No interfering processes
}

# Ensure clean test environment - call at start of test suite
ensure_clean_test_environment() {
    # First, try to kill any orphan processes
    kill_orphan_smolvm_processes

    # Verify they're gone
    if ! check_smolvm_processes; then
        log_info "Warning: Some smolvm processes are still running after cleanup"
        log_info "Processes:"
        ps aux | grep -E "(smolvm serve|smolvm-bin microvm|smolvm microvm)" | grep -v grep || true
    fi
}
