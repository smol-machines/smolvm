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

# Resolve a hostname to a single IPv4 address on the host, portably across
# Linux and macOS. Linux glibc has `getent`; macOS does not, so fall back to
# dig/python3/host (all present on a stock macOS or with bind tools). Prints the
# IP on stdout, or nothing if resolution fails.
resolve_host_ipv4() {
    local host="$1" ip=""
    if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
    fi
    if [[ -z "$ip" ]] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +short "$host" A 2>/dev/null | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$')
    fi
    if [[ -z "$ip" ]] && command -v python3 >/dev/null 2>&1; then
        ip=$(python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "$host" 2>/dev/null)
    fi
    if [[ -z "$ip" ]] && command -v host >/dev/null 2>&1; then
        ip=$(host -t A "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
    fi
    printf '%s' "$ip"
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

# Fail-fast mode: stop on first failure.
# Set FAIL_FAST=1 or use TEST_FILTER with run_tests.sh.
FAIL_FAST="${FAIL_FAST:-0}"

# Single test filter: only run tests whose name contains this string.
# Usage: TEST_FILTER="port mapping" ./tests/run_tests.sh ports
TEST_FILTER="${TEST_FILTER:-}"

# Skip slow tests (≥25s intentional sleeps) when SMOLVM_SKIP_SLOW=1.
# Usage inside a test function: skip_if_slow && return 0
SMOLVM_SKIP_SLOW="${SMOLVM_SKIP_SLOW:-0}"

skip_if_slow() {
    if [[ "$SMOLVM_SKIP_SLOW" == "1" ]]; then
        log_skip "slow test skipped (SMOLVM_SKIP_SLOW=1)"
        return 0
    fi
    return 1
}

# Run a test function, capturing output and showing it on failure.
run_test() {
    local test_name="$1"
    local test_func="$2"

    # Skip if filter is set and test name doesn't match
    if [[ -n "$TEST_FILTER" ]] && [[ "$test_name" != *"$TEST_FILTER"* ]]; then
        return 0
    fi

    # Skip remaining tests if fail-fast triggered
    if [[ "$FAIL_FAST" == "1" ]] && [[ $TESTS_FAILED -gt 0 ]]; then
        return 0
    fi

    ((TESTS_RUN++))
    log_test "$test_name"

    local output_file
    output_file=$(mktemp)

    if $test_func 2>&1 | tee "$output_file"; then
        log_pass "$test_name"
        rm -f "$output_file"
        return 0
    else
        log_fail "$test_name"
        FAILED_TESTS+=("$test_name")

        # Show last 10 lines on failure (may already be visible, but
        # repeating under the FAIL marker makes it easy to find)
        local output
        output=$(tail -10 "$output_file" 2>/dev/null || true)
        if [[ -n "$output" ]]; then
            echo -e "  ${RED}Error output:${NC}"
            echo "$output" | sed 's/^/    /'
        fi
        rm -f "$output_file"

        if [[ "$FAIL_FAST" == "1" ]]; then
            echo -e "\n${RED}Stopping: --fail-fast is set${NC}"
        fi
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

# Get the data directory for a named machine.
#
# Delegates to `smolvm machine data-dir --name <name>` so the test helper never
# duplicates the hash logic. If Rust changes the on-disk layout, the test
# suite automatically picks it up via this CLI call.
vm_data_dir() {
    local name="${1:-default}"
    $SMOLVM machine data-dir --name "$name" 2>/dev/null
}

# Cleanup helper - stop machine and remove named "default" from DB
# so tests start from a clean slate (no leftover DB records from
# manual testing or previous test runs).
cleanup_machine() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
}

# Verify that a VM's data directory was removed after deletion.
# Returns non-zero if the directory still exists.
ensure_data_dir_deleted() {
    local name="${1:?vm name required}"
    local data_dir
    data_dir=$(vm_data_dir "$name")
    if [[ -d "$data_dir" ]]; then
        echo -e "${RED}ERROR: data directory still exists after delete: $data_dir${NC}" >&2
        return 1
    fi
}

# Ensure machine is running and reachable.
# If net=true, recreate with --net (needed for container image pulls).
# Handles stale "already running" state from previous tests by verifying
# connectivity and doing a full cleanup cycle if the VM is unreachable.
ensure_machine_running() {
    local with_net="${1:-false}"
    if [[ "$with_net" == "true" ]]; then
        # Stop and delete existing default VM, recreate with --net
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete --name default -f 2>/dev/null || true
        $SMOLVM machine create --name default --net 2>/dev/null || true
    fi
    $SMOLVM machine start 2>/dev/null || true

    # Verify the VM is actually reachable. If it reports "running" but
    # the process is dead (stale PID), do a full cleanup and restart.
    if ! $SMOLVM machine exec -- true 2>/dev/null; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete --name default -f 2>/dev/null || true
        if [[ "$with_net" == "true" ]]; then
            $SMOLVM machine create --name default --net 2>/dev/null || true
        fi
        $SMOLVM machine start 2>/dev/null || true
    fi
}

# Poll until a VM responds to exec (i.e., the agent is ready to accept commands).
# Replaces fixed sleep N readiness waits after machine start.
#
# Usage: wait_vm_ready [--name NAME] [TIMEOUT_SECS]
#   --name NAME   Named VM (default: unnamed default VM)
#   TIMEOUT_SECS  Give up after this many seconds (default: 10)
#
# Returns 0 when ready, 1 on timeout.
wait_vm_ready() {
    local name_flag="" timeout=10
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name_flag="--name $2"; shift 2 ;;
            *)      timeout="$1"; shift ;;
        esac
    done
    local i=0
    while [[ $i -lt $((timeout * 2)) ]]; do
        $SMOLVM machine exec $name_flag -- true 2>/dev/null && return 0
        sleep 0.5
        ((i++)) || true
    done
    return 1
}

# Extract container ID from output
extract_container_id() {
    local output="$1"
    echo "$output" | grep -oE 'smolvm-[a-f0-9]+' | head -1
}

# Cleanup container by ID
cleanup_container() {
    local container_id="$1"
    $SMOLVM container rm --container "$container_id" -f 2>/dev/null || true
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
#   - smolvm-bin machine start (VM processes from previous test runs)
#   - Packed binaries running as daemons
#
# When SMOLVM_ORCHESTRATED=1 (set by run_tests.sh), this is a no-op: the
# orchestrator does a single pre-flight kill before launching any suites, so
# per-suite kills are skipped to avoid parallel suites killing each other's
# in-flight VM starts.
#
# Call this before running tests to ensure clean state.
kill_orphan_smolvm_processes() {
    if [[ "${SMOLVM_ORCHESTRATED:-0}" == "1" ]]; then
        return 0
    fi
    local killed=0

    # Kill any smolvm serve processes
    if pkill -f "smolvm serve" 2>/dev/null; then
        ((killed++)) || true
    fi
    if pkill -f "smolvm-bin serve" 2>/dev/null; then
        ((killed++)) || true
    fi

    # Kill any orphaned machine processes (from smolvm-bin in dist/)
    if pkill -f "smolvm-bin machine start" 2>/dev/null; then
        ((killed++)) || true
    fi

    # Kill any orphaned machine processes (from target/release)
    if pkill -f "smolvm machine start" 2>/dev/null; then
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
    procs=$(pgrep -f "(smolvm serve|smolvm-bin machine start|smolvm machine start)" 2>/dev/null || true)
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
        ps aux | grep -E "(smolvm serve|smolvm-bin machine|smolvm machine)" | grep -v grep || true
    fi
}
