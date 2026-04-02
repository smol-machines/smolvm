#!/bin/bash
# Benchmark: microVM startup time
#
# Measures the time to start the smolvm agent VM from cold state.
# This includes: VM creation, kernel boot, init execution, agent ready.
#
# Usage: ./tests/bench_vm_startup.sh [iterations]
#    or: ./tests/run_all.sh bench-vm

set -euo pipefail

ITERATIONS="${1:-5}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Millisecond timestamp using bash builtin (no subprocess overhead)
now_ms() {
    # EPOCHREALTIME gives seconds.microseconds — convert to milliseconds
    local t="${EPOCHREALTIME}"
    local secs="${t%%.*}"
    local frac="${t#*.}"
    # Pad/truncate fractional part to 3 digits (milliseconds)
    frac="${frac:0:3}"
    echo $(( secs * 1000 + 10#$frac ))
}

echo "========================================"
echo "  smolvm microVM Startup Benchmark"
echo "========================================"
echo ""
echo "Iterations: $ITERATIONS"
echo ""

# Check if smolvm is available
if [[ -n "${SMOLVM:-}" ]] && [[ -x "$SMOLVM" ]]; then
    : # use provided SMOLVM
elif command -v smolvm &> /dev/null; then
    SMOLVM="smolvm"
elif [ -f "$PROJECT_ROOT/target/release/smolvm" ]; then
    SMOLVM="$PROJECT_ROOT/target/release/smolvm"
elif [ -f "$PROJECT_ROOT/target/debug/smolvm" ]; then
    SMOLVM="$PROJECT_ROOT/target/debug/smolvm"
else
    echo -e "${RED}Error: smolvm not found. Build with 'cargo build --release'${NC}"
    exit 1
fi

echo "Using: $SMOLVM"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    $SMOLVM machine stop 2>/dev/null || true
    pkill -f "smolvm-bin machine" 2>/dev/null || true
    pkill -f "smolvm machine start" 2>/dev/null || true
}

trap cleanup EXIT

# Kill any existing smolvm processes before benchmarking
echo "Cleaning up any existing smolvm processes..."
pkill -f "smolvm-bin machine" 2>/dev/null || true
pkill -f "smolvm machine start" 2>/dev/null || true
$SMOLVM machine stop 2>/dev/null || true
sleep 1

# ============================================
# Test 1: MicroVM Start (VM boot + agent ready)
# ============================================
echo -e "${BLUE}Test 1: VM Cold Start (machine start)${NC}"
echo "  Measures: fork → kernel boot → init → agent ready"
echo ""

declare -a START_TIMES

for i in $(seq 1 $ITERATIONS); do
    $SMOLVM machine stop 2>/dev/null || true
    sleep 0.5

    START_TIME=$(now_ms)
    $SMOLVM machine start > /dev/null 2>&1
    END_TIME=$(now_ms)

    DURATION=$(( END_TIME - START_TIME ))
    START_TIMES+=($DURATION)
    echo "  Run $i: ${DURATION}ms"
done

# ============================================
# Test 2: MicroVM Start + First Command
# ============================================
echo ""
echo -e "${BLUE}Test 2: VM Start + First Command (exec)${NC}"
echo "  Measures: cold start + first vsock round-trip"
echo ""

declare -a PING_TIMES

for i in $(seq 1 $ITERATIONS); do
    $SMOLVM machine stop 2>/dev/null || true
    sleep 0.5

    START_TIME=$(now_ms)
    $SMOLVM machine start > /dev/null 2>&1
    $SMOLVM machine exec -- echo hello > /dev/null 2>&1
    END_TIME=$(now_ms)

    DURATION=$(( END_TIME - START_TIME ))
    PING_TIMES+=($DURATION)
    echo "  Run $i: ${DURATION}ms"
done

# ============================================
# Results Summary (pure bash — no Python)
# ============================================
stats() {
    local label="$1"
    shift
    local times=("$@")
    local n=${#times[@]}
    local sum=0 min=${times[0]} max=${times[0]}

    for t in "${times[@]}"; do
        (( sum += t ))
        (( t < min )) && min=$t
        (( t > max )) && max=$t
    done

    local avg=$(( sum / n ))
    # Standard deviation (integer approximation)
    local var_sum=0
    for t in "${times[@]}"; do
        local diff=$(( t - avg ))
        (( var_sum += diff * diff ))
    done
    local variance=$(( var_sum / n ))
    # Integer square root approximation
    local std_dev=0
    if (( variance > 0 )); then
        std_dev=1
        while (( std_dev * std_dev < variance )); do
            (( std_dev++ ))
        done
    fi

    echo "  $label:"
    echo "    Min:     ${min}ms"
    echo "    Max:     ${max}ms"
    echo "    Average: ${avg}ms"
    echo "    Std Dev: ~${std_dev}ms"
    # Return average via global
    _STAT_AVG=$avg
}

echo ""
echo "========================================"
echo "  Results Summary"
echo "========================================"
echo ""

stats "VM Cold Start (machine start)" "${START_TIMES[@]}"
START_AVG=$_STAT_AVG

echo ""
stats "VM Start + First Command" "${PING_TIMES[@]}"
PING_AVG=$_STAT_AVG

echo ""
echo "----------------------------------------"
echo "Breakdown:"
echo "----------------------------------------"
echo "  VM boot to agent ready:  ${START_AVG}ms"
echo "  First command overhead:  $(( PING_AVG - START_AVG ))ms"

echo ""
echo -e "${GREEN}Benchmark complete.${NC}"
echo ""
