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

echo "========================================"
echo "  smolvm microVM Startup Benchmark"
echo "========================================"
echo ""
echo "Iterations: $ITERATIONS"
echo ""

# Check if smolvm is available
if ! command -v smolvm &> /dev/null; then
    # Try local build
    if [ -f "$PROJECT_ROOT/target/release/smolvm" ]; then
        SMOLVM="$PROJECT_ROOT/target/release/smolvm"
    elif [ -f "$PROJECT_ROOT/target/debug/smolvm" ]; then
        SMOLVM="$PROJECT_ROOT/target/debug/smolvm"
    else
        echo -e "${RED}Error: smolvm not found. Build with 'cargo build --release'${NC}"
        exit 1
    fi
else
    SMOLVM="smolvm"
fi

echo "Using: $SMOLVM"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    $SMOLVM machine stop 2>/dev/null || true
    # Kill any orphaned smolvm processes
    pkill -f "smolvm-bin machine" 2>/dev/null || true
    pkill -f "smolvm machine start" 2>/dev/null || true
}

# Ensure cleanup runs on exit (normal or error)
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
    # Ensure machine is stopped
    $SMOLVM machine stop 2>/dev/null || true
    sleep 0.5

    # Measure VM startup time (machine start returns when agent is ready)
    START_TIME=$(python3 -c "import time; print(time.time())")

    $SMOLVM machine start > /dev/null 2>&1

    END_TIME=$(python3 -c "import time; print(time.time())")

    DURATION=$(python3 -c "print(int(($END_TIME - $START_TIME) * 1000))")
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
    # Ensure machine is stopped
    $SMOLVM machine stop 2>/dev/null || true
    sleep 0.5

    # Measure from start to first successful command
    START_TIME=$(python3 -c "import time; print(time.time())")

    $SMOLVM machine start > /dev/null 2>&1
    $SMOLVM machine exec echo hello > /dev/null 2>&1

    END_TIME=$(python3 -c "import time; print(time.time())")

    DURATION=$(python3 -c "print(int(($END_TIME - $START_TIME) * 1000))")
    PING_TIMES+=($DURATION)

    echo "  Run $i: ${DURATION}ms"
done

# ============================================
# Results Summary
# ============================================
echo ""
echo "========================================"
echo "  Results Summary"
echo "========================================"

START_TIMES_STR=$(IFS=,; echo "${START_TIMES[*]}")
PING_TIMES_STR=$(IFS=,; echo "${PING_TIMES[*]}")

python3 << EOF
start_times = [$START_TIMES_STR]

ping_times = [$PING_TIMES_STR]

def stats(times, label):
    avg = sum(times) / len(times)
    min_t = min(times)
    max_t = max(times)
    variance = sum((t - avg) ** 2 for t in times) / len(times)
    std_dev = variance ** 0.5
    print(f"  {label}:")
    print(f"    Min:     {min_t}ms")
    print(f"    Max:     {max_t}ms")
    print(f"    Average: {avg:.1f}ms")
    print(f"    Std Dev: {std_dev:.1f}ms")
    return avg

print("")
start_avg = stats(start_times, "VM Cold Start (machine start)")
print("")
ping_avg = stats(ping_times, "VM Start + First Command")

print("")
print("----------------------------------------")
print("Breakdown:")
print("----------------------------------------")
print(f"  VM boot to agent ready:  {start_avg:.0f}ms")
print(f"  First command overhead:  {ping_avg - start_avg:.0f}ms")
EOF

echo ""
echo -e "${GREEN}Benchmark complete.${NC}"
echo ""

# Cleanup handled by trap
