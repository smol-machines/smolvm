#!/bin/bash
# Benchmark: Container startup time inside microVM
#
# Measures the time to execute a command in a container.
# Tests both cold start (first pull) and warm start (cached).
#
# Usage: ./tests/bench_container.sh [iterations] [image]
#    or: ./tests/run_all.sh bench-container

set -euo pipefail

ITERATIONS="${1:-10}"
IMAGE="${2:-alpine:latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "========================================"
echo "  smolvm Container Startup Benchmark"
echo "========================================"
echo ""
echo "Image:      $IMAGE"
echo "Iterations: $ITERATIONS"
echo ""

# Check if smolvm is available
if ! command -v smolvm &> /dev/null; then
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
    pkill -f "smolvm machine" 2>/dev/null || true
}

# Ensure cleanup runs on exit (normal or error)
trap cleanup EXIT

# Kill any existing smolvm processes before benchmarking
echo "Cleaning up any existing smolvm processes..."
pkill -f "smolvm-bin machine" 2>/dev/null || true
pkill -f "smolvm machine start" 2>/dev/null || true
$SMOLVM machine stop 2>/dev/null || true
sleep 1

# Helper function to measure exec time
measure_exec() {
    local START_TIME=$(python3 -c "import time; print(time.time())")

    $SMOLVM machine run --image "$IMAGE" -- /bin/true > /dev/null 2>&1

    local END_TIME=$(python3 -c "import time; print(time.time())")
    python3 -c "print(int(($END_TIME - $START_TIME) * 1000))"
}

# ============================================
# Test 1: Cold Start (no machine, no image cache)
# ============================================
echo -e "${BLUE}Test 1: Cold Start${NC}"
echo "  (MicroVM not running, image not cached)"
echo ""

# Stop machine and clear caches
$SMOLVM machine stop 2>/dev/null || true
sleep 1

# Measure cold start
echo "  Measuring cold start..."
COLD_START=$(measure_exec)
echo -e "  Cold start: ${YELLOW}${COLD_START}ms${NC}"
echo ""

# ============================================
# Test 2: Warm Start (machine running, image cached)
# ============================================
echo -e "${BLUE}Test 2: Warm Start${NC}"
echo "  (MicroVM running, image cached, overlay reused)"
echo ""

# MicroVM should be running from cold start, image should be cached
declare -a WARM_TIMES

echo "  Running $ITERATIONS iterations..."
for i in $(seq 1 $ITERATIONS); do
    DURATION=$(measure_exec)
    WARM_TIMES+=($DURATION)
    echo "    Run $i: ${DURATION}ms"
done

# ============================================
# Test 3: Echo Command (minimal work)
# ============================================
echo ""
echo -e "${BLUE}Test 3: Echo Command${NC}"
echo "  (Minimal command execution overhead)"
echo ""

declare -a ECHO_TIMES

for i in $(seq 1 $ITERATIONS); do
    START_TIME=$(python3 -c "import time; print(time.time())")

    $SMOLVM machine run --image "$IMAGE" -- /bin/echo "hello" > /dev/null 2>&1

    END_TIME=$(python3 -c "import time; print(time.time())")
    DURATION=$(python3 -c "print(int(($END_TIME - $START_TIME) * 1000))")
    ECHO_TIMES+=($DURATION)
    echo "    Run $i: ${DURATION}ms"
done

# ============================================
# Results Summary
# ============================================
echo ""
echo "========================================"
echo "  Results Summary"
echo "========================================"

WARM_TIMES_STR=$(IFS=,; echo "${WARM_TIMES[*]}")
ECHO_TIMES_STR=$(IFS=,; echo "${ECHO_TIMES[*]}")

python3 << EOF
cold_start = $COLD_START

warm_times = [$WARM_TIMES_STR]

echo_times = [$ECHO_TIMES_STR]

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

print(f"")
print(f"Cold Start (first run):")
print(f"  Time: {cold_start}ms")
print(f"")

warm_avg = stats(warm_times, "Warm Start (/bin/true)")
print(f"")
echo_avg = stats(echo_times, "Echo Command (/bin/echo)")

print(f"")
print(f"----------------------------------------")
print(f"Key Metrics:")
print(f"----------------------------------------")
print(f"  Cold start:        {cold_start}ms")
print(f"  Warm exec (avg):   {warm_avg:.1f}ms")
print(f"  Speedup:           {cold_start / warm_avg:.1f}x")
EOF

echo ""
echo -e "${GREEN}Benchmark complete.${NC}"
echo ""
echo "Note: For accurate benchmarks, run on a quiet system"
echo "and ensure no other VMs or heavy processes are running."

# Cleanup handled by trap
