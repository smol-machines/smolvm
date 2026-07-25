#!/bin/bash
# HIGH-N PAYOFF: the regime the fork pool exists for.
#
# Native holds one full model per learner (~7.4 GiB), so an 80 GiB card runs
# out at ~11 (measured: N=12 finished only 7/12, peaking at 81 GiB). With
# weight sharing repaired, a clone's marginal cost is ~1.6 GiB, so the same
# card should hold far more learners than native can.
#
# Runs native first (fails fast) then fork, strictly sequentially. Steps are
# short because this measures MEMORY CEILING and completion, not throughput.
set -u
cd "$(dirname "$0")"
LOG=~/highn_progress.log; : > "$LOG"
N=${N:-16}
STEPS=${STEPS:-10}

run() {
    echo "" | tee -a "$LOG"
    echo "########## $* ##########" | tee -a "$LOG"
    ./bench.sh "$@" 2>&1 | tee -a "$LOG" || echo "  (cell failed — recorded)" | tee -a "$LOG"
    for i in $(seq 1 40); do
        u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
        [[ "$u" -lt 500 ]] && break
        sleep 3
    done
    pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null
    pkill -f "_cuda-clone-worke[r]" 2>/dev/null
    sleep 3
}

echo "===== HIGH-N: native vs fork at N=$N =====" | tee -a "$LOG"
run --arm native --n "$N" --steps "$STEPS" --cpus 4 --timeout 1500
run --arm fork   --n "$N" --steps "$STEPS" --cpus 4 --timeout 1500

echo "" | tee -a "$LOG"
echo "HIGHN_DONE" | tee -a "$LOG"
