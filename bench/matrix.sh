#!/bin/bash
# The two experiments that decide whether the fork architecture earns its cost.
#
# A. SCALE: raise N until VRAM binds. Native holds N copies (~7 GiB each), fork
#    holds N+1 (golden + one per clone), so native should survive to a higher N.
#    This is the regime the architecture is *for* — if weight sharing worked,
#    fork would keep going where native OOMs.
#
# B. KERNEL SIZE: raise batch/seq so each CUDA call does more work. If the fork
#    gap shrinks, the remoting cost is per-call launch latency (amortizable, so
#    the design is viable for realistic training shapes). If it stays flat, the
#    remoting cost is proportional and no shape escapes it.
#
# Runs strictly sequentially: the GPU must be exclusive or every number is junk.
set -u
cd "$(dirname "$0")"
LOG=~/matrix_progress.log; : > "$LOG"

run() {
    echo "" | tee -a "$LOG"
    echo "########## $* ##########" | tee -a "$LOG"
    # Never abort the matrix on one failed cell: an OOM IS the result we want.
    ./bench.sh "$@" 2>&1 | tee -a "$LOG" || echo "  (cell failed — recorded)" | tee -a "$LOG"
    # Let the GPU fully drain before the next cell's preflight check.
    for i in $(seq 1 30); do
        u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
        [[ "$u" -lt 500 ]] && break
        sleep 2
    done
    pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null
    pkill -f "_cuda-clone-worke[r]" 2>/dev/null
    sleep 3
}

echo "===== EXPERIMENT A: scale N until memory binds =====" | tee -a "$LOG"
run --arm native --n 8  --steps 20 --cpus 4 --timeout 600
run --arm fork   --n 8  --steps 20 --cpus 4 --timeout 600
run --arm native --n 12 --steps 20 --cpus 4 --timeout 600
run --arm fork   --n 12 --steps 20 --cpus 4 --timeout 600

echo "" | tee -a "$LOG"
echo "===== EXPERIMENT B: bigger kernels (batch 8 x seq 1024) =====" | tee -a "$LOG"
run --arm native --n 2 --steps 20 --cpus 4 --batch 8 --maxseq 1024 --timeout 600
run --arm fork   --n 2 --steps 20 --cpus 4 --batch 8 --maxseq 1024 --timeout 600

echo "" | tee -a "$LOG"
echo "MATRIX_DONE" | tee -a "$LOG"
