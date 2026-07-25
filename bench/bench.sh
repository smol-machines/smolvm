#!/bin/bash
# Reproducible A/B: the SAME post-training workload run two ways on one GPU.
#
#   native — N learner processes on bare metal, each loading its own base
#   fork   — one smolvm golden VM loads the base once, then N --share-weights
#            clones, CUDA remoted to the host daemon
#
# Both arms run the identical workload file (workload_dpo.py) with identical
# STEPS/BATCH/MAXSEQ/MODEL/seed, and are measured identically (wall clock from
# t0 to last learner done, 1 Hz nvidia-smi peak sampling, per-learner tok/s from
# the workload's own JSONL). Results append to results/<run-id>.json.
#
# FAIRNESS KNOBS (the confounds that made the first ad-hoc comparison invalid):
#   --cpus K   pin EACH native learner to its own K-core set, matching the
#              per-VM vCPU count in the fork arm. Default 4 = fork parity.
#              Use --cpus 0 to leave native unpinned (whole host).
#   --cold     drop the page cache before the run (default: warm, i.e. the
#              model file is pre-read so neither arm pays first-touch disk I/O)
#   --reps R   repeat R times; summarize.py reports the median and the spread
#              (the golden load is known to be bimodal ~15s vs ~156s)
#
# Usage: ./bench.sh --arm native|fork --n 4 [--steps 20] [--reps 3] [--cpus 4]
#        [--cold] [--share on|off|default] [--batch 2] [--maxseq 256]
set -u

ARM=""; N=4; STEPS=20; REPS=1; CPUS=4; COLD=0; BATCH=2; MAXSEQ=256; TIMEOUT=600; SHARE=default
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arm) ARM="$2"; shift 2 ;;
        --n) N="$2"; shift 2 ;;
        --steps) STEPS="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --cold) COLD=1; shift ;;
        --batch) BATCH="$2"; shift 2 ;;
        --maxseq) MAXSEQ="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        # on|off|default — sets SMOLVM_CUDA_FORK_SHARE_WEIGHTS for the run and
        # VERIFIES the daemon actually honoured it (see check_share_mode).
        --share) SHARE="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done
[[ "$ARM" == "native" || "$ARM" == "fork" ]] || { echo "need --arm native|fork"; exit 2; }

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$BENCH_DIR/results"; mkdir -p "$RESULTS"
WORKLOAD="$BENCH_DIR/workload_dpo.py"
MODEL="${MODEL:-unsloth/Qwen2.5-7B-bnb-4bit}"
PY_VENV="${PY_VENV:-$HOME/ptwork/bin/python}"
S="${SMOLVM:-$HOME/smolvm/smolvm}"
export SMOLVM_LIB_DIR="${SMOLVM_LIB_DIR:-$HOME/smolvm/lib/linux-x86_64}"
SOCK=/tmp/smolvm/cuda-daemon.sock
PACK="${PACK:-$HOME/qlora-baked.smolmachine}"
# expandable_segments:True makes torch allocate via CUDA VMM, which bypasses
# the daemon alloc-table that marks weight ranges "loaded" -> fork weight
# sharing degrades to private copies. Override to test the sharing path.
ALLOC_CONF="${ALLOC_CONF:-expandable_segments:True}"

# ---------------------------------------------------------------- preconditions
# A leaked context or a live clone from a previous run silently changes both
# load time and peak memory, so refuse to measure until the box is clean.
preflight() {
    local used
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    if [[ "$used" -gt 500 ]]; then
        echo "PREFLIGHT FAIL: GPU already using ${used} MiB (leaked context?). Aborting."
        nvidia-smi --query-compute-apps=pid,used_memory --format=csv | head
        exit 1
    fi
    pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null
    pkill -f "_cuda-clone-worke[r]" 2>/dev/null
    # --cascade removes a golden together with its clones (no name guessing).
    $S machine rm --name bench-g --cascade >/dev/null 2>&1
    for m in $($S machine list 2>/dev/null | awk '/^bench-/{print $1}'); do
        $S machine rm --name "$m" --force >/dev/null 2>&1
    done
    rm -f "$SOCK"
    if [[ "$COLD" == "1" ]]; then
        sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1 || echo "  (cache drop needs sudo; continuing warm)"
    else
        # Warm both arms identically: page in the model weights once.
        find "$HOME/hf" -name "*.safetensors" -exec cat {} + > /dev/null 2>&1
    fi
}

# Environment manifest: everything that could move a number between runs.
manifest() {
    python3 - "$@" <<'PY'
import json, subprocess, sys, os
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception: return None
print(json.dumps({
  "smolvm_version": sh(f"{sys.argv[1]} --version"),
  "smolvm_binary_md5": sh(f"md5sum {sys.argv[1]} | cut -d' ' -f1"),
  "proto_hash_rootfs": sh("cat ~/.local/share/smolvm/agent-rootfs/usr/local/lib/smolvm-cuda/proto-hash"),
  "shim_md5": sh("md5sum ~/.local/share/smolvm/agent-rootfs/usr/local/lib/smolvm-cuda/libcudart-shim.so | cut -d' ' -f1"),
  "driver": sh("nvidia-smi --query-gpu=driver_version --format=csv,noheader"),
  "gpu": sh("nvidia-smi --query-gpu=name --format=csv,noheader"),
  "torch": sh(f"{sys.argv[2]} -c 'import torch;print(torch.__version__)'"),
  "host_cores": os.cpu_count(),
  "host_mem_gb": round(os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES')/1e9),
}))
PY
}

# 1 Hz peak sampler; writes the max MiB seen to $1 when told to stop via $2.
sample_gpu() {
    local out="$1" stopflag="$2" maxv=0 v
    while [[ ! -f "$stopflag" ]]; do
        v=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null)
        [[ "$v" -gt "$maxv" ]] 2>/dev/null && maxv=$v
        sleep 1
    done
    echo "$maxv" > "$out"
}

# ---------------------------------------------------------------------- arms
run_native() {
    local CO="$1"
    export HF_HOME=$HOME/hf HF_HUB_OFFLINE=1 COORD=$CO ARM=native FORK=0 OUTBASE=$CO
    export STEPS=$STEPS MODEL=$MODEL BATCH=$BATCH MAXSEQ=$MAXSEQ
    export PYTORCH_CUDA_ALLOC_CONF="$ALLOC_CONF" TORCHINDUCTOR_COMPILE_THREADS=1
    # Collect the learner PIDs and wait on THOSE only: a bare `wait` would also
    # block on the GPU sampler running in this same shell, which by design does
    # not exit until after this function returns (deadlock).
    local pids=()
    for i in $(seq 0 $((N-1))); do
        if [[ "$CPUS" -gt 0 ]]; then
            # Give each learner its own K-core set, mirroring one VM's vCPUs.
            local nproc_n cores
            nproc_n=$(nproc)
            cores=$(python3 -c "print(','.join(str(($i*$CPUS+k) % $nproc_n) for k in range($CPUS)))")
            LEARNER_ID=$i taskset -c "$cores" "$PY_VENV" "$CO/dpo_train.py" > "$CO/o$i.log" 2>"$CO/e$i.log" &
        else
            LEARNER_ID=$i "$PY_VENV" "$CO/dpo_train.py" > "$CO/o$i.log" 2>"$CO/e$i.log" &
        fi
        pids+=($!)
    done
    wait "${pids[@]}"
}

run_fork() {
    local CO="$1"
    # Set the mode explicitly rather than relying on ambient env: an arm that
    # silently runs the wrong configuration is worse than no arm at all (this
    # bit me — a "copy mode" control that actually shared, because the variable
    # never reached the daemon). check_share_mode below proves what ran.
    case "$SHARE" in
        on)  export SMOLVM_CUDA_FORK_SHARE_WEIGHTS=1 ;;
        off) export SMOLVM_CUDA_FORK_SHARE_WEIGHTS=0 ;;
        default) unset SMOLVM_CUDA_FORK_SHARE_WEIGHTS ;;
        *) echo "bad --share: $SHARE (want on|off|default)"; exit 2 ;;
    esac
    env SMOLVM_CUDA_FORK_WORKERS=1 SMOLVM_CUDA_FORK_ISOLATE=1 SMOLVM_CUDA_DAEMON_IDLE_SECS=0 \
        RUST_LOG=warn,smolvm::cuda_daemon=info "$S" _cuda-daemon "$SOCK" > "$CO/daemon.log" 2>&1 &
    for i in $(seq 1 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
    # No manual CUDA env: smolvm injects SMOLVM_CUDA_ZEROCOPY and stages the
    # guest shims (libcuda.so.1 + the unversioned dev names) itself.
    # Optional guest-side prelude (e.g. `unset SMOLVM_CUDA_ZEROCOPY;`) so a run
    # can disable the zero-copy upload path, whose crc=0 coverage makes every
    # weight chunk unshareable.
    local GUEST="${BENCH_GUEST_EXTRA:-} export HF_HOME=/opt/hfcache HF_HUB_OFFLINE=0 COORD=/opt/coord ARM=fork FORK=1 \
STEPS=$STEPS NSLOTS=$N MODEL=$MODEL OUTBASE=/root BATCH=$BATCH MAXSEQ=$MAXSEQ \
PYTORCH_CUDA_ALLOC_CONF=$ALLOC_CONF TORCHINDUCTOR_COMPILE_THREADS=1; \
/home/ubuntu/ptwork/bin/python /opt/coord/dpo_train.py 2>>/opt/coord/g.err"
    $S machine create --name bench-g --cuda --net -v "$CO:/opt/coord:rw" \
        --from "$PACK" --storage 30 --overlay 20 -- sh -c "$GUEST" >/dev/null 2>&1
    env SMOLVM_CUDA_SHARED=1 $S machine start --forkable --name bench-g >/dev/null 2>&1
    local tgold
    for i in $(seq 1 300); do [[ -f "$CO/golden_ready" ]] && break; sleep 1; done
    [[ -f "$CO/golden_ready" ]] || { echo "GOLDEN-LOAD-FAILED"; return 1; }
    tgold=$(date +%s.%N); echo "$tgold" > "$CO/.t_golden"
    for c in $(seq 0 $((N-1))); do
        $S machine fork --golden bench-g --name bench-c$c --share-weights >/dev/null 2>&1
    done
    echo "$(date +%s.%N)" > "$CO/.t_forked"
    touch "$CO/go"
    local deadline=$(( $(date +%s) + TIMEOUT ))
    while [[ "$(grep -l '"event": "done"' "$CO"/learner_*.jsonl 2>/dev/null | wc -l)" -lt "$N" ]]; do
        [[ $(date +%s) -ge $deadline ]] && { echo "  TIMEOUT after ${TIMEOUT}s (learners still unfinished)"; break; }
        sleep 2
    done
    check_share_mode "$CO"
    $S machine rm --name bench-g --cascade >/dev/null 2>&1
    pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null; pkill -f "_cuda-clone-worke[r]" 2>/dev/null
}

# The daemon logs "M2: shared weight ranges shared=<n> private=<m>" per clone.
# Confirm it agrees with --share, so a result can never be attributed to a mode
# that did not actually run.
check_share_mode() {
    local CO="$1" line shared
    line=$(grep -o "shared=[0-9]* private=[0-9]*" "$CO/daemon.log" 2>/dev/null | tail -1)
    shared=$(echo "$line" | sed -E "s/shared=([0-9]*).*/\1/")
    echo "  share-mode requested=$SHARE  daemon reported: ${line:-<none>}"
    if [[ "$SHARE" == "off" && "${shared:-0}" -gt 0 ]]; then
        echo "  !! CONTROL FAILED: asked for copy mode but the daemon shared $shared ranges"
    elif [[ "$SHARE" == "on" && "${shared:-0}" -eq 0 ]]; then
        echo "  !! SHARING DID NOT ENGAGE: asked to share but the daemon shared 0 ranges"
    fi
}

# ---------------------------------------------------------------------- driver
MF=$(manifest "$S" "$PY_VENV")
for rep in $(seq 1 "$REPS"); do
    RUNID="${ARM}_n${N}_s${STEPS}_c${CPUS}_$(date +%Y%m%d-%H%M%S)_r${rep}"
    CO="$HOME/bench_run/$RUNID"; rm -rf "$CO"; mkdir -p "$CO"; cp "$WORKLOAD" "$CO/dpo_train.py"
    echo "=== $RUNID (arm=$ARM n=$N steps=$STEPS cpus=$CPUS cold=$COLD) ==="
    preflight
    STOP="$CO/.stop"; PEAK="$CO/.peak"; rm -f "$STOP"
    sample_gpu "$PEAK" "$STOP" &
    SAMPLER=$!
    T0=$(date +%s.%N)
    if [[ "$ARM" == "native" ]]; then run_native "$CO"; else run_fork "$CO"; fi
    T1=$(date +%s.%N)
    touch "$STOP"; wait $SAMPLER 2>/dev/null
    WALL=$(echo "$T1 - $T0" | bc)
    GOLD=""; [[ -f "$CO/.t_golden" ]] && GOLD=$(echo "$(cat "$CO/.t_golden") - $T0" | bc)
    FORKED=""; [[ -f "$CO/.t_forked" ]] && FORKED=$(echo "$(cat "$CO/.t_forked") - $(cat "$CO/.t_golden")" | bc)
    SHARE_RECORD="$SHARE" SHARED_RANGES="$(grep -o 'shared=[0-9]*' "$CO/daemon.log" 2>/dev/null | tail -1 | cut -d= -f2)" BATCH_RECORD="$BATCH" MAXSEQ_RECORD="$MAXSEQ" ALLOC_CONF_RECORD="$ALLOC_CONF" SW_RECORD="${SMOLVM_CUDA_FORK_SHARE_WEIGHTS:-unset}" python3 - "$CO" "$RESULTS/$RUNID.json" "$ARM" "$N" "$STEPS" "$CPUS" "$COLD" "$WALL" "${GOLD:-null}" "${FORKED:-null}" "$(cat "$PEAK" 2>/dev/null || echo 0)" "$MF" <<'PY'
import sys, json, glob
co, out, arm, n, steps, cpus, cold, wall, gold, forked, peak, mf = sys.argv[1:13]
learners = []
for f in sorted(glob.glob(f"{co}/learner_*.jsonl")):
    d = {}
    for line in open(f):
        e = json.loads(line); d[e["event"]] = e
    if "done" in d:
        z = d["done"]
        learners.append({k: z.get(k) for k in ("lid","tok_s","train_s","step_ms","loss0","lossN","peak_gb")})
rec = {
  "arm": arm, "n": int(n), "steps": int(steps), "cpus_per_learner": int(cpus),
  "cold_cache": bool(int(cold)),
  "alloc_conf": __import__("os").environ.get("ALLOC_CONF_RECORD", ""),
  "batch": int(__import__("os").environ.get("BATCH_RECORD", "0")),
  "maxseq": int(__import__("os").environ.get("MAXSEQ_RECORD", "0")),
  "share_weights_env": __import__("os").environ.get("SW_RECORD", ""),
  "share_mode": __import__("os").environ.get("SHARE_RECORD", ""),
  "shared_ranges": __import__("os").environ.get("SHARED_RANGES", ""),
  "wall_s": round(float(wall), 2),
  "golden_load_s": None if gold == "null" else round(float(gold), 2),
  "fork_s": None if forked == "null" else round(float(forked), 2),
  "peak_gpu_mib": int(peak),
  "learners_done": len(learners), "learners_expected": int(n),
  "agg_tok_s": sum(l["tok_s"] for l in learners if l["tok_s"]),
  "learners": learners,
  "env": json.loads(mf),
}
json.dump(rec, open(out, "w"), indent=2)
print(f"  wall={rec['wall_s']}s done={rec['learners_done']}/{n} agg_tok_s={rec['agg_tok_s']} peak_gpu={rec['peak_gpu_mib']}MiB" + (f" golden_load={rec['golden_load_s']}s" if rec["golden_load_s"] else ""))
print(f"  -> {out}")
PY
done
