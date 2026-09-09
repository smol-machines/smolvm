#!/bin/bash
# Boots a golden VM that loads a model with Unsloth and freezes, then forks
# three clones that each fine-tune a different task concurrently.
#
#   ./demo.sh [model]        (default unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit)
#
# Requirements: see README.md. `machine start --forkable` enables CUDA forking;
# the one env var below opts into cross-clone weight sharing.
set -u
MODEL=${1:-unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit}
S=${SMOLVM_BIN:-smolvm}
VENV=${SMOLVM_DEMO_VENV:-$HOME/ptwork}                 # host venv with unsloth
DRV=${SMOLVM_DEMO_DRV:-$(dirname "$0")/drvlib}         # CUDA shim libs
COORD=${SMOLVM_DEMO_COORD:-$(mktemp -d)}               # shared clone<->host mount
WORKLOAD="$(cd "$(dirname "$0")" && pwd)/workload.py"
export SMOLVM_CUDA_FORK_SHARE_WEIGHTS=1
gpumem() { nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits; }
line()   { printf '%s\n' "──────────────────────────────────────────────────────────────"; }

cp "$WORKLOAD" "$COORD/workload.py"
rm -f "$COORD"/GO "$COORD"/claim_* "$COORD"/result_* "$COORD"/marks.txt
for m in add mul sub golden; do $S machine stop --name uns-$m >/dev/null 2>&1; $S machine rm --name uns-$m --force >/dev/null 2>&1; done

line
echo "  smolvm CUDA fork demo"
echo "  model: $MODEL     GPU baseline: $(gpumem) MiB"
line
echo "[1/3] boot golden VM, load model"
T0=$(date +%s)
$S machine create --name uns-golden --cuda --net \
  -v "$VENV:$VENV:ro" -v "$DRV:/opt/drvlib:ro" -v "$COORD:/opt/coord:rw" \
  --image debian:bookworm-slim --storage 20 --overlay 15 -- sh -c "
    export LD_PRELOAD='/opt/drvlib/libcudart.so.12 /opt/drvlib/libcuda.so.1' \
      HF_HOME=/opt/coord/hf CC=gcc HF_HUB_DISABLE_TELEMETRY=1 \
      TRITON_CACHE_DIR=/root/.triton SMOLVM_MODEL='$MODEL'
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc ca-certificates >/dev/null 2>&1
    ln -sf /opt/drvlib/libcuda.so.1 /usr/lib/x86_64-linux-gnu/libcuda.so
    $VENV/venv/bin/python /opt/coord/workload.py
  " >/dev/null 2>&1
$S machine start --forkable --name uns-golden >/dev/null 2>&1
until grep -q READY "$COORD/marks.txt" 2>/dev/null; do sleep 2; done
echo "      golden ready in $(( $(date +%s) - T0 ))s ($(gpumem) MiB); frozen as the fork base"
echo
echo "[2/3] fork three clones"
for m in add mul sub; do
  TF=$(date +%s.%N)
  $S machine fork --golden uns-golden --name uns-$m >/dev/null 2>&1
  printf "      uns-%s forked in %.1fs\n" "$m" "$(echo "$(date +%s.%N) $TF" | awk '{print $1-$2}')"
done
echo go > "$COORD/GO"
echo "      gate released; clones train concurrently (add / mul / sub)"
echo
PEAK=0
until [ "$(ls "$COORD"/result_* 2>/dev/null | wc -l)" -ge 3 ]; do
  M=$(gpumem); [ "$M" -gt "$PEAK" ] && PEAK=$M
  sleep 2
done
echo "[3/3] results"
line
printf "      %-5s %-14s %-14s %-12s %s\n" task "GO→training" "loss" "ask it" verdict
for f in "$COORD"/result_*.txt; do
  IFS='|' read -r name t l0 l1 q gen expect verdict < "$f"
  printf "      %-5s %-14s %-14s %-12s %s\n" "$name" "${t}s" "$l0 → $l1" "$q = $gen" "$verdict (want $expect)"
done
line
echo "      peak VRAM: ${PEAK} MiB (base weights shared across the clones)"
line
for m in add mul sub golden; do $S machine stop --name uns-$m >/dev/null 2>&1; $S machine rm --name uns-$m --force >/dev/null 2>&1; done
