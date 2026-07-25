#!/bin/bash
# smolvm arm: load the model ONCE into a golden VM, fork N --share-weights
# learners (frozen 4-bit base shared in GPU memory; each learner's LoRA +
# optimizer + activations private). CUDA is remoted to a host daemon that owns
# the real GPU. Prints load time, fork time, aggregate tok/s, peak VRAM.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"

# Two golden layouts:
#  - DEFAULT (fast fork ~0.4s/clone): minimal ubuntu image + mount the venv;
#    the HF cache is reached via a symlink inside the coord mount. This is the
#    layout that produced the published fork numbers. `machine fork` cost scales
#    with the golden's ON-DISK data, so a minimal image forks in a fraction of
#    a second.
#  - USE_BAKED=1 (DEFAULT — reliable offline load, but SLOW fork ~25s/clone):
#    boot from the baked machine ($BAKED) with venv+model on guest block
#    storage. This loads the model reliably offline. Its large disk makes each
#    fork ~25s (disk-bound provisioning, NOT the GPU clone — see BENCHMARKS.md).
#    Throughput + memory numbers are correct; the fork TIME is understated vs a
#    minimal-disk golden. Default because the non-baked path's model loading is
#    currently unreliable (the coord/hf symlink doesn't cross virtiofs).
: "${USE_BAKED:=1}"
CO="$HOME/coord_smol"; rm -rf "$CO"; mkdir -p "$CO"; cp "$WORKLOAD" "$CO/qlora_train.py"
SOCK=/tmp/smolvm/cuda-daemon.sock
if [ "$USE_BAKED" = 1 ]; then
  [ -f "$BAKED" ] || { echo "MISSING baked machine at $BAKED — build it with ./make-baked.sh"; exit 1; }
  BASE=(--from "$BAKED"); MOUNTS=(-v "$DRVLIB:/opt/drvlib:ro" -v "$CO:/opt/coord:rw")
  HF_ENV="HF_HOME=/opt/hfcache HF_HUB_OFFLINE=1"
else
  [ -d "$VENV" ] || { echo "MISSING venv at $VENV (set VENV=..., or USE_BAKED=1)"; exit 1; }
  [ -d "$HF/hub" ] || { echo "MISSING HF cache at $HF/hub (pre-download the model; set HF=...)"; exit 1; }
  ln -sfn "$HF" "$CO/hf"   # HF cache reached through the coord mount
  BASE=(--image ubuntu:22.04); MOUNTS=(-v "$VENV:$(dirname "$GUEST_PYBIN" | xargs dirname):ro" -v "$DRVLIB:/opt/drvlib:ro" -v "$CO:/opt/coord:rw")
  HF_ENV="HF_HOME=/opt/coord/hf HF_HUB_OFFLINE=0"
fi

mk() { for m in "$@"; do "$SMOLVM" machine stop --name "$m" >/dev/null 2>&1; "$SMOLVM" machine rm --name "$m" --force >/dev/null 2>&1; done; }
mk ql-g $(seq -f "ql-c%g" 0 $((N-1)))
pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null; pkill -f "_cuda-clone-worke[r]" 2>/dev/null; sleep 1
rm -f "$SOCK"

# stage shims under both suffixed + unsuffixed names (harness/loader use both)
cp "$DRVLIB/libcudart.so" "$DRVLIB/libcudart.so.12" 2>/dev/null || true
cp "$DRVLIB/libcuda.so"   "$DRVLIB/libcuda.so.1"    2>/dev/null || true

env SMOLVM_CUDA_FORK_WORKERS=1 SMOLVM_CUDA_FORK_ISOLATE=1 SMOLVM_CUDA_DAEMON_IDLE_SECS=0 RUST_LOG=error \
  "$SMOLVM" _cuda-daemon "$SOCK" > "$HOME/smol_daemon.log" 2>&1 &
for i in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done

echo "== SMOLVM: golden + $N share-weights forks, $STEPS steps each (USE_BAKED=$USE_BAKED) =="
# The default (non-baked) path apt-installs python in the minimal image.
APT=""; [ "$USE_BAKED" = 1 ] || APT="export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3 python3-dev gcc ca-certificates >/dev/null 2>&1;"
GUEST="$APT export LD_PRELOAD='/opt/drvlib/libcudart.so.12 /opt/drvlib/libcuda.so.1' \
$HF_ENV COORD=/opt/coord ARM=fork FORK=1 GOLDEN_WARMUP=1 \
STEPS=$STEPS NSLOTS=$N MODEL=$MODEL PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True; \
ln -sf /opt/drvlib/libcuda.so.1 /usr/lib/x86_64-linux-gnu/libcuda.so; \
$GUEST_PYBIN /opt/coord/qlora_train.py 2>>/opt/coord/g.err"

t0=$(date +%s.%N)
"$SMOLVM" machine create --name ql-g --cuda --net "${BASE[@]}" "${MOUNTS[@]}" \
  --storage 30 --overlay 20 -- sh -c "$GUEST" >/dev/null 2>&1
env SMOLVM_CUDA_SHARED=1 "$SMOLVM" machine start --forkable --name ql-g >/dev/null 2>&1
for i in $(seq 1 300); do [ -f "$CO/golden_ready" ] && break; sleep 2; done
[ -f "$CO/golden_ready" ] || { echo "GOLDEN-LOAD-FAILED"; tail -5 "$CO/g.err" 2>/dev/null; mk ql-g; exit 1; }
tready=$(date +%s.%N); echo "golden_load_s=$(echo "$tready - $t0" | bc) (once)"

for c in $(seq 0 $((N-1))); do "$SMOLVM" machine fork --golden ql-g --name "ql-c$c" --share-weights >/dev/null 2>&1; done
tfork=$(date +%s.%N); echo "fork_${N}_clones_s=$(echo "$tfork - $tready" | bc)"
touch "$CO/go"   # release the barrier in every clone

maxvram=0; done=0
for s in $(seq 1 900); do
  done=$(grep -l '"event": "done"' "$CO"/learner_*.jsonl 2>/dev/null | wc -l)
  v=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null)
  [ "$v" -gt "$maxvram" ] 2>/dev/null && maxvram=$v
  [ "$done" -ge "$N" ] && break
  sleep 2
done
tend=$(date +%s.%N)
echo "time_to_all_done_s=$(echo "$tend - $t0" | bc)"
echo "peak_gpu_mem_MiB=$maxvram   ($N learners, ONE shared base)"
mk ql-g $(seq -f "ql-c%g" 0 $((N-1)))
pkill -f "smolvm _cuda-daemo[n]" 2>/dev/null; pkill -f "_cuda-clone-worke[r]" 2>/dev/null

python3 "$HERE/summarize.py" "$CO" fork
