# Quickstart — fork warm GPU VMs for dense fine-tuning

The two-command story: load a model **once** into a golden VM, then fork it
into N isolated learners that share the frozen weights in GPU memory. New
learners start in ~0.4 s and cost only their private LoRA + optimizer +
activations. Measured result: **N=16 at 9,628 tok/s on one H100 — +36% over
the container ceiling in 44 GB vs 62 GB**, with 8/8 reliability (BENCHMARKS.md).

This is the fastest path to reproduce. Deeper audit trails: REPRODUCIBILITY.md
(engine pins, exact host/guest versions), BENCHMARKS.md (all numbers),
QA-LOG.md / PERF-LOG.md (every defect + experiment).

## Prerequisites (host)

- NVIDIA GPU + driver, `/dev/kvm` accessible (`sudo chmod 666 /dev/kvm` or the
  `kvm` group). Validated sm86 (3070), sm80 (A100), sm90 (H100).
- `smolvm` binary **and** the guest shims (`libcudart.so.12`, `libcuda.so.1`)
  built from the SAME source — the daemon refuses a mismatched shim with a
  wire-hash error (this is a feature; see the staging note below). Build:
  ```
  LIBKRUN_BUNDLE=<libkrun dir> cargo build --release \
    -p smolvm -p smolvm-cudart-shim -p smolvm-cuda-shim
  ```
  Building on a glibc-older host (e.g. Ubuntu 22.04) requires the musl Rust
  target so the guest init links static: `rustup target add $(uname -m)-unknown-linux-musl`.

## Fastest path: the baked machine

`pack create` a golden VM with the venv + model cache baked into guest block
storage, so learners never apt-install or re-download weights:

```bash
# one-time: provision a VM that copies venv + HF cache onto its disk, then pack it
smolvm machine create --name bake --storage 30 --overlay 10 \
  -v "$VENV:/mnt/venv_src:ro" -v "$HF:/mnt/hf_src:ro" -v "$COORD:/opt/coord:rw" \
  --image ubuntu:22.04 -- sh -c '
    apt-get update -qq && apt-get install -y -qq python3 python3-dev gcc ca-certificates
    mkdir -p /home/ubuntu /opt/hfcache
    cp -a /mnt/venv_src /home/ubuntu/ptwork && cp -a /mnt/hf_src/hub /opt/hfcache/hub && sync'
smolvm machine start --name bake && smolvm machine stop --name bake
SMOLVM_FILE_TRANSFER_MAX_BYTES=64G smolvm pack create --from-vm bake -o qlora-baked
# -> qlora-baked.smolmachine  (self-contained; ship it + the smolvm binary + shims)
```

## Run the fork sweep

```bash
# daemon (host-side CUDA server)
SMOLVM_CUDA_FORK_WORKERS=1 SMOLVM_CUDA_FORK_ISOLATE=1 \
  smolvm _cuda-daemon /tmp/smolvm/cuda-daemon.sock &

# golden: load the 7B base ONCE
smolvm machine create --name g --cuda --net --from qlora-baked.smolmachine \
  -v "$DRVLIB:/opt/drvlib:ro" -v "$COORD:/opt/coord:rw" --storage 30 --overlay 10 \
  -- sh -c "export LD_PRELOAD='/opt/drvlib/libcudart.so.12 /opt/drvlib/libcuda.so.1' \
    HF_HOME=/opt/hfcache HF_HUB_OFFLINE=1 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    FORK=1 GOLDEN_WARMUP=1 MODEL=unsloth/Qwen2.5-7B-bnb-4bit COORD=/opt/coord; \
    ln -sf /opt/drvlib/libcuda.so.1 /usr/lib/x86_64-linux-gnu/libcuda.so; \
    python /opt/coord/qlora_train.py"
SMOLVM_CUDA_SHARED=1 smolvm machine start --forkable --name g   # waits at a barrier when READY

# fork N learners (each claims a distinct data shard); then release the barrier
for c in $(seq 0 $((N-1))); do
  smolvm machine fork --golden g --name c$c --share-weights
done
echo go > $COORD/go
```

## The recipe that matters (learned the hard way — QA-LOG.md)

- **`--share-weights`** is the density mode: the frozen 4-bit base is shared in
  GPU memory; only each learner's LoRA/optimizer/activations are private.
- **`GOLDEN_WARMUP=1`**: run one training step in the golden BEFORE forking, so
  the daemon's content-verification marks training-written chunks private (else
  N≥3 shared-weights training corrupts to nan).
- **`PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True`** with share-weights (or
  `:False` for copy mode). Copy mode without this fails the clone's first VMM map.
- **`HF_HUB_OFFLINE=1`** + a baked/pre-populated `HF_HOME`: a missing local
  snapshot silently falls back to a multi-GB hub download (looks like a "slow
  load"; it's a network fetch).

## Deploy staging (the wire-hash guard)

Stage the `smolvm` binary AND every shim in `drvlib/` (`libcudart.so.12`,
`libcuda.so.1`, plus the unsuffixed `libcudart.so`/`libcuda.so` the harness
copies at start) from ONE build, atomically. A daemon/shim mismatch is refused
with a wire-hash error (correct — it prevents silent corruption), which
surfaces as a golden that fails to load. `cp: Text file busy` on the binary
means a daemon is still running it — kill the daemon first.
