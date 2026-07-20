# smolvm H100 GPU-remoting setup — friction found & fixed (2026-07-20 QA)

Reproducible setup for smolvm CUDA-remoting + fork on a fresh Lambda H100
(Ubuntu 22.04, glibc 2.35, driver 570, sm90). Every step below was a real
blocker this session; encode them so next setup is minutes, not hours.

## Host prerequisites (one-time, per box)
1. **/dev/kvm access**: `sudo usermod -aG kvm,docker $USER` AND
   `sudo chmod 666 /dev/kvm` (group needs re-login; chmod is immediate).
   Symptom if missing: `kvm permission denied: Cannot access /dev/kvm`.
2. **Build smolvm ON the box** — a binary built on a newer-glibc dev box
   (e.g. Arch glibc 2.39) won't exec here (`GLIBC_2.39 not found`).
   `curl https://sh.rustup.rs | sh -s -- -y --profile minimal`
   `sudo apt install -y build-essential pkg-config libssl-dev`
   `cd smolvm-src && LIBKRUN_BUNDLE=~/smolvm/lib/linux-x86_64 cargo build --release -p smolvm -p smolvm-cudart-shim -p smolvm-cuda-shim`
   (Build all three together — building the shim alone fails: `crate::host` is
   feature-gated off without smolvm.)
3. **Shim must export cudaGetDriverEntryPoint** (torch >=2.7 links it at load)
   — fixed in-tree (commit 710a4bb); rebuild picks it up.

## Guest image requirements (per workload VM)
- Use `--image ubuntu:22.04` (guest python must MATCH the host venv's minor
  version; venv built with Ubuntu 22.04 python3.10, debian bookworm's 3.11
  won't load the venv's compiled extensions).
- Guest boot cmd MUST `apt-get install -y python3 python3-dev gcc ca-certificates`
  — python3 (venv interpreter target /usr/bin/python3), python3-dev (Triton
  needs Python.h), gcc (Triton JIT-compiles cuda_utils, unsloth needs it).
- Symlink the shim driver: `ln -sf /opt/drvlib/libcuda.so.1 /usr/lib/x86_64-linux-gnu/libcuda.so`.

## Python env (host venv, mounted into guest + containers)
- Clean ISOLATED venv (NOT --system-site-packages; the box's old system
  Pillow/numpy shadow and break unsloth/transformers).
  `python3 -m venv ~/ptwork && ~/ptwork/bin/pip install "unsloth[cu128-torch270]" bitsandbytes trl peft datasets accelerate`
- Load models from the LOCAL snapshot dir (glob HF_HOME/hub/.../snapshots/*),
  not the repo id — avoids unsloth's offline-resolution quirk AND online
  verify latency, identical across native/container/guest.

## Container baseline image
- `FROM nvidia/cuda:12.4.0-devel-ubuntu22.04` (devel: has gcc + cuda.h for
  Triton; runtime image lacks both) + `apt install python3 python3-dev gcc`
  + `ln -sf /usr/bin/python3 /usr/bin/python`.
- Run with `--gpus '"device=0"'`, mount the shared venv + HF cache read-only.

## Known open QA items (this box, ongoing)
- **N>=3 concurrent clone training -> loss=nan** (forward pass corrupts;
  N=1/N=2 correct). NOT caused by the fork-time warm chain (reproduces with
  SMOLVM_CUDA_WARM_DIAL=0). Root cause TBD — concurrency in the daemon /
  worker compute path.
- **QLoRA training step is NOT CUDA-graph capturable** (bitsandbytes 4-bit
  dequant is capture-unsafe: "operation failed during capture"). Blocks the
  graph-replay optimization for backward passes; op-coalescing is the lever.
