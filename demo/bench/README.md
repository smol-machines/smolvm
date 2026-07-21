# Run the benchmark yourself

The measured head-to-head from BENCHMARKS.md, as a script anyone can run on
their own GPU box: load a 7B model once, fork N `--share-weights` learners,
and compare against N cold container replicas of the identical workload.

## One command

```bash
cd demo/bench
N=8 STEPS=8 ./benchmark.sh
```

Output ends with a head-to-head table (aggregate tok/s, peak VRAM, load time)
and a density ratio. `ARMS=smolvm ./benchmark.sh` runs only the fork arm (skip
Docker); `N=16 ./benchmark.sh` pushes density past where containers OOM.

## What you need first (one-time)

1. **A GPU host** with the NVIDIA driver and `/dev/kvm` accessible
   (`sudo chmod 666 /dev/kvm`). Validated on RTX 3070 (sm86), A100 (sm80),
   H100 (sm90).
2. **smolvm + guest shims, built from the same source** (the daemon refuses a
   mismatched shim — see QUICKSTART.md). You need the `smolvm` binary, the
   libkrun bundle, and `drvlib/` (`libcudart.so.12`, `libcuda.so.1`).
3. **A python venv** with the pinned stack (torch 2.6.0+cu124, unsloth, trl,
   bitsandbytes — see REPRODUCIBILITY.md), and the **model pre-downloaded** to
   an `HF_HOME` cache.
4. For the container arm only: **Docker** with the NVIDIA runtime and an image
   (`IMG`, default `qlora-base`) that contains the same venv + CUDA.

Point the scripts at your paths by editing `config.sh` or exporting the vars
(`SMOLVM`, `DRVLIB`, `VENV`, `HF`, `MODEL`, ...). Everything defaults to the
layout in QUICKSTART.md.

## Files

| file | role |
|---|---|
| `benchmark.sh` | orchestrator: preflight, run both arms, print head-to-head |
| `run-smolvm.sh` | smolvm arm — golden load once, fork N share-weights learners |
| `run-containers.sh` | container arm — N cold replicas, identical workload |
| `config.sh` | all paths + knobs (override via env) |
| `summarize.py` | aggregate per-learner JSONL → one line + detail |
| `../qlora_train.py` | the workload both arms run (FORK barrier + golden warmup) |

## Reading the result

`agg_tok_s` is the sum across learners; `peak_gpu_mem_MiB` is the whole-GPU
high-water mark. Expect smolvm to reach or beat the container aggregate at far
lower VRAM, and to keep scaling past the N where containers OOM. Each run is a
single sample — average a few (and warm the page cache) for a stable number.

**Two honest caveats (measured; see BENCHMARKS.md):**
- **Fork time is understated by the default baked machine.** The baked golden
  has a ~14 GB disk, and `machine fork` provisioning scales with golden disk
  size (~1 s/GB, disk-bound — NOT the GPU clone, which is sub-second). So the
  `fork_N_clones_s` you see is ~25 s, vs the ~0.4 s the RAM/GPU clone actually
  costs on a minimal-disk golden. Throughput and memory numbers are unaffected.
- **The default uses the baked machine for reliable OFFLINE model loading.**
  The non-baked path (`USE_BAKED=0`) forks fast but its model loading is
  currently unreliable (the coord/hf symlink doesn't resolve across virtiofs),
  so it's not the default.

Known gotchas (staging/wire-hash) are in QUICKSTART.md and QA-LOG.md.
