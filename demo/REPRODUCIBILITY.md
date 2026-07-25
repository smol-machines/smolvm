# Reproducibility notes — smolvm warm-CUDA-fork benchmarks

Companion to BENCHMARKS.md (results) and QA-LOG.md (defects found while
validating). Everything here was measured 2026-07-18/19. This document
exists so a third party can re-run every number and audit every claim.

## Engine pin

- smolvm **v1.6.13** plus PR #681 (`cu12-advertise`, commit `cfae06d`):
  the guest shim advertises the CUDA 12.4 surface by default
  (`SMOLVM_CUDA_ADVERTISE` overrides). Without #681 every in-VM vLLM run
  fails at `cublasLtMatmul` with `CUBLAS_STATUS_NOT_INITIALIZED` — the
  benchmark suite itself caught this regression.
- Build: `LIBKRUN_BUNDLE=<libkrun dir> cargo build --release -p smolvm
  -p smolvm-cudart-shim -p smolvm-cuda-shim`. Guest shims
  (`libcudart.so.12`, `libcuda.so.1`) must come from the SAME build as the
  daemon (proto-hash consistency).

## Environments

| | RTX 3070 (local) | A100 (Lambda) | H100 (Lambda) |
|---|---|---|---|
| GPU | RTX 3070 8 GB, sm86 | A100 SXM4 40 GB, sm80 | H100 SXM5 80 GB HBM3, sm90 |
| Driver | 610.43.03 | 570.x (Lambda stock) | 570.148.08 |
| Host OS | Arch, kernel 7.1.3 | Ubuntu 22.04 | Ubuntu 22.04.5, kernel 6.8.0-60 |
| Instance | desktop | gpu_1x_a100_sxm4 ($1.99/hr) | gpu_1x_h100_sxm5 ($4.29/hr) |

Guest stack (identical everywhere, pinned by `l7_freeze.txt`):
python 3.12 (standalone build), **torch 2.6.0+cu124, vllm 0.8.5,
transformers 4.51.3**, unsloth (training experiments). Install with
`pip install --no-deps -r l7_freeze.txt --extra-index-url
https://download.pytorch.org/whl/cu124` — loose installs pull newer
torch/xformers whose `libc10_cuda` needs CUDA ≥12.5 cudart symbols the
shim does not export.

## Artifacts

- `smolvm-gpu-testbed.smolmachine` (133 MB, this directory): packed guest
  (debian + toolchain + experiment scripts baked). `machine create --from`
  it. Note: pack-created machines support **3 user virtiofs mounts** (the
  artifact's layers mount consumes a slot); bind-mount the HF cache under
  the coord mount.
- Lambda persistent FS `smolvm-testbed` (us-east-1): prebuilt engine,
  pinned venv, 21 GB model cache, harness scripts — a fresh A100 is
  experiment-ready ~2 min after boot (`testbed_boot.sh`).
- Harnesses (session scratchpad + FS `scripts/`): `bench_baselines.sh`
  (native-vs-VM), `h100_suite.sh` (phases ENV/A–F), `l8_vllm_scale.sh`
  (fork scaling), `vllm_compare.py` (serving workload), `qa1*.sh`
  (QA repros).

## Methodology definitions

- **Load→serving**: process start to first successful generation
  (`WARM-READY` mark, written after a real warmup request).
- **Batch-1 latency**: 60+ sequential deterministic requests
  (temperature 0, max_tokens 8), p50/p90/p99 over per-request wall time.
- **Batch-N sustained**: N identical concurrent prompts per engine step
  (continuous batching inside the engine), aggregate tokens/sec averaged
  over the last 4–5 steps.
- **Remoting tax**: the same four numbers native vs inside a smolvm VM
  (`--cuda`, shared daemon) on the same card, same config, same seed.
- **Time-to-capacity**: wall time until R replicas serve — cold replicas
  (fresh VM + engine load each) vs one warm golden + `machine fork`.
- **Density**: replicas serving simultaneously on one card until
  allocation failure — cold vs forks (`--share-weights` where noted).
- vLLM in-VM requires: `VLLM_USE_V1=0` (V1's memory profiler misjudges
  through remoting), `enforce_eager=True` (see QA-LOG: CUDA-graph capture
  in forkable sessions is an open bug), `PYTORCH_CUDA_ALLOC_CONF=
  expandable_segments:True`, pre-downloaded HF cache (virtiofs breaks HF's
  cross-VM locking), and the platform-detect patch in `vllm_compare.py`.

## Key results (see BENCHMARKS.md for full tables)

Measured this session, engine as pinned above:

| Qwen2.5-0.5B, vLLM 0.8.5, eager, V0 | A100 native | A100 in-VM | H100 native | H100 in-VM |
|---|---|---|---|---|
| load→serving | 56.3 s | 155.6 s | 11.8 s (12.5–12.7 on box 2, ×3) | 376 s (see note) |
| batch-1 p50 / p90 / p99 (ms) | 94 / 98 / 128 | 435 / 485 / 501 | 58 / 59 / 61 | 405 / 420 / 449 |
| batch-40 tok/s | ~2,319 | ~684 | ~4,225 | ~786 |
| batch-160 tok/s | ~5,924 | ~2,382 | ~10,880 | ~2,765 |

H100 numbers: instance `e846e470` (us-southeast-1, driver CUDA-13
generation), engine `2ef7a8f` (branch clone-channel-attach = v1.6.13 +
cu12-advertise + fatbin-chain walk + unconditional version advertisement +
TMA descriptor forwarding — the last three were required for sm90 in-VM
serving to exist at all; see QA-LOG.md). H100-native numbers from a second
box (us-south-2, driver 570.148.08) replicated ×3 within ±1%. The 376 s
in-VM load is inflated by full fatbin-chain shipping (correctness fix);
treat it as an upper bound pending module-image caching. Note the
structural result: the batch-1 remoting overhead is an additive constant
(~345 ms) across A100 and H100.

## Threats to validity

1. **Single-run timings** except H100 native (3 independent runs, spread
   shown). Cloud instances are shared infrastructure; expect ±10% on
   throughput numbers.
2. **The remoting tax is real and significant** (in-VM ≈ 30–40% of native
   throughput at batch ≥40; ~4.6× batch-1 latency on A100). Fork-based
   scaling wins (time-to-capacity, density, isolation) are measured
   *within* the virtualized world; a deployment that needs raw single-node
   throughput above all else should weigh the tax first.
3. **V0 + eager required in-VM** (see above). Native baselines were run
   with the same settings for a fair like-for-like comparison; native
   non-eager V1 would be faster still.
4. **Open defects found by this QA effort** (QA-LOG.md): (a) clone-routing
   rejects guest channels opened post-fork — first-ever cublas use inside
   a clone fails; workloads that touch cublas before forking are
   unaffected (fix sketched); (b) CUDA-graph capture fails in forkable
   sessions; (c) sm90 in-VM vLLM init failure (open); (d) copy-mode fork
   memory bills can exceed small cards with errors surfacing as misleading
   library failures rather than clean OOMs.
5. Fork/density/training results (BENCHMARKS.md) predate the discovery of
   (a) and hold because those workloads exercised cublas pre-fork
   (vLLM serving goldens) or avoid cublas in clones (triton/bnb training).
6. Models are small-to-mid (0.5B/7B); multi-GPU and >13B untested in this
   series.

## Raw-log index

- A100 native-vs-VM: `scratchpad/bench_out3.txt` (+ per-run `nat_*.txt`,
  `vm_*.txt` on the testbed FS).
- H100 archive: `scratchpad/h100_archive/h100_archive.tgz` — env
  fingerprint, 3× native runs, failed VM runs with tracebacks, probe
  series (GEMM matrix, shape/dtype, backend pinning, FA import), daemon
  logs, setup log.
- Fork/density/training: `scratchpad/l8_final_results.txt`, earlier-run
  logs referenced from BENCHMARKS.md.
- QA repro outputs: `scratchpad/qa1*_out.txt`, `qa*_daemon.log`.
