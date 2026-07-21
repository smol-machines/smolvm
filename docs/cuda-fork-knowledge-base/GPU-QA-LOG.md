# GPU workload QA log (continuous)

Standing QA of GPU/CUDA-fork workloads. One entry per experiment: setup,
result, verdict, and any fix that came out of it. Fixes land as commits on
QA branches (pushed, no PRs). Venue: Lambda A100-40GB (sm80) unless noted.

## Experiment queue
- [x] EXP-1 zero-config release path — PASS (see Results)
- [x] EXP-2/2b/2c fork `--env` GPU sweep — feature PASS; exposed main-branch
      clone first-op CUDA failure (see Results)
- [ ] EXP-3 golden boot-time cut: apt/Triton-cache baked artifact vs current
      (285s baseline)
- [ ] EXP-4 clone ring-activation SIGSEGV reproduction at N=8 (sm80, from the
      H100 QA-LOG's 1-clone-per-leg crash)
- [ ] EXP-5 vLLM clone serving: 30-min sustained load stability (sm80)
- [ ] EXP-6 balloon-idle + model-load interaction on tip (the #697 bug shape,
      engine-local reproduction)

## Results
(newest first)

### EXP-2 / 2b / 2c — fork `--env` GPU sweep: feature PASS; main-branch clone
### first-op CUDA failure found (2026-07-21, A100-40GB, merged-main build)

The feature under test worked exactly as designed: three clones forked with
only `-e LR=1e-4|3e-4|6e-4` (946-975ms each) all read their correct, distinct
parameter from `/etc/smolvm/fork-env` and proceeded — no claim files.

What it exposed: on MERGED MAIN, every clone's first heavy GPU op fails with
`RuntimeError: CUDA error: unknown error` (in `fix_untrained_tokens`, a
`torch.amax` over the 7B embedding matrix). Discriminators:
- EXP-2:  N=3, `--share-weights`  -> all 3 fail
- EXP-2b: N=3, copy mode          -> all 3 fail (NOT the share path)
- EXP-2c: N=1, single clone       -> fails (NOT a concurrency race)
- Light ops are fine (golden loads the model; clone heartbeat torch-add passed
  on the same main build earlier) — the break is heavy first-ops.
- The p3b-graph-replay branch binary passed an hour-long N=8 QLoRA soak on
  this same box — its clone first-op registry + widened transport-retry work
  is exactly the missing piece; this series is an independent sm80 repro of
  the bug that branch fixes, now shown to be deterministic on main.

Verdict: `--env` ships clean; main's clone-CUDA training path is broken until
the graph-replay branch's reliability commits merge. No fix authored here —
owned by that in-flight branch; this entry is the repro record.
Repro: exp2 harness on the A100 (`~/exp2.sh`, workload `coord/exp2_workload.py`).

### EXP-1 — zero-config release path: PASS (2026-07-21, A100-40GB)
Released 1.6.13 tarball + `smolvm-gpu-testbed.smolmachine` + `--cuda`, with
NO drvlib mount, NO LD_PRELOAD, no manual daemon, no SMOLVM_CUDA_* env:
- Golden CUDA-ready in **58s** from the artifact — the agent-rootfs-bundled
  shims auto-stage correctly. The entire legacy drvlib/LD_PRELOAD recipe is
  obsolete for released binaries; docs and demos should stop teaching it.
- Golden + 2 forked clones all heartbeating CUDA correctly (16 beat lines).
- Known blemish, not a new bug: forks from the pack-backed golden took
  **16.5s each** on the released binary — this is the per-clone sidecar
  re-extraction already fixed on main (merged as the fork-layers-reuse
  change; measured 0.95s post-fix on this same box). Confirms the fix must
  ride the next release before the artifact-first demo is publishable.
Raw log: A100 `~/exp1-result.log`.
