# GPU workload QA log (continuous)

Standing QA of GPU/CUDA-fork workloads. One entry per experiment: setup,
result, verdict, and any fix that came out of it. Fixes land as commits on
QA branches (pushed, no PRs). Venue: Lambda A100-40GB (sm80) unless noted.

## Experiment queue
- [x] EXP-1 zero-config release path — PASS (see Results)
- [ ] EXP-2 fork `--env` on GPU: 3-learner QLoRA sweep parameterized via
      `-e LR=...` instead of claim files (merged main build)
- [ ] EXP-3 golden boot-time cut: apt/Triton-cache baked artifact vs current
      (285s baseline)
- [ ] EXP-4 clone ring-activation SIGSEGV reproduction at N=8 (sm80, from the
      H100 QA-LOG's 1-clone-per-leg crash)
- [ ] EXP-5 vLLM clone serving: 30-min sustained load stability (sm80)
- [ ] EXP-6 balloon-idle + model-load interaction on tip (the #697 bug shape,
      engine-local reproduction)

## Results
(newest first)

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
