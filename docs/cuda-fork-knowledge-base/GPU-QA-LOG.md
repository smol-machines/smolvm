# GPU workload QA log (continuous)

Standing QA of GPU/CUDA-fork workloads. One entry per experiment: setup,
result, verdict, and any fix that came out of it. Fixes land as commits on
QA branches (pushed, no PRs). Venue: Lambda A100-40GB (sm80) unless noted.

## Experiment queue
- [ ] EXP-1 zero-config release path: released tarball + artifact + `--cuda`,
      NO drvlib mount, NO LD_PRELOAD, no manual daemon (auto-staged shims)
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
