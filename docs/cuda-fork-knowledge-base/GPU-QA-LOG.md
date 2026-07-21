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
- [~] EXP-5 vLLM 30-min serving — BLOCKED on harness/venv drift (see Results)
- [x] EXP-6 balloon-idle + model-load — NO-REPRO, narrows the cloud bug (see Results)

## Results
(newest first)

### EXP-5 — BLOCKED on harness/venv drift, not an engine defect (2026-07-21)
Four launch attempts, three separate stale-harness path issues each fixed in
turn (missing `~/hfshare` mount [QA-GPU-5], `vllm_compare.py` not in `~/coord`,
then vLLM engine-config failure from a transformers/vLLM version mismatch
against this box's venv — the testbed `vllm_compare.py` predates the venv).
De-prioritized: sustained sm80 clone serving is ALREADY validated clean in the
original reproduction (A100-REPRODUCTION EXP3, batch-40, zero SIGSEGV/nan). A
longer re-soak isn't worth chasing a drifted harness. If revisited, pin the
vLLM/transformers versions the `vllm_compare.py` was written against, or
rewrite the probe against the current venv.

### EXP-2d — confirm the clone-CUDA break is main-only: RUNNING
Re-runs the exact EXP-2c workload (N=1 clone QLoRA training) with the BUNDLE
(graph-demo) binary that passed the N=8 soak, instead of merged-main. If the
clone trains here, it confirms EXP-2's finding — the clone first-op CUDA
failure is specific to merged-main (missing the p3b-graph-replay clone first-op
registry + transport-retry work), not a hardware/workload issue.


### QA-GPU-5 (harness) — EXP-5 START-FAILED root cause: missing mount source
gives a "vm not found" at start, not a clear create error (2026-07-21). EXP-5's
create referenced `~/hfshare` (a path from the *first* A100 box, absent on
repro2); the create aborts with `mount source not found`, the machine is never
registered, and the subsequent `start` fails opaquely with `vm not found`.
Fixed the harness to mount the real cache (`~/coord/hf`). Product note worth a
look: a `--volume` whose host source is missing should fail the CREATE loudly
and consistently, rather than surfacing later as a confusing start-time
`vm not found`. (This is what the earlier "START FAILED twice" retry was
actually hitting — not daemon contention as QA-GPU-4 first guessed; QA-GPU-4's
stale-daemon reap is still a valid harden, but the real blocker here was the
mount path.)


### QA-GPU-4 (LOW) — fork/CUDA harness: golden start fails if a prior daemon
### is mid-teardown (2026-07-21). EXP-5's first run hit an immediate "START
FAILED" because the previous experiment's `_cuda-daemon` + machine were still
winding down when it started a new daemon on the same socket. A bare golden
start on the same binary/box succeeds once the socket is free. Not an engine
defect — a harness sequencing gap; hardened the run scripts to reap the daemon
+ socket and retry the golden start once. Product-side follow-up worth noting:
`machine start --forkable --cuda` gives no distinct error when the CUDA daemon
socket is stale/busy — a clearer message would help users.

### EXP-6 — balloon-idle then 7B model load: NO-REPRO (2026-07-21, A100, main)
`SMOLVM_IDLE_RECLAIM=1` (1-min window), guest idled 240s, then loaded
Qwen2.5-7B-bnb-4bit: **LOADED-OK**. Interpretation, with caveats:
- Under CUDA remoting the weights go to HOST VRAM, so a plain model load does
  not create the pinned guest-RAM pressure the balloon bug needs (the
  DEFLATE_ON_OOM PR's own repro used 400MB of pinned tmpfs). Guest page cache
  from safetensors reads is reclaimable, so the kernel yields it to the
  balloon without dying.
- Pulse firing was not independently confirmed in this run (no RUST_LOG on
  the launcher) — treat as "not sufficient to trip", not "mechanism absent".
- Net: the cloud pool-golden segfault likely requires the pinned/tmpfs or
  larger guest-RAM working set of the @enter flow, or pool-claim timing —
  plain idle+load is not the trigger. The balloon-OOM mechanism itself is
  already demonstrated in the DEFLATE_ON_OOM PR; its merge remains the fix.

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
