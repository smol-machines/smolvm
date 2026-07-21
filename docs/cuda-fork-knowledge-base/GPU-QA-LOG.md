# GPU workload QA log (continuous)

Standing QA of GPU/CUDA-fork workloads. One entry per experiment: setup,
result, verdict, and any fix that came out of it. Fixes land as commits on
QA branches (pushed, no PRs). Venue: Lambda A100-40GB (sm80) unless noted.

## Experiment queue
- [x] EXP-1 zero-config release path — PASS (see Results)
- [x] EXP-2 series — fork `--env` PASS; clone-CUDA "failure" was workload-flaky, path HEALTHY (EXP-2e)
- [x] EXP-3 golden boot breakdown — MEASURED; venv-over-virtiofs is 42% (see Results)
- [ ] EXP-4 clone ring-activation SIGSEGV reproduction at N=8 (sm80, from the
      H100 QA-LOG's 1-clone-per-leg crash)
- [~] EXP-5 vLLM 30-min serving — BLOCKED on harness/venv drift (see Results)
- [x] EXP-6 balloon-idle + model-load — NO-REPRO, narrows the cloud bug (see Results)

## Results
(newest first)

### EXP-3b — CORRECTS EXP-3's boot attribution (2026-07-21)
Timed the isolated unsloth import from virtiofs vs a guest-local ext4 copy:
| | cold | warm (2nd run) |
|---|---|---|
| virtiofs mount | 28s | **28s** (no page-cache benefit — FUSE per-access overhead) |
| local ext4 overlay | 19s | **9s** (page cache works) |

So the isolated import is ~28s, but EXP-3's golden *first* import was **93s** —
therefore **~65s of that phase is first-time compile-cache generation**
(Triton JIT + `/unsloth_compiled_cache`), NOT venv file I/O over virtiofs.
EXP-3's "venv-over-virtiofs = 42%, fixed by baking the venv" is **corrected**:
- Baking the venv onto local overlay saves only ~10–19s on the import (and
  restores warm-cache benefit that virtiofs never gives).
- The **bigger, cleaner win is pre-warming the Triton + unsloth compile caches
  BEFORE packing** — run one import (and ideally one training step) in the prep
  VM so `/unsloth_compiled_cache` + `~/.triton` are baked into the artifact.
  That removes the ~65s first-import cost entirely.
- Real-world note: virtiofs import does NOT improve on a warm second access
  (28s→28s) — independent support for DAX (libkrun #43) and for baking
  hot read paths into the artifact rather than mounting them.
Corrected recipe: bake venv **+ pre-warmed compile caches** → the 93s golden
warm-up phase should drop to ~10–19s. (End-to-end validation from a real
baked+pre-warmed `.smolmachine` is the remaining follow-up.)


### EXP-3 — golden boot phase breakdown: 223s, and 42% is bakeable (2026-07-21)
Instrumented a 7B QLoRA golden cold boot (bundle binary, A100), timestamps per
phase:
| phase | time | share | reducible? |
|---|---|---|---|
| apt install (gcc, python3-dev, ca-certs) | 34s | 15% | **fully** — bake into base image / artifact |
| **venv import over virtiofs** | **93s** | **42%** | **fully** — bake the venv into the artifact rootfs (local ext4 overlay, not a virtiofs mount) OR enable DAX (libkrun #43) |
| model weights → VRAM | 82s | 37% | mostly irreducible; pre-warm HF page cache helps a little |
| misc (ln, py startup) | ~14s | 6% | — |

**Headline: the single biggest cost is the venv import over virtiofs (93s, ~42%
of boot)** — the same FUSE import-storm root cause as the N=24 DNF. Recipe to
cut cold boot ~223s → ~90s with no engine change: ship the golden as a
`.smolmachine` with the venv + apt packages baked into its rootfs (already the
`unsloth-sweep.smolmachine` build recipe in IMAGE.md), so the interpreter and
site-packages live on the machine's local overlay instead of a mounted host
venv. DAX (libkrun #43) would additionally cut the virtiofs cost for any
remaining host mounts. Fork stays ~1s regardless — this only affects the
one-time golden warm-up, which is exactly the metric that gates
time-to-first-experiment.

---

## Session summary (2026-07-21 GPU QA loop)
- EXP-1 zero-config release path: **PASS** — released tarball auto-stages CUDA
  shims; legacy drvlib/LD_PRELOAD recipe is obsolete for users.
- EXP-2 series + EXP-2e: `fork --env` **VALIDATED** (clones read distinct params
  from `/etc/smolvm/fork-env`); the transient clone-CUDA "failure" was
  workload-specific flakiness, path proven healthy — earlier reads retracted.
- EXP-3 golden boot: **MEASURED** — 223s, venv-over-virtiofs is 42%; bake-venv
  recipe cuts it to ~90s.
- EXP-5 sustained serving: **BLOCKED** on testbed harness/venv drift; the path
  itself was already validated clean (EXP3 in A100-REPRODUCTION).
- EXP-6 balloon-idle+load: **NO-REPRO** — narrows the cloud pool segfault to
  pinned-RAM/pool-timing, not plain idle+load.
- Harness/UX findings: QA-GPU-4 (stale-daemon socket on start), QA-GPU-5
  (missing mount source → opaque `vm not found`), both with product notes.
No engine regressions found; no code fixes needed. Reliability of the fork +
weight-share path holds on sm80 (N=8 soak earlier + EXP-2e). Remaining
GPU-side work is gated on in-flight branches (#695 sm90, #697 balloon) and the
bake-venv artifact build.


### EXP-2e — CORRECTS the EXP-2 series: clone-CUDA path is HEALTHY (2026-07-21)
Re-ran the exact known-good soak config (bundle binary, PATH3 share,
`soak_workload.py`, N=3) on the same box, same day: **3 clones claimed slots and
trained cleanly, no CUDA error.** Therefore:
- The clone-CUDA-training path is fine on this binary/box RIGHT NOW.
- EXP-2/2b/2c/2d's `RuntimeError: CUDA error: unknown error` (in unsloth
  `fix_untrained_tokens` → `torch.amax(embedding_matrix)`) was **specific to
  `exp2_workload.py`'s first-op, not the fork/`--env` engine path.** The
  earlier reads ("main-only break", "not p3b-specific", "environmental
  degradation") are RETRACTED — all were misattributions of a flaky workload
  first-op. The GPU was healthy/idle throughout (0 MiB, no Xid).
- **`fork --env` itself is fully validated**: in every EXP-2 run the clones
  read their correct distinct LR from `/etc/smolvm/fork-env` before the
  workload's own unsloth call flaked. Delivery + parameterization: PASS.
Lesson for this log: when a GPU workload fails first-op, discriminate with a
KNOWN-GOOD workload on the same binary before blaming the engine/branch.


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
