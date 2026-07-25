# smolvm GPU QA log — edge cases, bugs, improvements

## BOARD CLEAR (2026-07-19 ~16:00): the last local defect closes — and QA-1's original mission completes

The shim audit refuted the baked-stale-shim theory (torch maps the mounted
current shims; baked copies exist but are unmapped). The remaining churn
failure was the HARNESS: it used the pre-instrumentation workload and
demanded pongs from the frozen-by-design golden. The corrected churn
(clone-answers expectation, probe workload) on the artifact guest:

**8/8 cycles green** — fork 7.8 s, clone computes bit-identical results,
teardown; and the lifecycle data QA-1 set out to measure on day one:
- **VRAM reclamation is exact**: 2,880 MiB baseline → 7,821 MiB with a
  clone live → back to exactly 2,880 MiB after every teardown. Zero leak
  over 8 cycles.
- **Daemon RSS**: one-time +706 MB after the first fork (staging cache, by
  design), then FLAT for 7 cycles. No drift.
- **Workers**: reaped to zero every cycle.

The historical "artifact×forkable fails at every commit" verdicts were the
since-fixed engine bugs plus the harness misreading the golden freeze —
the artifact guest is fine on the current stack. **No open local defects
remain**: plain-torch forks, share-weights vLLM forks, artifact churn,
CUDA-graph capture, rings, and module dedup are all green on one build.
(Remaining engineering, not defects: P2b clone rings, P3b clone graph
replay, ping-thread late-handle edge — tracked in OPTIMIZATIONS.md.)

## Final regression sweep (2026-07-19 ~15:40, post-#690-merge build + P2/P3)

1. Plain-torch fork (debian): **GREEN** — post-fork sync/add/matmul all
   pass, bit-identical values.
2. Share-weights vLLM forks: **GREEN** — golden 193 ms pre-fork (rings),
   both clones serve (5.4/6.5 s first request, 525/529 ms steady).
3. Original artifact-guest churn: **still fails** (clones never answer;
   note the harness also miscounts — the frozen golden can't pong by
   design). This is the LAST open local defect, and a new prime theory
   emerged: **the testbed .smolmachine bakes Jul-18-era shims** (and a
   /usr/lib libcuda symlink) into the guest image — dlopen-by-soname paths
   inside the guest can hit the stale baked copies instead of the mounted
   drvlib, which would explain artifact-only failures across all engine
   versions. Next action: REBUILD the artifact from a fresh guest with
   current shims (also required for the public reproducibility story —
   the artifact is the shareable vehicle), then re-run the churn.

## RESOLUTION (2026-07-19 ~12:45): fork-scaled vLLM serving WORKS; two long-standing "failures" were misreadings

Final local validation on the full branch (commit 7737217): golden serves
pre-fork (441 ms) → 2 `--share-weights` forks → **both clones serve the
correct generation** (first requests 6.5 s / 13.1 s = lazy reloads, ~3×
faster via the new module cache) → **steady-state 533 / 532 ms per clone**.

Closures this unlocks:
1. **"Golden wedges after fork" was DESIGN, not a bug**: the fork CLI
   prints "Golden stays frozen as the fork base" — a forked golden is a
   frozen template; CLONES serve. QA-1b P3's "timeout" and the H100
   head-to-head's "golden collapse to 16 tok/s" were both the freeze
   working as intended, misread as failures (the harnesses discarded the
   CLI output that said so).
2. **The H100 head-to-head arm B was therefore mis-designed** (counted the
   frozen golden as a serving replica; polluted aggregate windows). It
   must be re-run as: golden (frozen) + N clones serving, on the current
   build. Arm A stands.
3. The remaining local failure modes decompose cleanly: plain (copy-mode)
   forks on the 8 GB card hit real VRAM pressure at cublas replay
   (`ALLOC_FAILED` — masked-OOM class, already documented); the
   ping-thread handle gap (vh-miss on late-created handles) remains a
   REAL architectural issue for workloads that create library handles
   post-fork on fresh threads, but does NOT block the serving pattern
   (handles pre-exist in the serving loop).

Optimizations verified this session (see OPTIMIZATIONS.md):
- **Module-image dedup (aec9307)**: second replica boots make ZERO full
  module loads (341/341 cache hits; ~790 MB ships once instead of per
  replica).
- **Single-container fatbin capture restored (7737217)**: the chain walk
  over-captured neighboring rodata (~20 GB/boot shipped, 129 MB avg per
  module); the sm90 209s are attributed to the version-advertise leak, not
  container truncation. `SMOLVM_CUDA_FATBIN_CHAIN=1` kept as a toggle
  pending one cheap sm90 re-verify.

Running log of QA experiments on warm-CUDA-fork behavior, run locally
(RTX 3070 8GB, sm86) while the A100/H100 academic-reproduction suites
execute remotely. Engine: smolvm v1.6.13 + cu12-advertise fix (PR #681).
Harnesses live in the session scratchpad (`qa_*.sh`); durable findings and
data land here.

## Backlog (edge cases not covered by the benchmark suites)

| # | Edge case | Why it matters | Status |
|---|---|---|---|
| QA-1 | Fork/destroy churn (8 cycles): VRAM reclamation, daemon RSS drift, worker cleanup, golden health after churn | Autoscalers scale down as often as up; benchmarks only ever fork up | FAILED — found a bug candidate, see findings |
| QA-1b | Discriminator for the QA-1 failure: plain vs forkable boot, ping before/after fork, warmed vs cold-kernel golden | Isolates whether fork breaks kernel launches on a never-launched golden | RUNNING |
| QA-2 | Shared-weights mutation hazard: clone writes in-place to a shared base tensor — is the sibling corrupted silently? | Safety property of `--share-weights`; documented as "base must stay frozen" but never adversarially tested | queued |
| QA-3 | Fork under load: fork the golden mid-kernel / during active training step — snapshot consistency | Real autoscaling forks a busy server, not an idle one | queued |
| QA-4 | Fork-of-fork (clone a clone): supported? clean error? | Users will try it; silent corruption would be worst-case | queued |
| QA-5 | Fork before any CUDA activity (cold golden): degenerate snapshot | Trivial-but-untested boundary | queued |
| QA-6 | Daemon idle-timeout with live clones (`SMOLVM_CUDA_DAEMON_IDLE_SECS` small) | Config footgun: does the daemon reap under live clones? | queued |
| QA-7 | Clone count to failure on 8GB card + error quality at VRAM exhaustion | Failure-mode UX: OOM should be a clear error, not a hang | queued |

## Findings

(one section per completed experiment; raw logs referenced from scratchpad)

### QA-1 (2026-07-19): fork of a cold-kernel golden → every VM's kernel launches fail — BUG CANDIDATE

**Setup.** RTX 3070, engine cfae06d (v1.6.13 + cu12-advertise). Golden guest
(testbed artifact, plain torch): allocate `w` (32 MB) + 1.5 GB ballast +
`x`, `torch.cuda.synchronize()`, write READY, then answer file-based pings
with a deterministic `x @ w`. Host: 8 cycles of fork → ping → verify →
stop/rm, sampling VRAM / daemon RSS / worker count. Crucially, the golden's
**first-ever kernel launch happens after the first `machine fork`** — every
prior demo/benchmark warmed the golden with real compute (model load /
training steps) before forking.

**Result: 0/8 cycles produced a single successful matmul, and the golden
died too.**

- Allocations, `cudaMemcpy`-free ballast setup, and `synchronize` all
  worked pre-fork (READY written, `alloc=1600MiB`).
- Claim files show golden + each clone *did* respond to pings (filesystem
  side alive), then hit `RuntimeError: CUDA error: unknown error` at the
  first `x @ w` and died (guest traceback in `qa_golden.err`).
- Daemon log: **zero warnings/errors**. Each fork produced a clean-looking
  snapshot: `M3a gathered modules=341 funcs=19392`, `M2-alloc private
  translated copies 3/3 (1.6 GB)`, `routed isolating clone … worker_pid=…`,
  `clone resumed token 1`. The failure is entirely client-visible.
- Fork CLI time uniform 7.8 s; VRAM stable 2909→2911 MiB across all 8
  cycles (clones never touched the GPU before dying); daemon RSS
  2572→3344 MB after fork 1 then flat (staging reuse, as designed);
  workers reaped to 0 every cycle.

**Hypothesis.** Snapshotting/quiescing a golden whose session has loaded
modules (torch eagerly loads 341 modules / 19 392 functions) but has never
launched a kernel leaves the session (golden's and therefore every clone's)
unable to launch kernels afterwards. QA-1b discriminates: plain boot vs
forkable boot vs pre-fork-warmed golden vs cold-kernel golden.

**Why it matters.** "Fork a pre-loaded but not-yet-exercised golden" is a
plausible production shape (pre-provision a pool before traffic arrives).
If confirmed, either fix the launch path or fail loudly at fork time.

Raw: `scratchpad/qa1_out.txt`, `qa_daemon.log`, `coord/qa_golden.err`.
Harness note for reruns: all VMs share one stderr file; per-claim ERR
attribution added in workload2 (try/except + `CUDA_LAUNCH_BLOCKING=1`).

### QA-1b (2026-07-19, interim): NOT a cold-kernel problem — plain-torch fork path is broken, 3 distinct bug candidates

Phased discriminator (same guest/workload, per-claim error attribution):

| Phase | Setup | Result |
|---|---|---|
| P1 | plain boot, ping | **val=51.049889** — kernel launch fine |
| P2 | forkable boot, ping before any fork | **val=51.049889** — identical (determinism), forkable session fine pre-fork |
| P3 | 1 fork (clone stopped), ping golden | **TIMEOUT** — warmed golden wedged after fork; no pong, no catchable error |
| P4 | fork again, ping | clone: **ERR CUBLAS_STATUS_NOT_INITIALIZED at cublasSetStream** |

So the QA-1 hypothesis (cold-kernel golden) is refuted: P2's golden had
launched kernels and P3 still broke it. Daemon log (RUST_LOG=info) pins
three separate bug candidates on the **plain-torch / native-allocator
(non-VMM) fork path**:

1. `[M3a-lazy] module reload failed: e=700 (ILLEGAL_ADDRESS)` ×3 per clone,
   `elf=false fatbin=true` (3.0 MB / 1.1 MB / 8.3 MB images, fatbin magic
   50ed55ba). cublas kernels live in fatbins → failed reload explains the
   clone's CUBLAS_STATUS_NOT_INITIALIZED (and QA-1's "unknown error"
   without CUDA_LAUNCH_BLOCKING). On sm86, engine cfae06d — i.e. *after*
   the sm90 byte-identical-reload fix landed; possible regression or a
   second reload path bug.
2. `clone-worker spawn failed; rejecting the clone connection error=no
   golden layout for token token=1` — repeated rejects; 3 forks issued but
   only 2 clones ever routed to workers (race between clone connect and
   layout staging?).
3. Golden compute breaks after fork+staging (P3 hang; QA-1 golden death) —
   possibly a side effect of staging the golden's cudaMalloc regions, or of
   stopping a clone mid-resume.

**Scope note:** the validated vLLM serving path uses
`expandable_segments:True` (VMM), and the training demos exercised clones
that were warmed differently — this plain-torch path (default PyTorch
allocator, no VMM) is its own code path (`stage_alloc_copies` → translated
private copies) and is currently broken locally. Next: A/B
`SMOLVM_CUDA_ADVERTISE` (12040 vs 13020), re-validate the vLLM
expandable-segments fork path on this engine build, and bisect the fatbin
reload failure.

### QA-1c/1d (2026-07-19): not an advertise regression; the FORKABLE session itself breaks vLLM load — bisect launched

- **QA-1c A**: plain-torch fork path with `SMOLVM_CUDA_ADVERTISE=13020` —
  pre-fork matmul PASSES, post-fork still fails (`unknown error`). The
  fork-path breakage is **independent of the advertised CUDA version**
  (rules out PR #681 as the cause).
- **QA-1c B**: harness bug (missing vLLM platform-detect patch), rerun as
  QA-1d.
- **QA-1d**: vLLM golden (exact validated recipe: V0, expandable_segments,
  warm HF cache) **fails during model load — before any fork — but only
  when started `--forkable` with the fork-workers daemon**:
  `RuntimeError: The specified pointer resides on host memory and is not
  registered with any CUDA device.` The identical non-forkable config
  passed the same night (regress_check REGRESSION-FIXED). So `--forkable`
  is the trigger, and the failure is in host-pinned-memory handling.
- **Engine archaeology**: only 5 commits sit between v1.6.12+#675 (the
  engine that demonstrably forked vLLM on the A100/l8 runs) and current
  HEAD cfae06d: 9e62059 (zombie reap), 417b192 (cu13 guest surface —
  126 lines of cudart-shim changes incl. symbol-gap work), 5f65319
  (PR #677: re-key golden exec overlay to clones), f681426 (attr replay +
  crash handler), cfae06d (cu12 advertise default). Prime suspect:
  417b192's cudart-shim host-alloc surface changes.
- **QA-1e bisect running**: per-commit build (engine + both shims staged
  together for proto-hash consistency), two signals per commit — PT
  (plain-torch forkable fork/compute) and VL (vLLM forkable load + fork +
  serve). Raw: `scratchpad/qa_bisect_out.txt`, `bis_<commit>_daemon.log`.

**Operational note (H100):** the comprehensive suite's fork phases (C–E)
would hit both bugs, so only the fork-independent phases A+B were launched
on the H100 while the bisect runs; C–F wait for a known-good engine pin or
a fix.

### QA-1i + bisect v3 (2026-07-19): ROOT CAUSE NARROWED — clone-worker fatbin reload (e=700) breaks cublas in clones; flaky by ordering; present since ≤ v1.6.12

- QA-1i A: 24×64 MB ballast fails post-fork identically → allocation-shape
  hypothesis refuted.
- QA-1i B (vLLM eager, golden + 2 forks): **one clone served correctly**
  (17.3 s first request incl. lazy reloads, then healthy), **the other died
  with `cublasGemmEx CUBLAS_STATUS_NOT_INITIALIZED`**, and on a follow-up
  ping a previously-healthy VM degraded to `unknown error`. Clone health is
  **probabilistic**, not deterministic.
- Bisect v3 (debian guest, real per-commit builds): v1.6.12 / 9e62059 /
  417b192 all fail the post-fork cublas matmul → present since ≤ v1.6.12
  in BOTH guest types.
- **Synthesis:** the QA-1b daemon evidence (`[M3a-lazy] module reload
  failed: e=700 ILLEGAL_ADDRESS`, ×3 fatbins per clone incl. multi-MB
  cublas-sized images) is the primary defect. Clone workers lazily reload
  golden modules; fatbin reloads sometimes hit e=700 → any library whose
  kernels live in those fatbins (cublas/cublasLt) is dead in that clone →
  `NOT_INITIALIZED`/`unknown error` on first GEMM. Triton workloads
  (unsloth demos) JIT fresh cubins per clone → always survive; that's why
  every historical training validation passed while cublas-dependent
  clone workloads (torch matmul, vLLM inference) are coin-flips. The l8
  A100 vLLM forks were the lucky path (and/or sm80 ordering differs).
- **Impact:** this is the flagship inference-fork scenario. Minimal 3-min
  repro: PT-debian harness (`qa1f.sh` shape). Fix target: the M3a lazy
  reload path (`host.rs` module staging / worker reload); QA-1b's raw
  logs name the failing images (fatbin magic 50ed55ba, 1.1/3.0/8.3 MB).

### QA-1j (2026-07-19): THE DECODE — post-fork failures are memory exhaustion with catastrophic error masking

Staged post-fork probes (sync → elementwise add → cublas matmul) in the
responding VM: **`sync=OK` (context healthy — the "poisoned context" theory
is out), `add=ERR: CUDA out of memory. Tried to allocate 1.50 GiB (7.66 GiB
total)`, `matmul=ERR: CUBLAS_STATUS_NOT_INITIALIZED`.**

Unified explanation of the whole local cluster: **copy-mode fork more than
doubles GPU residency** (golden working set + exportable staging + clone's
private copies). On the 8 GB RTX 3070 with a 1.6 GB-ballast workload plus
a 1.5 GB transient, that's genuine VRAM exhaustion — surfacing not as a
clean OOM at fork time but as downstream `CUBLAS_STATUS_NOT_INITIALIZED`
(cublas workspace alloc fails), `CUDA error: unknown error` (async alloc
failures), and even `[M3a-lazy] e=700` module-reload fallout. It explains:
why 40/80 GB cards passed everything (headroom), why the share-weights
demos pass locally (+~300 MB per clone instead of +2×), why clone health
was *flaky* (allocation timing races), and why local vLLM at GPU_UTIL=0.5
(4 GB engine) could never copy-fork twice on an 8 GB card.

QA-1k verifies: small-ballast (256 MB) plain-torch copy-fork and vLLM at
GPU_UTIL=0.2 with 2 forks — all VMs should pass all probes/serves.

**QA-1k result — OOM was only half the story:** with the small footprint,
post-fork `sync=OK` AND `add=OK` (the elementwise failure was indeed pure
memory pressure), but **`matmul` still fails with `CUDA error:
initialization error` despite ~4.5 GB free** — a genuine,
memory-independent defect: cublas handle (re-)initialization in a forked
VM. Mechanism hypothesis: cublasCreate lazily loads cublas' kernel fatbins;
in a clone worker those module loads fail (QA-1b's e=700 evidence) →
cublas init fails → `initialization error` / `NOT_INITIALIZED` — while
already-initialized handles sometimes survive (QA-1i's one healthy clone;
flakiness = which VM answers and whether its handle predates the fork).
(QA-1k's vLLM arm hit the known V0-profiler floor at GPU_UTIL=0.2 on 8 GB
— harness config error, disregard.) Next: RUST_LOG=debug daemon trace to
name the exact failing driver op in the clone worker.

**H100 sm90 probe (in-VM GEMM matrix): cublas, cublasLt, bmm all PASS**
under both allocator configs with zero daemon errors — basic sm90 GEMM
through the shim is fine; the phase-B vLLM failure is init-at-scale
specific (size-bisect probe running). Also: the "Attempting to run cuBLAS,
but there was no current CUDA context" warning appears in PASSING probes —
it's benign through the shim, not a diagnostic signal.

**The real engine bugs if confirmed:** (1) fork should compute the memory
bill up front and fail loudly ("clone needs N GB, M free") instead of
letting clones limp into masked OOM; (2) staging should release eagerly;
(3) the graph-capture-in-forkable failure (QA-1g/1h BUG A) remains a
separate real bug, as does the H100 in-VM cublasLt init failure (non-fork,
80 GB free — not OOM; cublasLt-log diagnostic running).

### sm90 in-VM vLLM: SOLVED (2026-07-19 ~10:05, commit 2ef7a8f) — three stacked shim bugs, closed with instrumentation in one morning

Fresh H100 (`e846e470`, us-southeast-1). The pid-tagged op log named each
layer in minutes:

1. **Fatbin container chains truncated** (`cuModuleLoadData` → 209
   NO_BINARY_FOR_GPU): the shim's image-length parser read ONE fatbin
   container; nvcc/cuBLAS emit back-to-back containers and sm90 SASS lives
   past the first (sm80/86 SASS sits in part 1 — why A100/3070 never
   noticed). Fix: walk every consecutive container (capped at 128 MB
   against runaway .rodata neighbors).
2. **Real driver version leaked to the guest**: `cuDriverGetVersion`
   forwarded post-connect and `cudaRuntimeGetVersion` HARDCODED 13000 —
   on this CUDA-13-generation box, guest cuBLASLt negotiated cu13 entry
   points the shim only partially provides. Fix: advertise
   `SMOLVM_CUDA_ADVERTISE` (default 12040) unconditionally from both shims.
3. **Hopper TMA descriptors unsupported**: with versions right, cuBLASLt
   correctly selects sm90 kernels — which need `cuTensorMapEncodeTiled`
   (stubbed NOT_SUPPORTED → "Failed to initialize the TMA descriptor 801"
   → NOT_INITIALIZED). Fix: forward the encode over the generic LibCall
   transport (lib 6/func 0, no proto change), with the global address
   passing through the clone dptr translation; the daemon returns the
   128-byte CUtensorMap.

**Result: first-ever sm90 in-VM vLLM serving** — correct generations,
392 ms/req, V0+eager, no workaround flags. The clean native-vs-VM A+B
comparison suite is running on the same box. (Also relevant beyond H100:
TMA is required by FA3, newer vLLM, and everything Blackwell.)

### H100 chapter closed (2026-07-19 05:20): instance terminated after full diagnostic sweep; sm90 in-VM vLLM bug documented as OPEN — superseded by the SOLVED entry above

Final state of the H100 investigation (instance `cbb9b139`, ~6 h ≈ $26,
terminated + verified):

- **Native H100 numbers, replicated ×3** (v1/v2/v3 runs): load→serving
  12.5–12.7 s; batch-1 p50 68–69 ms / p99 69–71 ms; batch-40 ~3,580–3,600
  tok/s; batch-160 ~9,170–9,215 tok/s. Excellent reproducibility — these
  are blog/paper-grade.
- **In-VM vLLM on sm90: OPEN BUG, never passed.** First `cublasLtMatmul`
  in engine init → `CUBLAS_STATUS_NOT_INITIALIZED`. Systematically ruled
  out: cu13 advertisement (fixed, still fails), stale shims (rebuilt at
  cfae06d), recv-timeout drops (retracted red herring), OOM/size (fails at
  GPU_UTIL=0.05 with 0 MiB pre-used), shape/dtype (exact failing linear
  1152×2048×896 passes standalone in-VM, fp16+bias, bf16, 4096²), vllm
  import side effects (linear passes after `import vllm`), alternate
  attention backends (unavailable in this venv: xformers built without
  CUDA; TORCH_SDPA invalid for V0). Remaining suspects: FA3 compiled-module
  (`_vllm_fa3_C`) lazy load, NCCL init, or another engine-init step unique
  to sm90. Blocker for offline work: the CUDA crates have **no per-op
  logging at any RUST_LOG level** — add op-stream instrumentation, then
  a ~15-min testbed session (~$1) can pin it.
- Raw archive: `scratchpad/h100_archive/h100_archive.tgz` (env
  fingerprint, all native/VM outputs + errs, probe series p3–p6, daemon
  logs, setup log).

### QA-1l (2026-07-19): ROOT CAUSE, log-confirmed — post-fork-opened guest channels are rejected by clone routing

Debug-daemon trace of the failing post-fork matmul shows the worker healthy
(`serving in its own context`, `lib_handles_seeded=1`), then, 150 ms later,
twice:

```
WARN clone reconnected while its worker is still alive; rejecting —
     a fresh worker would silently reset the clone's GPU state
```

**Mechanism:** guests hold multiple daemon connections. Channels that
existed at snapshot time resume into the worker (the benign
`clone resumed token N: 0 private copies` lines). But a channel the clone
opens *after* the fork — exactly what happens on first-ever cublas use,
since `cublasCreate` dials a fresh channel — presents the clone preamble,
matches a live worker in `route_clone_connection` (src/cuda_daemon.rs
~l.925), and is **rejected**. The guest library sees dead driver calls →
`initialization error` / `CUBLAS_STATUS_NOT_INITIALIZED`.

This closes the whole local cluster coherently:
- Goldens that exercised cublas pre-fork → channel in snapshot → resumes →
  clones healthy (unsloth demos, vLLM after a pre-fork request; the worker
  even re-seeds pre-fork cuBLAS/cuBLASLt/cuDNN handles via
  `replay_lib_handles` — the architecture intends this to work).
- First-cublas-in-clone → new channel → rejected → the QA repros' failures,
  flaky by channel timing.
- The reject was added for a real reason (a fresh worker would reset clone
  GPU state — the H100 reconnect-storm fix), but the correct handling for a
  *matching live* (token, clone_id) is to ATTACH the new fd to the existing
  worker (SCM_RIGHTS pass + multiplexed serve loop), not reject. Serving it
  in-daemon instead would split the guest across two UVA spaces — worse.

**Fix sketch:** daemon: on live-worker match, send the fd to the worker
over a per-worker control socketpair; worker: convert the single-stream
`serve()` into a poll loop over {primary fd, control fd, attached fds}
against the one backend (CUDA ops are already serialized). Regression test:
`qa1l.sh` (post-fork sync/add/matmul must all pass, first-cublas-in-clone).

### Fix progress (2026-07-19, branch `clone-channel-attach`, commit d99f3c4)

Implemented and verified layer by layer with the QA-1l harness:

1. **Channel attach (DONE)**: per-worker control socketpair; daemon
   SCM_RIGHTS-forwards each additional same-clone connection; worker serves
   each attached fd on its own thread (own backend handle, same primary
   context) seeded with clones of every thread-local translation table
   (modules/functions/streams/events, VMM map, staged-alloc map — plus a
   new non-draining `worker_alloc_trans_snapshot()`). Verified: "attached
   new clone channel to its live worker" + both sessions adopt the SAME 5
   translations (no split state); rejections gone.
2. **VA-guard (DONE)**: `mem_address_reserve_fixed` over every staged
   golden non-VMM region in the worker — fresh allocations could land
   inside golden VA ranges (they're unoccupied in translated-copy mode) and
   the RANGE-based dptr translation then rewrites fresh pointers into the
   staged copies (corruption) or past their end (async illegal address).
   Verified: the deterministic `[M3a-lazy] e=700` fatbin reload failures
   are GONE (0 in the guarded run; context-health probes had shown
   sync=700/alloc=700 — poisoned context, not bad bytes: the dumped
   fatbins load cleanly standalone via both cuModuleLoadData and
   cuLibraryLoadData).
3. **ROOT CAUSE FOUND AND FIXED (commit 7fe6550)**: LibCall tagging traced
   the poison to the cublas call burst — and the generated library
   dispatch (`smolvm-cuda-codegen`) emitted **raw `__c.u64()` for every
   DevPtr argument**: `cublasGemmEx`'s A/B/C, `cublasSetWorkspace`, every
   gemm variant — no `dptr_resolve`. (The typed-resolve fix from the
   earlier session covered only the hand-written cublasLt path; a stale
   comment claimed the generated dispatch resolved DevPtrs.) In a clone
   session, A/B are golden VAs — unmapped in the worker — so the real
   cublasGemmEx faulted async → sticky 700 → module-reload failures,
   NOT_INITIALIZED, "unknown error": the entire cascade. Fix: codegen now
   emits `super::dptr_resolve(...)` for DevPtr args (identity for
   non-clone sessions); regenerated = 71 resolved args in cublas, 4 in
   cudnn.
   **Regression GREEN**: post-fork `sync=OK | add=OK | matmul=OK:51.061905`
   — bit-identical to pre-fork, with first-ever-cuBLAS-init inside the
   clone, zero module reload failures.
   Corrections along the way: (a) an earlier "module reloads fixed by the
   VA guard" claim was a grep-pattern artifact — the guard alone did NOT
   stop the fault (it remains correct defense: without it, raw golden-VA
   reads could silently hit unrelated fresh allocations instead of
   faulting); (b) the `MemcpyGpaDtoH → status=500` entries are BENIGN
   (shared-daemon mode has no guest-RAM maps; guests fall back to
   socket-framed MemcpyDtoH — 0xb3→500 then 0x33).
4. **Validation matrix results (post-fix):**
   - Debian plain-torch fork (qa1l): **GREEN** — the fixed path.
   - vLLM (expandable_segments/VMM) forkable + forks: golden warm + serves
     pre-fork (384–503 ms), but post-fork responders hit `cublasGemmEx
     NOT_INITIALIZED`. First analysis (attached sessions re-running the
     `pending_isolate` copy branches against the primary's re-registered
     ranges) led to commit a847828: workers now skip the in-daemon
     isolate-copy branches entirely (correct in any case — worker VMM is
     address-preserved; copying live clone ranges into stale "private
     copies" was wrong). **Not sufficient**: post-fix, MORE VMs respond
     (attach working) but still `NOT_INITIALIZED`. Refined lead: that
     status is cublas rejecting a GARBAGE HANDLE — the guest's pre-fork
     cublas handle id is passing through `vh_resolve` unmapped on some
     clone channels, i.e. the vhandles adoption (HANDOFF registry keyed by
     a LUCKY collision between the guest's resume token and the worker's
     local `next_lineage_token()`) fails for some channel/session
     orderings in multi-channel vLLM guests. Next: oplog the vLLM repro
     worker-side and make the vhandles handoff explicit for attached
     channels (adopt from the primary session directly instead of via the
     token-keyed registry).

     **vh-miss instrumentation results (loop final state, commit c567520):**
     `[vh-miss] tagged handle 0x8000000000000006 unmapped` confirmed the
     class of bug, but neither registry-fallback adoption nor a fully
     SHARED per-worker handle map eliminated it (27 misses persist with
     the shared map). Conclusion: handle #6 is created in a DIFFERENT
     PROCESS than where it's used — the remaining suspect is
     `route_clone_connection`'s no-lineage-token path, which deliberately
     serves token-less clone-preamble connections IN-DAEMON ("fresh
     post-fork work"): a clone's new cuBLAS channel that Inits without a
     resume token mints its handle in the daemon while the GEMMs flow
     through the worker. NEXT FIX (unimplemented): route no-token
     clone-preamble connections to the live worker by clone_id (registry
     lookup ignoring token), falling back to in-daemon only when no worker
     exists. Verify afterwards with `val_vllm.sh` — expect 0 vh-misses and
     3/3 serving VMs.
   - Original QA-1 churn (PACK-ARTIFACT guest): still fails wholesale
     (no pongs from any VM, golden dead) — consistent with the bisect
     finding that artifact×forkable fails at every commit. This is a
     SEPARATE, still-unexplained dimension (guest-image-specific; possibly
     the artifact's extra layers mount or baked env interfering with the
     forkable snapshot). Open.

Diagnostics added along the way (both env-gated, worth keeping):
`SMOLVM_CUDA_DUMP_FAILMOD` (dump failing module images + post-fail
context-health probes) — `SMOLVM_CUDA_HOST_OPLOG` already existed.

### QA-1e (2026-07-19): bisect result — NOT a recent regression; suspicion moves to the pack-artifact guest

Per-commit rebuilds (engine + both shims staged together): **v1.6.12,
9e62059, and 417b192 all fail identically** (PT post-fork compute error, VL
`pointer resides on host memory and is not registered` at load). The
breakage predates every commit since v1.6.12 — yet v1.6.12+#675
demonstrably forked vLLM on the A100 (l8) and plain-torch on this same
3070 (fork-sweep demo). The variable nobody ever combined with `--forkable`
until QA-1: **the pack-artifact guest** (`--from smolvm-gpu-testbed.smolmachine`),
which post-dates those validations. Non-forkable + artifact passes
(regress_check); forkable + debian-image guest passed historically;
forkable + artifact fails. QA-1f runs the exact failing tests with a
debian-image guest to close the 2×2 matrix. Consistent detail: pack guests
carry an extra virtiofs (layers) mount and a different memory setup — a
plausible collision with forkable-mode guest-RAM registration (the
host-pinned-pointer error) and with post-fork module/context state.

### QA-1f + demo control (2026-07-19): guest type exonerated; engine exonerated; suspicion converges on default COPY fork mode

- **QA-1f (debian guest, forkable)**: fails identically to the artifact
  guest — PT post-fork `unknown error`, VL load `pointer … not registered`.
  Pack-artifact hypothesis refuted.
- Host environment checked: NVIDIA driver 610.43.03 + kernel installed
  Jul 9 (box up since Jul 11), libkrun bundle untouched since Jul 13 —
  no environment drift since the last passing fork runs.
- **Control: `unique-demo.sh` rerun verbatim on the same binary — PASSES
  end-to-end today** (4×0.4 s forks, 4 concurrent QLoRA clones, kill -9
  isolation, adapters saved). Engine + box are fine for the demo shape.
- **The discriminating variable, found by config diff:** every historically
  successful fork flow used weight sharing (demo: global
  `SMOLVM_CUDA_FORK_SHARE_WEIGHTS=1`; every l8 fork: `--share-weights`).
  The QA repros are the first exercises of the **default COPY mode** with
  these workloads on this box. Unified theory: forkable+COPY sessions
  prepare to stage all golden memory at fork, interposing (virtualizing)
  host-pinned allocations — so vLLM's weight loader trips
  "pointer resides on host memory and is not registered" *pre-fork*, and
  the COPY-mode staging/translated-copies path breaks post-fork compute
  (fatbin reload e=700, context loss). QA-1g reruns QA-1f with share-mode
  parity (daemon env + `--share-weights` forks) to confirm.
- If confirmed: production impact is real — COPY mode is the DEFAULT
  (`--share-weights` is opt-in), so any user forking without the flag hits
  this. Either fix the copy path or make the failure loud.

### QA-1g/1h (2026-07-19): share-mode refuted; TWO bugs isolated — vLLM graph capture in forkable sessions, and the reconnect-resume cublasLt gap

- **QA-1g** (share-weights parity: daemon env + `--share-weights` forks):
  fails identically → share-vs-copy mode refuted as the discriminator.
- **Full vLLM traceback read**: the forkable-session load failure is in
  `capture_model → weak_ref_tensor → torch.ops._C` — i.e. **CUDA graph
  capture**, after weights loaded fine. Config archaeology:
  `vllm_compare.py` (used by every prior validation incl. l8, the A100/H100
  baselines, regress_check) sets **`enforce_eager=True`** — so graph
  capture in a forkable session had never been exercised anywhere.
  **BUG A: vLLM CUDA-graph capture fails in forkable sessions**
  (`pointer resides on host memory and is not registered` from the pointer-
  attribute query during capture). Production-relevant: vLLM defaults to
  graphs (V0 non-eager and all of V1).
- **QA-1h with `enforce_eager=1`: vLLM forkable now loads, serves pre-fork
  (382 ms), forks, and a post-fork VM serves the CORRECT generation**
  (first post-fork request 18.4 s = lazy module reload cost). One of two
  VMs didn't answer within 90 s — follow-up running with attribution
  (pid/hostname in pongs) and longer waits.
- **QA-1h PT (rich warmup: pinned+pageable H2D, varied kernels): still
  fails post-fork** — warmup shape refuted. Remaining suspect: allocation
  shape — the failing workload holds a single 1.6 GB tensor (the copy
  stager granularity-merges regions); the passing unsloth demo holds
  hundreds of small allocations. QA-1i tests 24×64 MB ballast.
- **BUG B (H100 phase B) — first theory RETRACTED, trace running.** The
  reconnect-resume story was a red herring: healthy local runs show the
  same `clone resumed token N: 0 private copies` lines and the same 4
  spaced daemon connections at boot — that's normal session setup, not
  drops. (The recv-timeout bump 10→60 s / 45→90 s was applied anyway —
  harmless robustness — and did NOT fix phase B.) Current facts: in-VM
  vLLM on the **H100 (sm90) fails at the first `cublasLtMatmul` with
  `CUBLAS_STATUS_NOT_INITIALIZED`** under cu12 advertisement, while the
  identical config passes on A100 (sm80) and RTX 3070 (sm86). Working
  hypothesis: sm90 cublasLt requests `cuGetProcAddress` entry points the
  shim doesn't export (arch-dependent init path). The shim has
  `SMOLVM_CUDA_SHIM_TRACE` which logs lookups incl. SYMBOL_NOT_FOUND —
  a traced repro is running on the box to name the missing symbols.

**H100 phase A+B (first pass): native A numbers landed** (12.7 s load,
b1 p50=69 ms p90=69 p99=71, b40 ~3,604 tok/s, b160 ~9,196 tok/s —
replicates the earlier session's 3,538/9,083). Phase B failed with the
cu13-advertise signature (`CUBLAS_STATUS_NOT_INITIALIZED` at
`cublasLtMatmul`): the box's guest shims were self-built from source rsynced
*before* the cu12-advertise fix. Source repushed at cfae06d, box shims
rebuilt, phase B rerun pending. (The A100 box passed B because its source
came from the updated testbed FS — same engine, different staleness.)

### Session context (2026-07-19)

- Remote runs in flight: A100 native-vs-VM baselines v3 (native phase done:
  load 56.3 s, b1 p50=94 ms p90=98 ms p99=128 ms, b40 ~2,320 tok/s,
  b160 ~5,920 tok/s), H100 comprehensive suite v2 (setup phase).
- These native numbers already bound the remoting tax measurement; VM phase
  pending.

## 2026-07-19 night — P3b root-caused and SOLVED: graph-mode clones serve

**Symptom stack (graphs-mode forks, local 3070):** clone requests failed
`CUBLAS_STATUS_NOT_INITIALIZED` at prefill GemmEx (or, with replay gated
off, `invalid argument` at decode graph launch). Instrumented every stage
(`[p3b]` trace): recording (35 graphs × 1202 ops), blob staging, and clone
adoption all green — but NO replay lines: the failure preceded any
`GraphLaunch`.

**Evidence that cracked it:** daemon log showed `[cuda-clone-worker] FATAL
signal 11` ×4 with empty backtraces — workers died BEFORE the guest's first
channel attach; every guest-visible cuBLAS error was fallout from a dead
(then respawned-empty) worker. `coredumpctl` on the 1.3 GB core:
`cublasSetStream_v2 → cuStreamGetGreenCtx → SEGV_ACCERR`.

**Root cause 1 (the segfault):** `stream_resolve` — the generated
lib-dispatch resolver for every `Stream`-typed arg — never applied
`xlat_stream` (M3a golden-raw → worker-raw). Raw-stream guests pass the
golden's heap pointer; the worker fed it straight to cuBLAS, which
dereferenced a foreign address. Eager torch uses stream 0 (no deref) —
which is why ONLY graphs mode crashed. Fix: apply `xlat_stream` in
`stream_resolve` (one line; same class as the typed-dptr_resolve fix).

**Root cause 2 (why replay is mandatory):** `CUgraphExec` is
process-local — a worker clone can never launch the golden's exec verbatim,
and node rebuild can't reproduce cuBLAS-emitted kernels. Capture-replay
with an eager WARMUP pass (binds library streams/workspaces outside the
capture window) re-captures in the clone's context; all pointer/handle
translation applies via normal re-dispatch.

**Gate result:** golden 95 ms pre-fork; both clones serve correct output —
first request 5.1/6.6 s (lazy reload + one replay), steady-state
**215/183 ms vs 609/510 ms eager** (~2.8×). Zero segfaults. Replay:
`1202 ops {LaunchKernel: 146, LibCall: 1056} → re-captured OK` per clone.
Default ON; `SMOLVM_CUDA_CLONE_GRAPH_REPLAY=0` opts out.

## 2026-07-19 late — edge case: stale-VM protocol-mismatch retry spam

A leftover golden VM from an earlier session (old shim build) kept
reconnecting to the shared daemon after a binary swap changed the wire
hash. The daemon refuses each attempt correctly ("PROTOCOL MISMATCH ...
Refusing the connection"), but the stale guest retries in a tight loop —
and while it spams, a FRESH golden's vLLM load hangs silently (empty
stderr, no WARM-READY; two multi-graph gate runs lost to it). Removing the
stale VM restores normal loads. Takeaway for shared-daemon deployments: a
version-mismatched guest is not inert — its reconnect storm degrades
service for healthy VMs. Candidate hardening (not implemented): daemon-side
per-source backoff after repeated hash-mismatch refusals, and/or a shim
that gives up after N refusals instead of retrying forever.

**CORRECTION (same night):** the stale VM was a red herring — the mismatch
client was the FRESH golden itself. After cherry-picking the P3b branch
onto main, only `-p smolvm` was rebuilt; the guest shims in
`target/release/` were still the old-lineage build, so every fresh guest
was refused (hash ca6612e1 vs d0cef4bb) and vLLM load hung. Rebuilding all
three artifacts fixed it. Two lessons re-learned: (a) the "rebuild shims
WITH the binary" footgun (QA-LOG passim) applies to BRANCH SWITCHES too,
not just proto edits — PROTO_HASH differs across lineages even when
proto.rs is textually identical; (b) the loud refusal worked as designed —
the failure mode was the HARNESS not surfacing it (vLLM hangs silently
with an empty stderr; the mismatch only shows in the daemon log). The
stale-VM reconnect-storm observation stands as a real hardening candidate,
but it was not the cause here.

## 2026-07-19 late — P3b multi-graph replay stress: GREEN

Gate: vLLM graphs golden + 2 share-weights forks; per clone: batch-1
(replays graph A) → batch-8 (replays graph B) → batch-1 (A intact?) →
batch-8 (steady). Result: all green — 2 distinct execs replayed per clone
(`1203 ops → re-captured OK` ×4), batch-8 lanes all agree (n=8 agree=8),
graph A still correct after B's replay, 0 segfaults, 0 replay failures.
Latencies: b1 first 6.7/5.1 s → 231/236 ms; b8 first 348/329 ms →
511/505 ms (the b8 "steady" being slower than its first hit is contention
noise — both clones ran b8 concurrently in both phases; not a regression
signal). Multi-graph replay and post-replay graph integrity validated.

**Copy-mode (no --share-weights) graphs gate: GREEN, with a caveat.** Same
4-phase multi-graph sequence, all correct (2 execs replayed per clone, 0
faults). Caveat discovered while verifying: with expandable_segments the
clone is fully address-preserved either way (`0 private copies`), so BOTH
green runs exercised identity translation only. The truly translated path
(dptr_trans non-empty) needs a DEFAULT-allocator workload with graphs —
probe built (`qa_graph_fork.py` + `val_graph_dptr.sh`: plain-torch
cudaMalloc tensors, cuBLAS matmul captured in a torch.cuda.CUDAGraph,
fork 2 clones, replay with fresh inputs vs eager check), result pending.

## 2026-07-19 latest — translated-clone graph replay: found broken, root-caused, FIXED

The QA loop's ground-truth probe (plain-torch cudaMalloc tensors + captured
cuBLAS matmul + 2 forks — the first test where clones get TRANSLATED
private copies, dptr_trans non-empty) caught what the vLLM gates could
not: `ok_gpu=True` while `ok_cpu=False` — the graph AND the eager GEMM
agreed with each other but both computed from wrong memory (stale
fork-state in one run, zeros in another, `unknown error` crashes in a
third; timing-dependent). H2D/D2H readback meanwhile saw fresh data
(asum tracked every update).

**Root cause:** the lazy replay captured on the clone's LIVE remapped
stream. The guest's own traffic (arriving concurrently on other channels)
raced the capture window — guest ops got absorbed into or collided with
the capture. The vLLM gates stayed green only because v0's blocking decode
kept the guest quiet during replay; the plain-torch probe's independent
channels exposed the race.

**Fix:** replay on a PRIVATE worker stream — all recorded streams are
temporarily redirected onto one fresh stream via the stream-translation
map (warmup + capture both), then restored and the stream destroyed.
Linearizing a multi-stream DAG is dependency-safe (only intra-graph
parallelism is serialized).

**Result:** truth probe fully green — both clones, both rounds,
`ok_cpu=True` with fresh values matching CPU ground truth; first replay
16.8 s → ~2 s; steady-state graph replays **18-19 ms**; no hangs. vLLM
multi-graph regression re-run pending. The QA-loop lesson: "replay==eager"
is NOT a sufficient correctness oracle — both can be wrong together; a
host-independent ground truth (CPU matmul) is what caught this.

## 2026-07-20 — fork-time pre-warm: first clone request 7 s → 1.6 s

Asked for "fork-time pre-replay"; profiling kept moving the target, three
layers deep:

1. **Resume-time pre-replay + module preload** (35 graphs ~0.4 s, 627
   modules ~1.3 s) worked mechanically but didn't move the first request —
   phase-split timers (`sync=` vs `gen=`) showed generate was ALREADY at
   steady state (~230 ms) and the entire ~6.5 s was the guest's first
   `torch.cuda.synchronize()`. A cross-thread flaw surfaced en route:
   MOD_TRANS was thread-local, so each serve thread silently RE-loaded
   every module (fixed: process-global module registry — also a real VRAM
   dedup win).
2. The first sync is when the WORKER SPAWNS: route_clone_connection spawns
   on the clone's first CUDA connection, so CUDA init + memory
   reconstruction + staging + pre-warm all sat on the first request.
3. **Eager warm dial**: the clone VM proxy dials the daemon at STARTUP
   with a warm-flagged preamble (bit 1); the daemon spawns the worker
   immediately, inferring the golden from registered layouts (content
   filter + Arc-identity dedup — every channel token shares the golden's
   layout Arc). Two follow-on fixes: tokened channels attach to ANY live
   worker for their clone_id (the warm worker may be registered under an
   inferred token), and graph adoption became registry-FIRST (the resumed
   session can serve on an attached thread whose thread-local oplogs were
   never seeded; the process-wide registry is the truth — without this,
   launches fell through to the broken patch path: "unknown error").

**Result (3070):** toy probe first request 2.7-3.4 s → **305/301 ms**
(steady 20/37 ms). vLLM graphs gate first request 6.7/7.9 s →
**4.0/1.6 s** (1.6 s = the floor; the 4 s clone contended with its
sibling's simultaneous ~1.7 s pre-warm on one GPU), steady-state
**170-218 ms** — the best clone numbers measured. All correctness gates
green. Spawn pre-warm: 627 modules + 35 graph re-captures ≈ 1.7 s,
fully overlapped with guest resume.

**Graphs churn gate (4× fork/serve/kill/refork): 4/4 green, 0 worker
leaks.** Cycle 2's first request hit FULL steady state (186 ms, sync=0):
with ~4 s of post-fork idle, the warm chain hides clone warm-up entirely.
Board clear: multi-graph, copy-mode, translated ground-truth, replay race,
eager regression, and churn all green on PR #695 head.

## 2026-07-20 — N≥3 concurrent clone TRAINING nan: ROOT-CAUSED (H100, 7B QLoRA)

**Symptom:** golden + N `--share-weights` forks each QLoRA-training a distinct
data shard. N=1, N=2 correct (distinct loss curves → ~7.2). N≥3: loss=nan,
and the FIRST forward is already corrupted (loss0 21.9 vs correct 16.965) for
~half the learners → cross-clone interference, not per-clone divergence.

**Discriminators:**
- Worker routing: 3 clones → 3 DISTINCT worker PIDs/contexts (not misrouting).
- Copy-mode N=3 (no --share-weights, private base per clone): CLEAN
  (16.97→7.25, 16.46→7.34, 17.08→7.27). ⇒ the SHARED base is the culprit.

**Root cause (cuda_daemon.rs reconstruct_golden_memory):** `--share-weights`
imports the golden's frozen base and maps it **READ-WRITE**, shared as the same
physical GPU memory across all clones. The COW isolation only catches EXPLICIT
mem-op writes — "kernel outputs are undetectable" (its own comment). Unsloth
writes the base via a KERNEL (fix_untrained_tokens embedding fix); the code knew
and assumed those writes are "identical across clones." True enough to survive
N=2, but at N≥3 the concurrent kernel writes race on the shared physical → all
sharers corrupt.

**Fix attempts:**
- Map shared base READ-ONLY (mem_set_access_ro, flags=1): worker SIGSEGV —
  confirms a kernel really writes the base; read-only makes it fatal. Not a
  drop-in fix (kept behind SMOLVM_CUDA_SHARE_RO=1 as a diagnostic).
- **Correct path shipped:** copy-mode (the default) is correct at all N; the
  density opt-in (--share-weights) is safe only for base-read-only workloads /
  N≤2. Proper density-preserving fix = private-copy ONLY the kernel-written
  ranges (embedding/lm_head), share the rest read-only — future work.

**Implication for the training-infra story:** the 17GB-vs-31GB density win
requires --share-weights, which is currently N≤2-safe for Unsloth-style
training. Copy-mode gives correctness at all N but ~container-equivalent VRAM.

## 2026-07-20 — N≥3 concurrent clone training nan: SOLVED (golden warmup)

Confirmed the root cause and shipped a fix. Base-weight checksums across 3
clones at fork are IDENTICAL (ck_embed/ck_q0/ck_qN all equal) → the IPC
sharing is correct; corruption is a POST-fork training write to a chunk the
daemon's content-verification (share only if content == initial H2D upload)
mis-marked as frozen. Cause: in a fork-sweep the golden loads the model then
FREEZES at the barrier WITHOUT running the training path, so any chunk the
forward/backward writes in-place was never dirtied in the golden → passes
verification as shared → clones' concurrent writes race on it at N≥3.

**Fix: warm the golden with ONE training step before fork** (GOLDEN_WARMUP in
the workload). This dirties every training-written chunk in the golden, so the
daemon marks those private per-clone; the genuinely-frozen base stays shared.

**Result (H100, 7B QLoRA, N=3 share-weights):** all 3 learners train CORRECTLY
(16.99→7.27, 16.48→7.33, 17.11→7.32), no nan, distinct curves. shared=260
private=227 (was 261/69 when broken). Fork 0.43s/clone. Density (clean):
container N=3 = 23.2GB; smolvm N=3 = <pending clean re-measure>. Cost: the
golden's first training step is slow (Triton JIT-compiles every training
kernel + eager-remoted backward — one-time, amortized over N clones).

**Smolvm-side implication:** share-weights correctness REQUIRES the golden to
have exercised the workload's write path before fork. Documented as a
requirement; a future guard could refuse/​warn if share-weights is requested
before the golden has run representative compute.

## 2026-07-20 — throughput analysis: op-trace tax + transport-bound training

**Op-trace logging is a 39% tax.** N=1 7B QLoRA: 257 tok/s with
SMOLVM_CUDA_HOST_OPLOG=1 (+RUST_LOG=info) vs **357 tok/s with logging off**
(RUST_LOG=error, no oplog). Production must never enable HOST_OPLOG — it's
a debug-only per-op eprintln. Free win; all benchmark harnesses had it on.

**Training is transport-bound, not compute-bound.** Native single-learner
2,507 tok/s (0.4 s/step) vs remoted 357 tok/s (2.87 s/step) → the H100 is
IDLE ~86% of each step waiting on the VM-boundary transport. Op-coalescing
already exists (client `wbuf` batches quiet launches "a thousand syscalls
into a handful"), so the residual tax is the SYNC round-trips (allocations,
loss readback, stream syncs) that each cross the guest↔host boundary and
can't be batched. Sync-op breakdown via SMOLVM_CUDA_COUNT_SYNC in progress
to find the dominant sync to cut. The big structural lever (clone rings,
shared-memory transport) stays libkrun-blocked (P2b); near-term levers are
reducing sync count + dropping the per-VM proxy hop.

## 2026-07-20 — DAX mappings DO NOT survive fork (verified locally, 3070)

Reproduced on the 3070 (val_dax_inherit.sh): a golden mmaps a file on a DAX
virtiofs mount, writes to it in a loop; the loop continues in the clone after
fork. Golden heartbeat advances (99→199, mapping live); post-fork the clone's
writes via the SAME inherited mapping STOP (199→199) and the clone SIGSEGVs.
Touching an inherited-then-DAX page in the clone faults.

**Implication:** DAX is FRESH-MMAP-ONLY across fork. Safe for the clone ring
files (freshly mmap'd on fork-detect — that's why file-rings work). UNSAFE for
any mount the clone reads via mappings inherited from the golden — including a
DAX venv mount (torch .so pages) or a DAX model mount (safetensors mmap). This
was the H100 `SMOLVM_MOUNT_DAX=1` training `done=0`: clone .so/safetensors
pages died on resume. `SMOLVM_MOUNT_DAX` stays OPT-IN/default-off; the load-hang
fix is non-DAX (page-cache warm now; block-disk model staging is the durable
fix). LESSON: verify VMM/fork behavior on the local 3070 before spending remote
H100 time — this took 5 min locally vs multiple H100 runs.

## 2026-07-20 — DAX fork issue ROOT-CAUSED and FIXED (libkrun PR #43)

Root cause (code-level, libkrun): smolvm's fork is manifest-based — the clone
is a fresh process that CoW-maps the golden's memfd RAM regions, but the DAX
window is an ANONYMOUS guest-memory region, and `open_cow_memory_from_pid`
gives anonymous regions a fresh ZEROED mapping. The virtiofs `setupmapping`
`mmap(MAP_SHARED|MAP_FIXED)` calls that populated the golden's window were
fire-and-forget — nothing recorded them — so the clone's restored guest kernel
still holds DAX page-table entries into a window that is now all zeros. The
guest reads zeros where file pages were (torch .so text, safetensors) and its
processes SIGSEGV. Not a CUDA bug at all.

Fix (libkrun `dax-fork-replay`, PR smol-machines/libkrun#43): track live
SETUPMAPPING/REMOVEMAPPING state in the passthrough server (`dax_maps`,
keyed by window offset), serialize it in `FuseServerState` (which already
crosses the fork and rebuilds inodes by host path), and replay each mmap
into the clone's window in `FsWorker::new` — after the inode map is rebuilt,
before the guest resumes.

Validated on the 3070 (val_dax_inherit.sh, patched libkrun BLK=1 NET=1 from
bundle-rev+1): clone's inherited-DAX writer ADVANCES post-fork (508→707),
zero guest errors, and the inherited read-only torch libc10.so DAX pages read
correctly (chk!=0) — the exact training failure mode. Non-DAX fork regression
run: clean.

Why this matters: DAX mounts now survive fork, so the venv/model mounts can go
DAX — removing the FUSE READ path that causes the golden-load slow mode (159s
load seen again on the H100 this run vs ~15s normal), and letting N clones
share ONE host page-cache copy of the model weights. Next: rebuild libkrun on
the H100 box and rerun the DAX training sweep.

## 2026-07-21 — DAX fix live on H100; new finding: all-DAX training clones hang at first CUDA op

Deployment lessons (H100): (1) libkrun built on the box booted guests that
panicked at ~1.5s ("boot process exited code 0") — root cause: no musl rust
target on the box, so the embedded guest init was DYNAMICALLY linked and died
as PID1. `rustup target add x86_64-unknown-linux-musl` + forcing the
init_blob build script to re-run fixed it. This retroactively explains the
earlier "instrumented build broke boots" mystery (same box, same missing
target) — it was never commit drift. (2) The init_blob musl probe is cached
by cargo; `touch src/init_blob/build.rs` after adding the target.

DAX smoke (golden + 2 clones, all 3 user mounts dax=always, patched libkrun):
- Fork-replay fix VERIFIED on H100: clones resumed, wrote claim files through
  the DAX rw coord mount post-fork (pre-fix this segfaulted instantly).
- golden_load_s=166s — DAX did NOT fix the slow load. The load bottleneck is
  not FUSE READs; leading suspect is the 14 GB weight upload through the
  remoting transport (~90 MB/s ≈ 155 s) — measure next.
- NEW DEFECT: both clone learners hang at their first CUDA op post-fork.
  Daemon: only ONE of two clone workers spawned; that one went silent after
  "[ring-file] file rings active" (0 FATALs, 0 ops). Guest: no segfault, no
  traceback; python alive-but-blocked. Suspect: DAX user mounts interacting
  with the CUDA warm-dial/ring attach at fork (ring mount was always-DAX and
  fine; all-DAX venv/drvlib/coord is the new variable).
- Next: reproduce on the local 3070 (fork-sweep demo + SMOLVM_MOUNT_DAX=1)
  per the local-first rule.

## 2026-07-21 — clone first-op reliability: three fixes landed, one tail remains

Root-caused the "one stranded learner per fork leg" (7/8, 15/16 on H100; ~50%
single-clone failure locally). Layered causes, all in the clone worker path:
1. TRANSPORT RACE (fixed): a clone's inherited connection dies at fork but the
   pre-call liveness peek can miss it — the first CUDA op surfaced transport
   death as CUDA 999. Fix: classify transport failures in the shim and retry
   exactly once after the forced reconnect (launch/malloc/free/memcpy + the
   existing retrying wrapper, flag-based). Minimal probe: 0-of-~half → 7/7.
2. WORKER SEEDING GAPS (fixed): thread_local alloc-translation was drained by
   whichever session hit PrimaryCtxRetain first (and its owner could FREE the
   clone's copies on close); module images + function metadata were per-thread
   too, so unseeded threads passed RAW GOLDEN HANDLES to the driver — launch
   "invalid argument" at best, SIGSEGV in cuModuleGetFunction at worst (the
   H100 crash-loop signature). Fix: process-global registries + ownerless
   adoption (copies live for the worker's lifetime).
3. REMAINING TAIL (open): trainer-init in clones still fails "invalid
   argument" AFTER a clean reconnect (traced: reconnect ok, then set_last(1)
   with empty frames). Not the attrs-memoization (zero-guards produce sane
   fallbacks). Next: per-wrapper error naming on the reduce-path candidates to
   pin the op. Reproducible in ~5 min via scratchpad val_trainer.sh.

Also: fork_err files are written by the workload itself; shim trace goes to the
detached container's stderr (invisible) — probes must capture stderr to coord.

## 2026-07-21 — clone trainer-init tail: classification via pre-fix baseline

The local 0.5B trainer/demo failures are NOT a regression from the clone
fixes: the identical control (proven H100 sweep workload qlora_train.py,
0.5B, single fork, full recipe) fails the same way at pre-fix commit 62ad582
(clone claims + emits ready, then dies "unknown error" in the first bnb 4-bit
forward). The local 0.5B combo has no known-good baseline and is not a valid
instrument for the trainer path. Three experimental shim changes (post-fork
strict window, burst-start liveness fence, bridged fence) did not validate and
were reverted; the burst-fence variant HUNG the proven workload (a probe read
on a dead inherited ring never returns — inherited ring pages never show the
host's close marker). Committed and kept: transport-retry (7/7 on its probe),
worker-state globals (alloc/mod/func/stream/event), bridged-op retry.

VALIDATION VENUE: the H100 sweep (proven 15/16 baseline; the fixes target the
stranded 1/16). Also fully identified en route: the deferred-mode killer op is
cuMemMap (torch expandable_segments VMM) — the documented clone recipe
(PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False + GOLDEN_WARMUP) is
REQUIRED for training clones; without it the VMM map fails INVALID_VALUE.

## 2026-07-21 — bug tail CLOSED: copy-mode fork translation is the defect

The local control in the EXACT H100 configuration (--share-weights +
expandable_segments:True) PASSES 2/2 on the 3070 with today's full fix stack:
clone trains loss 8.381→6.994 at ~1,960 tok/s, bit-identical across runs. The
same control WITHOUT --share-weights (copy mode) fails at all commits incl.
pre-fix baseline. Classification: every local trainer/demo failure this
session reduces to ONE pre-existing defect — copy-mode fork translation
breaks bnb/trainer workloads (first 4-bit forward dereferences an
untranslated pointer; suspect: pointers embedded at unaligned offsets in
kernel-param structs that the 8-byte-aligned scan misses, and/or VMM MemMap
in copy mode). Share-weights — the production and density mode — works on
sm86 and sm90. Repro harness: scratchpad val_sweepwl.sh (~2 min/cycle);
flip the --share-weights flag to toggle the failure.

## 2026-07-21 — copy-mode RESOLVED; overnight soak started

Copy-mode fork (no --share-weights) now passes 3/3 on the 3070 (1,930-1,980
tok/s, losses identical to share-weights) — the same transport-retry +
worker-globals fixes that closed the stranded-learner bug healed it; the
"copy-mode translation defect" was the same root causes. Both fork modes are
now correct on sm86 and sm90.

Remaining (perf, not correctness): clone workers lack the CLONE's guest-RAM
map — every zero-copy GPA op (MemcpyGpaDtoH 0xb3) fails NOT_FOUND and falls
back to the bounce path (visible as [op!] status=500 noise; costs a wasted
round-trip per readback and likely part of the per-learner gap). Fix: route
the clone's RAM advert to its worker.

Overnight fork-churn soak running on the H100 (soak.sh: baked golden, 200
cycles of fork-4/train/verify/teardown; cycle 1: 4/4, 0 nan).

## 2026-07-21 (cont.) — clean-stack soak: zero worker crashes

Fork-churn soak on the fully-fixed stack (transport-retry + worker-globals +
GPA latch + binary-search xlat, all shims restaged to matching wire hash):
11/11 cycles pass, 44 fork waves, 0 fail, 0 FATAL, 0 nan. The PRE-fix soak
grew daemon FATALs ~2.7/cycle (teardown-time worker SIGSEGVs); the fixed stack
holds at 0 — the clone fixes eliminated teardown crashes, not just the
stranded learner. Ongoing overnight for sustained-stability evidence.

DEPLOY NOTE (cost 3 false "golden failed" runs): smolvm binary AND all of
drvlib/ (libcudart.so.12, libcuda.so.1) must be restaged from ONE build
atomically — the wire-hash guard refuses a daemon/shim mismatch (correctly).
A `cp: Text file busy` on ~/smolvm/smolvm means a daemon is still running it;
kill the daemon first. The guard did its job: mismatch = refused connection,
not corruption.
