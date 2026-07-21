# smolvm CUDA performance — experiment log

Running log of performance experiments toward production-ready clone
training/inference. Each entry: hypothesis, method, result, decision.
Newest first. Numbers are H100 SXM5 80GB (sm90) unless noted; local = RTX 3070
(sm86). Baselines: clone solo 7B QLoRA ~1,434 tok/s, native ~2,507; N=8 agg
~6,750–7,341, N=16 ~9,628; container ceiling 7,088 (OOM ~N=10).

## Committed levers (correctness-safe, perf pending confirmation)
- Binary-search dptr translation (`xlat`, host serve path) — commit 33ad68c.
  Local: within noise (small table). H100 large-table payoff = measuring now.
- Clean-pipeline sync elision — commit b033601. Fires ~1/1667 in training
  (launch-dense); helps idle-heavy serving. No training throughput change.
- Clone GPA D2H fast-fail latch — commit 5f0e46e. Removes doomed retries;
  targeted time was mostly GPU-drain, so no measured throughput gain.
- Time-weighted sync tally tooling — commit 5f0e46e. Diagnostic upgrade.

## Reliability (measured, production-relevant)
- Clean-stack fork-churn soak: 22/22 cycles, 0 fail, 0 FATAL, 0 nan
  (pre-fix stack grew ~2.7 FATAL/cycle). Ongoing.

## Open levers, expected impact
1. Golden ring transport (load time) — HIGH conf: ~62s socket upload → ~10-15s
   (clones already prove 3.2x on this path). Load 156s → ~90s, ~50-60s with
   baked venv. Not throughput.
2. Host-serve overlap (per-learner) — MED conf: gap is solo 1,434 vs native
   2,507 (43%). If GPU idles between deferred batches, recover ~half → ~1,900
   (78% native). Needs phase profiler to confirm.
3. Binary-search xlat magnitude — LOW conf: few % or zero depending on serve
   saturation. Measuring.

Aggregate leverage: per-learner +32% at N=16 → agg ~12,700 (~1.8x container
ceiling), a regime containers cannot reach.

## 2026-07-21 09:56 — measurement-blocking gotcha found and fixed
run_smolvm_fast/baked harnesses re-copy drvlib/libcudart.so -> .so.12 (and
libcuda.so -> .so.1) at every start — staging only the suffixed names gets
clobbered by stale unsuffixed files, producing PROTOCOL MISMATCH refusals
(seen as "GOLDEN-LOAD-FAILED"). Cost five failed measurement attempts.
Deploys must stage BOTH suffixed and unsuffixed shim names + the smolvm
binary from one build. xlat solo A/B relaunched with corrected staging.

## 2026-07-21 10:18 — xlat A/B verdict: NEUTRAL; solo baseline re-established
Controlled solo 7B A/B (2 runs each, same box/day/harness):
binary-search xlat 1,681/1,578 vs linear 1,631/1,639 tok/s — no difference;
the share-weights translation table is small, the scan was never hot. Change
kept (correct + future-proofs large tables), no perf claim. Byproducts:
(a) current-stack solo clone = ~1,630 tok/s (65% of native 2,507), up from
the 1,434 historical record (cross-day, soft comparison); (b) 4/4 golden
loads at 151-155s with zero failures — staging fix confirmed as the cure
for the "flaky load" era. NEXT: host-serve phase profiler (ring-wait vs
decode/translate vs execute) to locate the remaining 35%.

## 2026-07-21 10:35 — serve-phase profiler: HOST IS 87% IDLE; gap is GUEST-side
New SMOLVM_CUDA_HOST_PROF instrumentation (serve loop: idle/decode/exec/
respond buckets). Local 30-step clone run, ~500k ops: idle 4,812ms, exec
726ms (~1.4us/op), decode+respond ~0. The host serve thread and ring
transport are effectively free — the guest cannot PRODUCE ops fast enough
(~17k ops/step: python dispatch + shim marshal + ring writes on 4 vCPUs).
Host-serve overlap hypothesis DEAD. New lever ranking:
1. Guest vCPUs (native uses all host cores; guests get 4) — A/B running.
2. Guest-side op production cost (marshal/encode) — measure if vCPUs move it.
3. Op-count reduction (17k/step is enormous) — torch-level, harder.
Local tok/s stable at ~2,450-2,500 across the current stack.

## 2026-07-21 10:40 — vCPU A/B: NO EFFECT (guest bottleneck is single-thread)
8 vCPUs vs 4 on local clone: 2,443/2,443 vs 2,443-2,508 — identical. The
guest's op production is a serial python/shim thread; cores don't help.
Refined thesis: per-op GUEST cost (torch dispatch + shim encode + ring write,
~12us/op budget at 17k ops/step) is the gap. Corollary: the tax should
SHRINK with model size (fewer, larger ops per token) — verifying via H100 7B
serve-prof run. If confirmed: guest encode-path optimization is the lever,
and large-model workloads are already near-native.

## 2026-07-21 10:39 — H100 7B serve-prof + NEW SOLO RECORD 1,720 tok/s
Solo 7B with profiler: agg 1,720 tok/s (69% of native 2,507; historical
record 1,434). Buckets over 647k ops: idle 5,887ms (51%) | exec 3,171ms
(27%, real CUDA) | respond 2,043ms (18%, host SPINS waiting for the guest to
drain the response ring) | decode 361ms (3%). Waiting-on-guest = ~69% at 7B
(was 87% at 0.5B) — guest-side serial op cost confirmed as THE lever at all
scales, and the tax shrinks with model size as predicted (bigger kernels,
fewer ops/token). Host CPU immaterial. NEXT ENGINEERING: guest marshal path
— do_launch allocates 3-5 heap buffers per op (param_sizes.clone, per-arg
Vecs, encode_request) x 17k ops/step; rework to a reused scratch buffer
encoding directly into the ring/wbuf.

## 2026-07-21 10:55 — guest shim marshal is NOT the lever; perf investigation converged
Shim launch profiler (SMOLVM_CUDA_SHIM_PROF): do_launch marshal = 3.0us/launch,
270ms over 90k launches (~4% of runtime). Reducing it is low-value. Env-cache
hardening (OnceLock the per-op getenv on launch/call/tally paths) committed —
neutral throughput (2,441-2,495), removes real syscalls from the hot path.

CONVERGENCE (5 measured experiments): the per-learner gap (7B solo 1,720 =
69% native) is NOT host-serve (51-69% idle), NOT translation (xlat neutral),
NOT vCPUs (neutral), NOT our marshal (3us/op). Residual = torch/python
framework dispatch (native pays it too, in-process) + per-sync ring RTT (our
only structural add, ~1,667 syncs/run). This is near the practical floor for
API-remoting; per-learner is well-characterized and near-optimal. The
throughput STORY is the aggregate/density win (already proven: N=16 9,628 =
+36% over container ceiling), not per-learner parity.

ROADMAP PIVOT: remaining high-value levers are (1) golden ring transport
(load time 156s->~90s, HIGH conf, user-facing) and (2) production hardening.
Per-learner micro-optimization retired as diminishing-returns.

## 2026-07-21 11:03 — OPEN reliability watch: teardown clone-worker SIGSEGV
soak7 (profiler-commit binary) showed FATAL clone-worker SIGSEGV ~2.8/cycle
(31 by cycle 11) — but soak5/6 (xlat-commit binary) held 0 FATAL over 22
cycles. All are TEARDOWN-time (each precedes "Broken pipe": guest closed,
worker faults during shutdown ring-read); ZERO correctness impact (learners
4/4 pass every cycle). Backtrace unsymbolized (<unknown>, async-signal
handler in worker). Hypothesis: serve_rings profiler refactor reintroduced a
shutdown-path fault, OR soak5's 0 was luck. Controlled check: redeployed the
LATEST (env-cache) binary + clean soak8 to see if FATALs return on the
shipping binary. Correctness-safe either way; tracking as hardening.

## 2026-07-21 11:26 — teardown clone-worker SIGSEGV ROOT-CAUSED + FIXED
Core dump (6.6GB) of a teardown crash: rip inside libcuda.so, worker
_cuda-clone-worker. Cause: serve() calls reclaim_session() on exit, issuing
cuMemFree/cuMemUnmap/cuMemRelease/cuCtxRelease against the clone's context
whose backing (golden exported physical + guest RAM) VANISHES when the clone
VM is torn down — the driver segfaults on the dead context. The per-resource
frees are ALSO redundant: a clone worker is a one-shot process; the driver
reclaims the whole context on process death.
FIX: serve_no_reclaim() for clone-worker main + attached channels; hard
std::process::exit(0) after (skips backend Drop, which would repeat the
driver calls; also cleanly kills late-attached threads instead of racing
them). In-daemon serve() keeps reclaim (long-lived process). Correctness-safe
(GPU mem reclaimed by driver on exit either way). Deployed; soak9 verifying
0-fatals across many cycles.
NOTE: core dumps are 6.6GB each on an 80GB-GPU box; a debug prlimit=unlimited
flooded ~90GB fast — reset core_pattern + prlimit=0 after capture.
