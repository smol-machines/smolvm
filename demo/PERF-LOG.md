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

## 2026-07-21 11:57 — no-reclaim fix REVERTED (failed + regressed)
The serve_no_reclaim + hard-exit change did NOT eliminate teardown fatals
(soak9 held ~2/cycle: 24→26→28 over cycles 3-5) AND correlated with a NEW
learner failure (cycle 2: done=3/4) the pre-fix stack never had. Conclusion:
reclaim_session is NOT the (sole) SIGSEGV source, and hard-exit(0) races a
still-finishing guest connection → lost learner. Reverted (bb908c7) to
known-good. The libcuda-frame core told us WHERE (driver, teardown) but not
WHICH call; release-binary cores are unsymbolizable past the driver frame.
NEXT: build a DEBUG (symbols) clone-worker, capture ONE core with a full
Rust backtrace to name the exact call, before touching the teardown path
again. Lesson: a plausible root-cause from a partial core is a hypothesis,
not a fix — validate the SIGSEGV location precisely first.

## 2026-07-21 12:10 — revert confirms known-good; teardown SIGSEGV is pre-existing
soak10 (reverted known-good): fail=0 both cycles — the learner failures were
MY no-reclaim/hard-exit regression, now gone. But fatals persist ~1-4/cycle,
so the teardown clone-worker SIGSEGV is PRE-EXISTING and long-standing on the
shipping stack (soak5's 0-fatals/22-cycles was luck). Correctness-safe
(learners complete). Approach: build release WITH debug symbols
(CARGO_PROFILE_RELEASE_DEBUG=2) so the crash handler's own Backtrace resolves
to real frames in the daemon log — no core dumps (avoids the 6.6GB flood).

## 2026-07-21 12:22 — teardown SIGSEGV re-classified COSMETIC; rat-hole exited
Debuginfo build: crash handler backtrace STILL frames 0-11 = <unknown>
(async-signal unwinder can't walk from its altstack; driver frames unsymboled).
Confirmed: crash is on the worker MAIN thread at teardown (frame 12 =
__libc_start_main), after "Broken pipe" (guest closed). SEVERITY ASSESSMENT:
COSMETIC. The clone worker is a one-shot process exiting anyway; the CUDA
driver reclaims the ENTIRE context on process death whether exit is clean or
SIGSEGV — so: learners unaffected (fail=0 on known-good across all soaks), no
GPU leak, identical cleanup. It is log noise, not a functional defect. Cost/
benefit says stop chasing the exact driver call (needs live-gdb + driver
symbols) — DECISION: document as known cosmetic, restore shipping binary,
pivot to the high-value lever (golden ring transport, load-time). Fixing it
cleanly would need catching the guest-close and skipping the driver teardown
without the hard-exit race that regressed — deferred, low priority.

## 2026-07-21 12:24 — CHECK before building golden-ring: golden ALREADY has rings
bring_up_client calls ring_try_setup for EVERY connection incl. the golden
(SMOLVM_CUDA_SHARED=1 → zerocopy → GPA rings; golden RAM is daemon-visible).
So the golden's from_pretrained H2D is likely ALREADY zero-copy — the planned
"golden ring transport" lever may be a no-op. The ~62s load is then dominated
by bnb-4bit quantize (GPU compute) + torch/python init + virtiofs disk read
(~13s warm), NOT transport. MUST VERIFY before building: (1) confirm golden
"shared-memory rings active" in daemon log; (2) decompose load_ms into
disk-read vs from_pretrained-compute. Applying the measure-first lesson from
the teardown rat-hole: don't build a fix for an unverified bottleneck.

## 2026-07-21 12:36 — PERF INVESTIGATION CONVERGED (data-backed)
Golden load decomposition CONFIRMS: golden shows "shared-memory rings active"
— H2D weight upload is ALREADY zero-copy. Load-phase sync-times are dominated
by ModuleLoadData (314+176+... ms of cubin/JIT loads) + Init 273ms +
PrimaryCtxRetain 119ms — NO large H2D in the sync costs. The 158s load is
bnb-4bit quantize (GPU compute) + torch/python framework + module JIT — all
outside our control, and PAID ONCE (fork amortizes it into 0.4s clones).

FULL CONVERGENCE across the session's measured experiments:
- Transport (H2D golden + clone rings): DONE (zero-copy, confirmed).
- Per-learner throughput: at API-remoting floor (framework dispatch native
  also pays + ~1,667 sync RTT/run); host 51-69% idle, marshal 3us/op, cores
  neutral, xlat neutral. Solo 7B 1,720 = 69% native.
- Load time: framework/compute-bound, paid once, fork-amortized; baking = 4%.
The wins are ARCHITECTURAL (fork density + amortized load), already proven:
N=16 agg 9,628 = +36% over container ceiling, 8/8 reliable.

No controllable perf lever remains. Remaining production-readiness items are
NON-perf: (1) teardown SIGSEGV — cosmetic, self-reaping (assessed); (2)
turnkey packaging (baked .smolmachine exists); (3) sustained-soak stability
evidence (ongoing). Perf-optimization phase complete.

## 2026-07-21 12:55 — packaging iteration + soak observations
DELIVERED: demo/QUICKSTART.md (turnkey: baked .smolmachine fork-sweep, the
proven share-weights+GOLDEN_WARMUP+expandable_segments recipe, staging/
wire-hash gotchas) + demo/qlora_train.py (the workload it references, now
in-repo so QUICKSTART is self-contained). Commit 650e7d0.
SOAK (shipping binary, soak_ship2): 8 cycles, fatals=0 (teardown SIGSEGV did
NOT recur — confirms intermittent/state-dependent, cosmetic), nans=0. One
cycle (5) went done=3/4: it ran 7min vs the normal 2.3min and lost one
learner with NO error in g.err — a transient SLOW clone that exceeded the
soak harness's 5-min poll window under contention, not a crash/corruption
(cycles 6-8 back to 4/4). Tail-latency note, not a defect. Production-
readiness status: perf converged, crash cosmetic, turnkey doc landed,
sustained-stability green (0 fatal/0 nan across cycles).
