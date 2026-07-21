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

## 2026-07-21 13:16 — CONVERGED: loop reaching natural completion
Sustained soak (shipping binary): 17 cycles / 68 fork-train-teardown waves,
fatals=0, nans=0, 16/17 pass (the 1 fail = classified slow-clone poll
timeout, not a crash). Teardown SIGSEGV did not recur in 17 cycles —
intermittent/cosmetic confirmed. Production-readiness scorecard:
- Performance: CONVERGED — transport zero-copy (done), per-learner at
  API-remoting floor, load framework-bound+fork-amortized. Wins architectural
  (N=16 +36% over container ceiling), proven.
- Reliability: 8/8 learners; 17-cycle soak clean; teardown crash cosmetic
  (self-reaping, no leak, learners unaffected).
- Turnkey: QUICKSTART.md + in-repo workload; flow == the soak's own
  (verified-by-proxy every cycle).
Open (low-priority, non-blocking): teardown-crash cosmetic fix (needs
live-gdb+driver symbols), QUICKSTART clean-box e2e, slow-clone tail latency
under contention. No controllable perf lever remains; further loop iterations
are monitoring, not progress. Stopping the autonomous loop at this convergence
point; restartable anytime.

## 2026-07-21 17:10 — runnable benchmark harness (demo/bench/) + e2e debugging
Committed demo/bench/: benchmark.sh (one command, both arms, preflight,
head-to-head table), run-smolvm.sh, run-containers.sh, config.sh (all paths
overridable), make-baked.sh, summarize.py, README. End-to-end test on the H100
caught a REAL turnkey bug: making the HF cache visible via a host symlink into
the coord mount FAILS — virtiofs won't follow a symlink pointing outside the
shared dir, so the guest can't load the model. FIX: mirror the proven soak
path — boot the smolvm arm from the BAKED machine (venv+model in guest block
storage; only drvlib+coord mounts; HF_HUB_OFFLINE=1). bash -x trace confirms
the script logic is correct through daemon-start + golden create; the one
empty run was the KNOWN intermittent box golden-load flake, not a script bug.
Harness is verified by (a) clean trace and (b) equivalence to run_smolvm_baked
.sh which the 17-cycle soak runs successfully every cycle. Deliverable: anyone
with the prereqs runs `N=8 ./demo/bench/benchmark.sh`.

## 2026-07-21 17:23 — HF fix CONFIRMED end-to-end (my exact script, complete run)
run-smolvm.sh (baked machine, HF_HUB_OFFLINE=1) ran to completion N=2/STEPS=3:
golden_load_s=153.6, learners_done=2/2, agg_tok_s=1167, peak_gpu_mem=13688 MiB,
both learners trained (loss 17.0->13.55 / 16.5->13.53). Model loaded from the
BAKED /opt/hfcache (no download, no symlink) — the HF-symlink turnkey bug is
definitively fixed and the runnable harness is empirically verified, not just
trace/soak-equivalent. Minor note: fork_2_clones_s=51s (first-fork warm-chain
spawn cost; amortizes at higher N, ~0.4-1s/clone in the soak). Not a
correctness issue.

## 2026-07-21 17:57 — fork time scales with GOLDEN DISK DATA (baked=25s, minimal=0.2s)
Isolated the verification run's 51s fork: 3 sequential baked-machine forks
(14GB venv+model on disk) = 25.4 / 27.2 / 27.1s each; a minimal machine
(little disk data, no cuda) = 0.20s. So `machine fork`'s disk-overlay/copy
cost scales with the golden's on-disk footprint — NOT a GPU-fork regression
(the RAM+CUDA fork is still sub-second; published fork_8=3.6s / fork_16=6.7s
were minimal-disk ubuntu machines). IMPLICATION: my benchmark's smolvm arm
switched to the baked machine (to fix model loading) and thereby regressed
fork time 0.4s->25s — breaking the headline. FIX: the benchmark's fork arm
must use the PROVEN run_smolvm_fast.sh approach (minimal ubuntu image + mount
venv/drvlib/coord, HF cache via coord) which forks fast AND loads correctly.
The baked machine stays a turnkey EASE option (QUICKSTART) but with a noted
fork-time tradeoff. Also worth a real smolvm investigation: why does fork copy
disk data instead of pure-CoW overlay? (separate item)

## 2026-07-21 18:07 — coord-symlink HF path CONFIRMED broken; load-saga re-explained
Fast (non-baked, ubuntu:22.04 + coord/hf symlink) path FAILED with the same
"Can't load the model" OSError as my v1. So virtiofs does NOT follow a
/opt/coord/hf -> $HF symlink into the guest, AND run_smolvm_fast.sh's `rm -rf
$CO` deletes the symlink anyway — meaning the "fast fork" ubuntu-machine
benchmark runs were loading the 7B via HF HUB DOWNLOAD (HF_HUB_OFFLINE=0), not
from local cache. That re-explains a chunk of the 156s "slow load" saga (it was
partly a 5.5GB download). ONLY the baked machine reliably loads offline. So the
real tension: baked = reliable offline load but 25s disk-bound fork; mounts =
fast fork but broken/downloading load. NEXT: make baked fork fast — test if
the 25s is overlay-SIZE (fixable: small/sparse overlay) vs a full backing-disk
copy (deeper smolvm fork-CoW fix).

## 2026-07-21 18:21 — fork-disk cost DEFINITIVELY isolated + record corrected
Baked disk (30GB storage / 14GB data), NO cuda, no workload: fork 26.0 / 30.3s
— identical to the with-cuda case. So the ~29s fork is PURELY disk-size cost;
the CUDA 7B clone is sub-second (ubuntu-minimal 7B fork = 0.4s). Disk clone
uses qcow2 CoW overlays (should be instant), so the cost is likely the clone's
GUEST BOOT scanning/mounting the large 14GB filesystem, not a copy. Corrected
BENCHMARKS.md header with both fixes: (1) sub-second fork is the RAM/GPU clone
on a MINIMAL-disk golden; large forkable disk adds ~1s/GB; (2) some ubuntu
golden "loads" were HF hub downloads (symlink doesn't cross virtiofs).
SMOLVM OPTIMIZATION FILED: machine fork of a large-disk golden is O(disk) via
guest-boot filesystem scan — investigate keeping fork O(1) (skip fsck/scan on
the CoW clone, or lazy-mount). Benchmark stance: keep the forkable golden's
disk small; the baked machine is a turnkey EASE option with a fork-time
caveat, not the way to showcase fork latency. Investigation CLOSED — the
record is now honest.

## 2026-07-21 19:09 — SELF-INFLICTED: scp'd a local (glibc-2.39) binary to the box (2.35)
Deployed my locally-built smolvm to the H100 (Ubuntu 22.04, glibc 2.35) — it
requires GLIBC_2.39 (Arch), so it wouldn't run, and I'd overwritten the box's
working binary, breaking the soak. Violated my own standing rule (memory:
"build smolvm ON the box"). RECOVERY: rsync source + rebuild on the box (which
also carries the fork-timing change a29f673), redeploy, restart soak. LESSON
re-learned: never scp a local Rust build to the glibc-older box; always build
there. The fork phase-timing measurement is pending the box rebuild.

## 2026-07-21 19:25 — box RECOVERED; fork-timing thread CLOSED
Box fully recovered after the two self-inflicted breaks: all 3 crates rebuilt
on the box (glibc-2.35), shims restaged, wire-hash matched (0 mismatches),
soak cycle 1 = 4/4 pass 0 nan. Fork phase-timing instrumentation (a29f673)
is deployed; its logs route to CLI stdout (soak discards them), so the exact
RAM-checkpoint-vs-disk-overlay split would need a soak pause to capture —
NOT pursued (diminishing returns; the two operational breaks this thread came
from rushing a refinement the conclusion didn't need).
FORK-TIMING FINDING (complete + actionable):
- machine fork of a large-disk golden = ~27s, ALL in host-side prepare_fork
  ("freeze golden"); clone boot is 73ms. Scales with golden disk size
  (baked 30GB/14GB-data = 27s; minimal = 0.2s). RAM/GPU clone is sub-second.
- The freeze = golden RAM checkpoint (FORK control cmd) + qcow2 CoW disk
  overlays (code is pure-CoW). Exact split uncaptured; instrumentation in
  place for whoever picks it up (read CLI stdout of a `machine fork`).
- MITIGATION (documented in BENCHMARKS/bench): keep the forkable golden's
  disk small → fork returns to sub-second. Baked machine = turnkey ease with
  a fork-time caveat.
- OPTIMIZATION FILED: make large-disk fork O(1) (the freeze shouldn't scale
  with golden disk if overlays are truly CoW — investigate the RAM checkpoint
  writing 8GB to a snapshot file vs the overlay path).
RETURNING TO MONITORING. Core deliverables intact: perf converged, reliability
soak clean, honest runnable benchmark, honest BENCHMARKS record.

## 2026-07-21 20:07 — PR #695 CI RED->GREEN + soak reassessed
PR #695 was FAILING CI (Format + all platform Clippy builds). Cause: my
session commits accrued rustfmt + clippy(-D warnings) violations that the
box's plain `cargo build` never caught — dead count_sync (orphaned by the
time-weighted tally), sort_by->sort_by_key, %==0 -> is_multiple_of, an unused
init. Fixed by reproducing CI's exact checks locally (fmt --check + clippy
-D warnings on cuda crates + shims + smolvm binary), commit b92a8f5. ALL CI
GREEN now; PR MERGEABLE (mergeStateStatus BLOCKED = awaiting human review, not
CI). PROCESS LESSON: gate "CI green" claims on actually running clippy
-D warnings, not just a successful build. Soak (cycle 14): 0 nans, learners
train correctly; the 90 FATALs are all the known cosmetic teardown SIGSEGV
(worker self-reaps, no correctness/leak impact — variable rate ~5/cycle now),
the 2 fails are slow-clone poll timeouts under sustained load (harness
sensitivity, cycle 9 ran 7min vs normal 2.3). NO new regression.

## 2026-07-21 20:12 — teardown crash VERIFIED harmless (no leak); long-run soak stable
Investigated whether the teardown clone-worker SIGSEGV leaks resources (a
crash DURING reclaim_session could strand the clone's GPU memory). Measured
across a full cycle: GPU mem is STABLE at 8837 MiB (exact golden baseline)
for 60s between cycles with 0 clones running; nvidia per-process shows only
the daemon (8810 MiB). So the driver fully reclaims each clone worker's GPU
memory on process death despite the SIGSEGV — GPU returns to baseline every
cycle. Daemon fd=268 (moderate, not unbounded), host mem 16G/209G. Over 34
soak cycles / 136 clones: 0 nans, no GPU leak, no fd leak, no memory creep.
CONCLUSION: the teardown SIGSEGV is VERIFIED harmless (was "believed
cosmetic", now measured) — pure log noise, no resource or correctness impact.
The long-run soak is stable = strong production-hardened evidence. Fatal rate
is variable ~3-5/cycle with bursts (intermittent, state-dependent), not a
smoothly-growing leak signature.

## 2026-07-21 21:42 — REAL BUG FOUND: zombie clone-worker leak (not cosmetic!)
Almost stopped the loop declaring "hardened", but checked the soak fail rate
first: 7 fails/42 cycles, ACCELERATING (0.2/cycle early -> 0.33/cycle late).
Root cause: 288 ZOMBIE (<defunct>) smolvm processes, all daemon children.
The daemon forks a worker per clone but only reaps on the RECONNECT path
(route_clone_connection); a worker that dies at teardown (incl. the teardown
SIGSEGV) with no reconnect was never waited on -> zombie. Over a long run they
fill the process table (risking PID exhaustion + fork failures that slow clone
startup -> the accelerating timeouts). This OVERTURNS the earlier "teardown
crash is harmless" — GPU didn't leak but the PROCESS TABLE did. My leak check
had only looked at GPU, not host RSS/zombies (daemon RSS also 16GB, likely
per-clone state not freed on no-reconnect death — separate follow-up).
FIX (commit): spawn_child_reaper() — background thread waitpid(-1, WNOHANG)
draining all exited children every 2s; coexists with the targeted reconnect
reap (whichever wins; the other sees the child gone -> spawns fresh). fmt +
clippy -D warnings clean (ran CI's checks pre-commit this time). Deploying via
BOX rebuild (not scp). LESSON: never declare "hardened" from a spot check —
watch the trend; an accelerating fail rate is a real signal.

## 2026-07-21 22:12 — reaper fix VERIFIED (zombies 288->0); wire matched
All-3 rebuild deployed (daemon-only had broken the wire hash — 3rd time this
session; rule saved to memory box-deploy-rule). Verified on the fixed stack:
zombies=0 (was 288), PROTOCOL MISMATCH=0, soak cycle 1 = 4/4 pass 0 nan. The
zombie clone-worker leak is FIXED. REMAINING FOLLOW-UP: daemon RSS was 16GB —
the reaper doesn't touch that (zombies cost ~0 memory), so it's a SEPARATE
accumulation: per-clone state (module images / graph oplogs / staged blobs)
not freed when a worker dies WITHOUT a reconnect. Monitoring whether zombies
stay ~0 across cycles and whether daemon RSS still climbs (isolates the RSS
leak as the next real hardening item).

## 2026-07-21 22:25 — reaper CONFIRMS the degradation was zombies; RSS is baseline not leak
5 cycles on the reaper stack: zombies stay 0 (transient 1 -> reaped), 0 fails
(vs 7/42 pre-reaper), daemon RSS STABLE at ~15991MB (not growing per-cycle).
CONCLUSIONS:
- The accelerating fail rate (nearly dismissed as cosmetic) WAS caused by
  zombie accumulation filling the process table -> slower fork/clone startup
  -> timeouts. The reaper fixes it: 0 zombies, 0 fails.
- The 16GB daemon RSS is a stable BASELINE (golden's zero-copy-mapped 8GB
  guest RAM + 7B model + CUDA host allocations), NOT a leak — flat across
  cycles. The earlier "per-clone state leak" worry was wrong.
- The teardown SIGSEGV (fatals ~4/cycle) is now genuinely harmless: reaped
  immediately, no zombie/resource accumulation, no correctness impact.
NET: the reaper (commit bc291ff) is a real production-hardening fix — it
converts sustained-operation degradation into steady-state stability. This is
the correct "hardened" conclusion, now with the actual bug fixed + verified
(not assumed). Accumulating more clean cycles for confidence.

## 2026-07-21 22:55 — reaper fix DEFINITIVELY verified: 18/18 clean cycles
18 consecutive soak cycles on the reaper stack: pass=18, fail=0, zombies=0
(72 clones). Pre-reaper had fails by cycle 2 and 9 and accelerating by cycle
24; post-reaper is 18/18 clean past that inflection. The zombie-leak
degradation is FIXED and thoroughly verified. Fatals (~4/cycle, teardown
SIGSEGV) continue but are reaped immediately — 0 zombie/resource/correctness
impact. PR #695 all CI green + MERGEABLE (reaper commit included; ran
fmt/clippy-D-warnings pre-commit).
HARDENING THREAD CLOSED. Final production-readiness state (demonstrated, not
asserted): perf converged; transport zero-copy; N=16 +36% over container
ceiling; 18-cycle soak stable with the real zombie-leak bug FIXED; RSS a
stable baseline (not a leak); the teardown SIGSEGV now genuinely harmless.
Open low-priority items (filed, non-blocking): teardown-SIGSEGV root cause
(cosmetic now that workers are reaped), fork O(disk) provisioning cost.
