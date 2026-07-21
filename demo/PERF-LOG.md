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
