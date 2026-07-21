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
