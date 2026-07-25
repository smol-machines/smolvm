# Forking warm GPU VMs vs. cold replicas — measured results

All numbers measured 2026-07-18/19 on: RTX 3070 8GB (sm86, local), A100 SXM4
40GB (sm80, Lambda $1.99/hr), H100 SXM5 80GB (sm90, Lambda $4.29/hr).
Engine: smolvm v1.6.13 + PR #681 (cu12-advertise). Reproduction: see
REPRODUCIBILITY.md + TESTBED.md + smolvm-gpu-testbed.smolmachine (this
directory / Lambda FS `smolvm-testbed`). Defects found while validating:
QA-LOG.md.

> **2026-07-21 corrections (see PERF-LOG.md for the measurements).** Two
> claims below need qualifying:
> 1. **Fork time.** The sub-second fork figures (0.43/0.45 s) are the RAM+GPU
>    clone (CoW memfd + CUDA state) on a golden with a **minimal disk**. Fork
>    time also includes provisioning the clone's disk, which scales with the
>    golden's on-disk size: a minimal golden forks in **0.2 s**, but a golden
>    with a 14 GB baked venv+model on a 30 GB disk takes **~26–30 s** (disk-
>    bound, not GPU — the CUDA 7B clone alone is still sub-second, confirmed by
>    a no-CUDA control at the same 26–30 s). The RAM/GPU innovation is fast;
>    packing large data onto the *forkable* disk is what's slow (a smolvm
>    fork-disk optimization opportunity — clone boot appears to scan the large
>    filesystem). Keep the forkable golden's disk small.
> 2. **Golden load time.** Some ubuntu-image golden runs loaded the model by
>    **downloading it from the HF hub** (the coord/hf symlink does not resolve
>    across virtiofs, and HF_HUB_OFFLINE=0 fell back to download), so part of
>    the 135–156 s "load" was a 5.5 GB download, not pure compute. Reliable
>    offline load requires the model on the guest's own disk (baked machine).

## Training head-to-head: N cold containers vs 1 golden + N forks (7B QLoRA, H100, 2026-07-20)

The incumbent training-infra pattern is N containers, each cold-loading the
7B base + CUDA-initializing independently, then QLoRA-training. smolvm loads
the base ONCE in a golden and forks N `--share-weights` learners (frozen
4-bit base shared; each learner's LoRA + optimizer + activations private).
Both run the identical Unsloth QLoRA workload; CUDA remoted to a host daemon
in the smolvm arm.

| N=3 | Container replicas | smolvm golden+forks |
|---|---|---|
| Startup per replica | ~7 s cold load each | **fork 0.43 s** (golden loads once, ~135 s) |
| Peak GPU (correct run) | 23.2 GB | **16.1 GB (−30%)** |
| Per-learner throughput | ~1,340 tok/s | ~340 tok/s |
| Correctness | ✓ distinct loss curves | ✓ distinct loss curves (all N, post-fix) |

Density scaling (measured, all correct — 0 nan):

| Peak GPU | Container | smolvm | smolvm density |
|---|---|---|---|
| N=3 | 23.2 GB | 16.1 GB | −30% |
| N=8 | 61.8 GB | 28.2 GB | **−54%** |

Each added container costs ~7.7 GB; each added smolvm clone only ~2.4 GB (the
~5 GB base is shared once). Container OOMs near N=10 on 80 GB; smolvm fits
**~3× the learners** (~N=30), and the density advantage GROWS with N.

**FINAL (2026-07-20, clone file-rings live): smolvm EXCEEDS the container
aggregate at N=8 while using 55% less VRAM.**

| N=8, one H100 | Container | smolvm (rings + graphs + warm chain) |
|---|---|---|
| Aggregate training tok/s | 7,088 | **7,341 (+3.6%)** |
| Peak GPU memory | 61.8 GB | **28.0 GB (−55%)** |
| Per-learner tok/s | ~886 | 804–1,106 |
| Startup per replica | 7–17 s | **0.45 s fork** |
| Learner slots remaining | ~2 | **~20** |
| Correctness | ✓ | ✓ (distinct loss curves, all 8) |

Journey of the per-learner remoting tax: 257 tok/s (socket, op-trace on) →
357 (op-trace off) → 429 (math-mode cache) → 450 (event deferral) →
**1,434 solo / ~920 avg at N=8 (DAX file rings — 3.2× from transport
alone)**. The container arm's ~7,100 tok/s is the GPU's compute ceiling for
this workload; smolvm now reaches it at N≈6–8 with ~20 learner slots to
spare — i.e. **token-throughput parity-or-better per GPU, ~3× the isolated
experiments per dollar, and 20–35× faster elastic scaling**. For
throughput-only single-job use, native/containers remain equal-best (the
ceiling is the ceiling); smolvm's win is carrying density, isolation, and
instant elasticity AT the ceiling.

**Correctness fix (this run):** concurrent share-weights training corrupted
(loss=nan) at N≥3 because the golden froze without exercising the training
write-path, so training-written weight chunks passed the daemon's
share-verification and raced. Fix = warm the golden with one training step
before fork (QA-LOG.md 2026-07-20). Copy-mode is correct at all N regardless.

**Open gap:** per-learner throughput (~4× slower via eager socket remoting;
CUDA-graphing the step is blocked by bitsandbytes 4-bit — op-coalescing is
the lever).

### Saturation sweep (2026-07-20, file rings, non-DAX, one H100)

Where does aggregate throughput stop scaling? The container arm cannot answer
past N≈10 (OOM on 80 GB); smolvm keeps going:

| N forked learners | Aggregate tok/s | Peak GPU | Learners finished |
|---|---|---|---|
| 8 | 6,105 | 25.6 GB | 7/8¹ |
| 16 | **9,628** | 43.9 GB | 15/16¹ |
| 24 | DNF² | 8.8 GB | 0/24 |

**N=16 exceeds the container arm's compute ceiling (7,088 at N=8, its OOM
wall) by +36% — a regime the container pattern cannot reach at all** — in
43.9 GB. Per-learner: 872 (N=8) → 642 (N=16): sub-linear but still strongly
additive at 2× the container's max density.

¹ Exactly one clone worker per leg crash-looped (SIGSEGV every ~1.6 s at
spawn, immediately after ring activation), stranding one learner; the other
N−1 trained to completion, 0 nan. Open defect — crash-handler hardening
landed (5972dc1) and a gdb catcher is staged to capture the fault site.
² The 24 learners never reached the training phase (GPU stayed at the
golden's 8.8 GB through all 3 attempts). Leading hypothesis: 24 guests ×
4 vCPUs ≈ 96 vCPUs on this box's cores — the concurrent venv/python import
storm over virtiofs FUSE starves learner startup, not a GPU/memory limit.
Retest planned with DAX mounts (imports bypass FUSE) after the DAX
fork-replay fix (libkrun PR #43).

Every golden load this session also hit the virtiofs FUSE slow mode
(~156 s vs ~15 s healthy), burning two retry attempts per leg — the same
FUSE path the DAX fix removes.

## The claim

Scaling LLM workloads today means cold-starting replicas: every new
instance re-boots, re-initializes the engine, and re-loads its own copy of
the model weights. smolvm forks a *warm* VM instead — new replicas inherit
the loaded model in sub-second time and (with `--share-weights`) share one
copy of the frozen weights in GPU memory.

## FINAL (2026-07-19 evening, optimized engine = PR #692 head): the remoting tax collapses to single-digit ms

Same H100, same 0.5B model, forkable in-VM (rings + module cache) vs
native, both modes:

| Batch-1 per-request p50 | native | in-VM (forkable) | tax |
|---|---|---|---|
| Eager | 71 ms | 78 ms | **+7 ms (~10%)** |
| CUDA graphs | 28 ms | 35 ms | **+7 ms (~25%)** |

**The additive ~345 ms overhead measured on the unoptimized engine is now
~7 ms** — the in-VM engine WITH graphs (35 ms) outruns native EAGER
(71 ms). Ring transport confirmed engaged (`guest-RAM mapped ×5 regions`);
in-VM load 88–99 s (module cache; down from 376–854 s). Native references
this box: b40 ~3,508, b160 ~8,979 tok/s.

**Corrected head-to-head** (4 serving replicas each; golden frozen by
design in arm B):

| | 4 native processes | frozen golden + 4 `--share-weights` clones |
|---|---|---|
| Time to 4 serving | 72 s | golden 152 s once, then **all 4 clones serving 57 s after fork** |
| Added VRAM | 45.9 GB | 54.8 GB¹ |
| Aggregate tok/s | 2,112 | 859² |

¹ At 0.5B the KV pools (~12 GB/replica at this GPU_UTIL) dwarf the shared
1 GB of weights — VRAM parity, not savings. Weight sharing pays where
weights dominate (7B: 2 → 8+ replicas per A100, measured earlier).
² Clones currently serve over sockets in eager mode (per-clone ring
transport and clone graph replay are the two remaining roadmap items,
P2b/P3b in OPTIMIZATIONS.md); the single-VM numbers above show where
clone serving lands once those close.

### P3b landed (2026-07-19 night, PR #695): clones serve WITH CUDA graphs

Local 3070 gate (vLLM graphs mode, golden + 2 `--share-weights` forks,
default build, no flags), per-request latency with both clones serving
concurrently:

| | eager clones (before) | graph clones (P3b) | + fork-time pre-warm |
|---|---|---|---|
| First post-fork request | 5.4 / 6.6 s | 5.2 / 6.7 s | **4.0 / 1.6 s¹** |
| Steady-state | 524 / 509 ms | 293 / 233 ms | **170–218 ms (~2.7×)** |

¹ 1.6 s is the observed floor; the 4.0 s clone was contending with its
sibling's simultaneous ~1.7 s pre-warm on the shared 3070. The worker now
spawns at FORK (eager warm dial from the clone proxy) and pre-warms — CUDA
init, memory reconstruction, 627 module loads, 35 graph re-captures —
concurrent with guest resume; the first request's generate is already at
steady state (phase-split: gen≈230 ms even on request #1).

Correct completions on every request; zero worker faults. Root causes and
mechanism in OPTIMIZATIONS.md P3b (stream_resolve xlat fix + capture-replay
with warmup + private replay stream + fork-time warm chain). Cross-GPU
(H100) re-measurement of the head-to-head with graph clones: pending next
cloud session — expected to close much of the 859 vs 2,112 tok/s gap (P2b
clone rings is the remaining lever).

The historical tables below (unoptimized engine) are retained as the
measured floor and for method continuity.

## The remoting tax — what virtualization costs before forking wins anything

Native bare-metal vLLM vs the identical config inside a smolvm VM
(`--cuda`), same card, same settings (V0, eager, fp16, 0.5B):

| | A100 native | A100 in-VM | tax | H100 native | H100 in-VM | tax |
|---|---|---|---|---|---|---|
| engine load→serving | 56.3 s | 155.6 s | 2.8× | 11.8 s (12.5–12.7 s on a 2nd box, ×3 runs) | 376 s¹ | 32׹ |
| batch-1 p50 / p99 | 94 / 128 ms | 435 / 501 ms | ~4.6× | 58 / 61 ms | 405 / 449 ms | ~7× |
| batch-40 | ~2,319 tok/s | ~684 tok/s | 3.4× | ~4,225 tok/s | ~786 tok/s | 5.4× |
| batch-160 (ceiling) | ~5,924 tok/s | ~2,382 tok/s | 2.5× | ~10,880 tok/s | ~2,765 tok/s | 3.9× |

¹ H100 in-VM load is inflated by the fatbin-chain fix (full multi-container
module images now ship through the socket, hundreds of MB); daemon-side
module-image caching is the queued fix. The H100 in-VM column exists at all
because three sm90 shim bugs were root-caused and fixed the same day
(QA-LOG.md: container-chain truncation, driver-version leakage, missing
Hopper TMA descriptor forwarding) — first-ever sm90 in-VM serving.

**The key structural finding: the per-request tax is an additive constant,
not a multiplier.** Batch-1: A100 +341 ms (94→435), H100 +347 ms (58→405)
— the same ~345 ms of remoting overhead on wildly different GPUs. Faster
GPUs therefore show a WORSE relative tax (7× vs 4.6× at batch-1; 5.4× vs
3.4× at batch-40) while the absolute overhead stays flat, and batching
amortizes it (H100: 5.4× → 3.9× from b40 → b160). Root mechanism: the
shared-memory ring transport cannot establish in shared-daemon mode (no
guest-RAM maps → `ring setup rejected 801` → socket framing); fixing that
is the single biggest performance lever available.

Honest reading: remoted CUDA costs 60–80% of throughput at high batch and
most of the interactive latency budget. Every fork-side win below happens
*inside* the virtualized world — the pitch is elasticity, density, and
isolation per GPU dollar, not raw single-replica speed. The golden's slow
in-VM load is paid once per host; after it, forked replicas materialize in
0.5–16 s — faster than even NATIVE cold starts (12–56 s).

## Head-to-head: container-style replicas vs smolvm forks (one H100, 0.5B, batch-40/replica)

The deployed incumbent is N replicas each loading private weights (one per
container) — not one perfectly-batched engine. Measured 2026-07-19,
4 replicas, GPU_UTIL 0.15 each, readiness-staggered starts:

| | 4 native processes (container-equivalent) | smolvm golden + 3 `--share-weights` forks |
|---|---|---|
| Time to 4 serving | **64 s** (~16 s/replica) | golden 854 s¹; forks issued in 27 s — **but did not serve** |
| Added VRAM | **46.0 GB** (4 × ~11.5 GB) | 12.5 GB (golden only) |
| Aggregate tok/s | **2,165** | FAILED (solo golden 267; collapsed to ~0 after forks) |

¹ Golden load inflated by full fatbin-chain shipping (correctness fix;
module-image dedup implemented since — commit aec9307 — expected to cut
this dramatically; not yet re-measured).

**Two honest findings:**
1. **The fork arm does not currently work for vLLM on sm90 under load** —
   clones added zero VRAM (never reconstructed) and the fork operation
   stalled the golden's serving loop; silent at RUST_LOG=warn. This is the
   same open clone-serving defect class documented in QA-LOG (vh-miss /
   handle staging), now with an H100 datapoint. The A100 result (4 forks →
   1,184 tok/s, EXP3) remains the only validated fork-throughput number.
2. **The incumbent's replica pattern is also expensive**: 4 native
   replicas aggregate 2,165 tok/s — HALF of one engine at batch-40 (4,225)
   and one-fifth of one engine at batch-160 (10,880). Process-level GPU
   sharing wastes most of the card; consolidation beats replication for
   raw throughput on both sides of this comparison.

## Inference (vLLM 0.8.5, Qwen2.5)

### Time to capacity — 8 replicas, 0.5B fp16, A100

| | cold replicas | warm forks |
|---|---|---|
| time to 8 serving | **25.7 min** (~193 s each) | golden 180 s once, then **8 forks in ~16 s** (0.5–10.9 s each) |
| VRAM for 8 | 18.7 GB | **3.6 GB** (5.2×) |
| marginal replica | ~193 s / ~2.3 GB | **~0.7 s / ~450 MB** |

With a standing warm golden (the steady-state autoscaling case), adding
capacity is ~**96× faster** at ~**1/5th the memory**.

### Replicas per GPU — 7B fp16, one 40GB A100

| | cold replicas | warm forks (`--share-weights`) |
|---|---|---|
| max serving replicas | **2** (29.7 GB; a 3rd cannot fit) | **8+** (script cap, not card) at **16.3 GB** |
| marginal replica | ~16.5 GB (full weight copy) | **~390 MB** (weights shared: 724 ranges) |

4.5× the replicas at half the total memory. Cold replication spends the
card on redundant copies of identical frozen weights; forking stops paying
for them.

### Throughput under constant load — batch-40 per server, 0.5B, A100

| | tokens/sec |
|---|---|
| 1 server, batch 40 | 681 |
| 4 forked clones, batch 40 each | **1,184** (1.74×) |

Sub-linear, as expected: replicas time-slice one GPU's SMs. The gain exists
because a single small-model engine does not saturate an A100. Honest
framing: for raw single-model throughput, one engine at batch 160 beats 4
forks at batch 40 (continuous batching fuses the compute). Forking's
unconditional wins are time-to-capacity, replicas-per-GPU, isolation, and
serving *different* model variants off one shared base.

### A fragility finding about the incumbent

Starting 8 cold vLLM engines *concurrently* on one GPU killed 5 of 8: each
engine's memory profiler assumes it owns the card, and concurrent
initializations race each other's measurements. Cold replication on shared
GPUs requires careful readiness-staggering; forks inherit one already-
profiled engine and sidestep initialization entirely.

### Local (RTX 3070, 0.5B) — the same shape at desk scale

Cold replica 45 s / 3.6 GB each; forked replica **0.5–4.8 s / ~313 MB**,
correct sustained serving (46 shared ranges).

## Training (Unsloth QLoRA, alpaca-cleaned)

### 7B fine-tune fork sweep — A100

One warm 7B golden (READY ~200-240 s incl. load), forked into 3 clones in
**750–950 ms each**, each training a different learning rate concurrently:

| | shared weights | copied weights |
|---|---|---|
| peak VRAM (golden + 3 training) | **11.9 GB** | 27.4 GB |
| convergence (losses) | 1.34→1.20 / 1.27→1.17 / 1.24→1.15 | **identical** |

2.3× less memory, bit-identical training results. Verified equally on H100
(sm90) after the FlashAttention attribute-replay fix.

### Real sweep with held-out eval (RTX 3070, 0.5B)

3 forked clones, 250 steps each on real data, distinct LRs: the sweep
produced the practitioner-relevant answer (mid LR best on held-out eval,
high LR overfits) and every clone's LoRA adapter loaded standalone in a
fresh VM and generated correctly — forks yield servable artifacts, not just
metrics.

### Isolation

`kill -9` of a whole clone VM mid-training: siblings unaffected, training
continues, adapters save. In one-process multi-tenant serving (multi-LoRA
engines), an equivalent fault takes down every tenant.

## Coverage

Validated end-to-end (training forks + vLLM inference forks) on sm86
(RTX 3070), sm80 (A100), sm90 (H100).

## Caveats (also the honest-limits section for the post)

- The remoting tax (table above) is the entry fee: in-VM serving runs at
  ~30–40% of native throughput at batch ≥40 and ~4.6× batch-1 latency.
- Aggregate throughput on one GPU saturates: forks add throughput only
  while the card is under-utilized (measured 1.74× at 4×batch-40, 0.5B);
  native single-engine batch-160 beats any fork arrangement of the same
  card on raw tokens/sec.
- Weight sharing requires the base to stay frozen (LoRA/QLoRA fine-tuning,
  inference) — full fine-tuning uses copied weights (still sub-second forks).
- Copy-mode (default) forking roughly doubles-plus GPU residency per clone
  (golden + staging + private copies) — on small cards this exhausts VRAM
  with errors that surface as library failures, not clean OOMs (QA-LOG).
- Clones must not make their *first-ever* cuBLAS initialization after the
  fork (open bug: post-fork-opened channels are rejected; QA-LOG QA-1l).
  Serving goldens warmed with one real request are unaffected.
- Warm state lives in GPU+RAM: it forks within a host but does not
  serialize to disk; each new host warms one golden (~3–4 min at 7B), then
  forks.
- vLLM needs `VLLM_USE_V1=0`, `enforce_eager=True` (CUDA-graph capture in
  forkable sessions is an open bug), `PYTORCH_CUDA_ALLOC_CONF=
  expandable_segments:True`, and pinned torch 2.6.0+cu124 (see
  REPRODUCIBILITY.md / TESTBED.md).
- In-VM vLLM on H100 (sm90) is an open bug — validated coverage for in-VM
  inference is sm80/sm86 today.

## Reproduce

1. Guest: `machine create --from smolvm-gpu-testbed.smolmachine` (baked
   toolchain + experiment scripts).
2. Host: Lambda persistent FS `smolvm-testbed` (us-east-1) carries the
   built engine, pinned venv, model cache, and harness scripts; a fresh
   instance is experiment-ready ~2 min after boot (`testbed_boot.sh`).
3. Harnesses: `vllm_compare.sh`, `l8_vllm_scale.sh`, `real-sweep.sh`,
   `unique-demo.sh`.

### Clone-reliability fix validation (2026-07-21, H100, N=8)

With the transport-retry + worker-state-globals fixes (commits 59314ee,
4039fdd, 46172e7): **learners_done=8/8** (pre-fix baseline: 7/8 with one
learner stranded by a crash-looping clone worker), agg 6,750 tok/s, all 8
loss curves distinct and converging, 8 forks in 3.6 s. The per-leg stranded
learner is eliminated; sweep rows no longer need the N−1 asterisk.

## Post-training: DPO fork sweep (2026-07-22, H100, 0.5B)

Direct Preference Optimization via smolvm forks — the post-training case where
sharing pays double. DPO trains a policy against a FROZEN REFERENCE model
(normally a second full copy in memory). With a LoRA policy the reference is
the adapter-off base, so `--share-weights` shares that one frozen reference
across all forks; each fork trains only its own LoRA policy on its own
preference shard.

golden loads once (176s), forks N=4 `--share-weights` DPO learners:

| learner | DPO loss (start→end) | tok/s | peak |
|---|---|---|---|
| 0 | 0.6931 → 0.6564 | 49 | 6.4 GB |
| 1 | 0.6931 → 0.6643 | 52 | 6.4 GB |
| 2 | 0.6931 → 0.6530 | 52 | 6.4 GB |
| 3 | 0.6931 → 0.6592 | 47 | 6.4 GB |

All 4 done; **peak 15.3 GB for 4 learners sharing ONE reference** (~40% under
4 independent at 0.5B; the share wins bigger at 7B where the reference
dominates memory). Every learner starts at ln(2)=0.6931 (the DPO identity —
policy==reference) and converges to a DISTINCT value, proving each optimized
its own preference shard while sharing the frozen reference. Correctness of
post-training + the reference-sharing density win, both demonstrated.
Workload: demo/dpo_train.py (FORK barrier + golden warmup + synthetic
preference pairs + trl DPOTrainer, ref_model=None). GRPO (RL) pending an
rlwork venv trl/vLLM realignment (trl 0.24 GRPOTrainer needs a vLLM API
0.19.1 lacks).
