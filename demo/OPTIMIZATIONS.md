# Optimization plan — closing the gap between floor and ceiling

Working plan for the performance/correctness levers identified by the
2026-07-19 benchmark + QA campaign (see BENCHMARKS.md for the measured
floor, QA-LOG.md for the defect trails). Ordered by value ÷ risk.

## P0 — Fix clone serving under load (correctness blocker, not a speedup)

**Why first**: blocks fork-scaled serving entirely (H100 head-to-head arm B
failed; only the A100 EXP3 number exists). Everything else optimizes a
path this bug caps.

**State**: locally reproducible. Trail: guest cuBLAS handle created on one
channel is invisible where GEMMs flow (`vh-miss` on `0x…006`); staged
`lib_handles=1` at fork despite the create being recorded (`lib-rec`
fired); worker seeding regressed 1→0 after the layout-share change.

**Next actions**:
1. Log the layout's `lib_handles` CONTENT at `spawn_clone_worker` (which
   (lib, func, handle) entries staged) and per-entry failure detail in
   `replay_lib_handles` (why seeded=0).
2. Fix the recording/staging gap the logs expose.
3. Green gate: `val_vllm.sh` — golden + 2 forks, 3/3 serving, 0 vh-miss.
4. Re-run the H100 head-to-head (the missing table).

## P1 — Module-image dedup (implemented aec9307; VALIDATE)

Guest offers content hash first; daemon loads from a process-wide cache on
hit — bytes cross the wire once per unique image instead of once per
replica. Expected: in-VM engine load 854 s → near the pre-fatbin-fix
~150 s for replica #2+, and much less for warm re-boots.

**Validation**: two sequential vLLM VM boots against one daemon; compare
WARM-READY deltas; count cache hits.

## P2 — Ring transport in shared-daemon mode (the ~345 ms lever)

Rings exist but need guest-RAM visibility, which the shared daemon lacks.
Key unlock discovered in code: **forkable VMs already back guest RAM with
a memfd** (launcher.rs).

**Design (grounded in code reading, branch p2-ring-transport)**:
- Forkable VMs already memfd-back guest RAM; clones already access it via
  `/proc/<pid>/fd/<memfd>` — the daemon uses the SAME door: no fd-passing
  protocol, just (pid, memfd fd-number, region triples) advertised.
- The per-VM proxy (`cuda_host.rs` daemon-connect, which already writes
  the clone preamble via `preamble()`) additionally writes a guest-RAM
  preamble: magic + pid + memfd# + (gpa, memfd offset, len)×N, computed
  from `krun_get_guest_ram` host VAs minus the memfd mapping base.
- Daemon accept path consumes it, opens `/proc/<pid>/fd/<n>`, mmaps
  MAP_SHARED, and calls `set_guest_ram` on that connection's backend with
  daemon-local VAs → `gpa_to_hva` works → the guest's existing RingSetup
  attempt (currently `[ring] rejected 801 → socket mode`) succeeds; the
  MemcpyGpa* zero-copy fallbacks (0xb3→500) also disappear.
- **Known limit, by memory model**: clone RAM is MAP_PRIVATE COW of the
  golden's memfd — a daemon mapping of the memfd sees the GOLDEN's pages,
  not a clone's writes. So P2a covers goldens + normal forkable VMs (where
  the ~345 ms was measured); CLONE transport stays socket-mode until a
  per-clone shared window exists (P2b, needs VM-side work at fork).

**Gate**: `[ring]` establishes in-VM; batch-1 p50 re-measured on the same
harness (expect ~405 ms → double-digit ms); MemcpyGpa 500s gone.

### P2b (clone rings) status: BLOCKED on libkrun (2026-07-19 eve)

Investigated to the point of a precise blocker. A clone's guest RAM is a
`MAP_PRIVATE` COW view of the golden's memfd, so the daemon can't map it
`MAP_SHARED` (it would see stale golden pages). Options assessed:
- **process_vm_readv/writev** (no shared mapping): the ring is a lock-free
  SPSC queue whose head/tail indices must be *coherently shared* and read
  atomically by both sides — `process_vm_*` gives neither coherence nor
  atomics, so it cannot back the ring. It could accelerate bulk `MemcpyGpa`
  only, which is NOT the clone latency bottleneck (per-call round-trips
  are). Low value.
- **Per-clone shared window** (the right fix): inject a small fresh
  memfd-backed region into the clone's guest-physical space at restore, and
  place the ring pages there. This needs a libkrun API to add a shared
  region — **libkrun exposes none** (61 symbols; nearest is
  `krun_add_virtiofs`, a filesystem, not raw shmem), and the libkrun
  submodule source is not checked out in this tree, so it can't be patched
  here. This is a libkrun fork, i.e. VMM work outside this repo.

**Conclusion**: clones serve over sockets today (the shipped, working
path — eager, 533 ms/req locally, 859 tok/s aggregate). Ring-speed clones
require a libkrun shared-region API. That's the single highest-value
remaining lever, and it's a libkrun change, not a smolvm one.

### P3b (clone graph replay): SOLVED — see the P3b section below.

**RESULT (2026-07-19, commit 434b64b, local 3070)**: implemented — one
correction to the design en route (libkrun backs guest RAM with one memfd
PER REGION, so the advert carries per-region (gpa, fd, offset, len) quads;
also MAP_SHARED-only filtering so clone COW mappings are never advertised).
Gate: `guest-RAM mapped: zero-copy + rings enabled count=5`, and
**batch-1 p50 dropped 318 ms → 87 ms (−73%)** on the identical harness —
the bulk of the additive transport tax eliminated for goldens/normal VMs.
Cross-GPU re-measurement (A100/H100 tables) pending the final cloud
session. Clone transport remains socket-mode (P2b).

## P3 — CUDA graphs inside forkable sessions

Capture fails today (found by QA; forced every benchmark to eager). With
graphs, a decode step is ONE remoted launch instead of hundreds of calls —
the big algorithmic multiplier on top of P2. Needs root-cause first;
repro: torch graph capture in a forkable VM.

**RESULT (2026-07-19, commit d5923fe)**: root cause = the guest cudart
shim's `cudaPointerGetAttributes` only knew its OWN allocations; torch
expandable-segments tensors (driver-VMM) reported as "unregistered host",
so vLLM's capture-time `weak_ref_tensor` refused them. Fix: on local miss,
classify through the server (LibCall 6/2 — the session knows every range).
**vLLM with CUDA graphs now loads AND serves in a forkable VM at 94 ms
per request** (rings + graphs compounding; the journey started at 441 ms
eager+sockets). Remaining edge → **P3b**: clone-side graph REPLAY fails
("invalid argument") at the known M3b boundary — stream-captured graphs
embed library-API kernels the worker rebuild can't re-resolve; forks
therefore serve eager for now, goldens/single-VMs get full graph speed.

## P3b — SOLVED (2026-07-19 night): clones serve with CUDA graphs

**Result (local 3070, vLLM graphs mode, golden + 2 forks): both clones
serve correct completions at 215 / 183 ms steady-state — ~2.8× faster than
eager clones (609 / 510 ms) on the identical harness.** Replay trace:
`1202 ops {LaunchKernel: 146, LibCall: 1056} → re-captured OK` per clone.

TWO stacked root causes, found by stage-by-stage instrumentation
(`[p3b]` trace at record → stage → adopt → replay) plus a core-dump
backtrace:

1. **Worker segfault (the actual "graphs clones fail" cause).** The clone
   workers died with SIGSEGV *before the guest's first channel attach* —
   every guest-visible error (`CUBLAS_STATUS_NOT_INITIALIZED`, earlier
   `invalid argument`) was downstream fallout of a dead/respawned-empty
   worker. Core dump: `cublasSetStream_v2 → cuStreamGetGreenCtx →
   SEGV_ACCERR`. Root cause: `stream_resolve` (the generated lib-dispatch
   path for ALL `Stream`-typed args) resolved the session map but never
   applied `xlat_stream` — so the worker passed the GOLDEN's raw stream
   pointer (foreign heap address) into cuBLAS, which dereferenced it.
   Eager clones never hit this because eager torch uses stream 0; graphs
   torch uses explicit streams. One-line class fix in `stream_resolve`
   (same family as the typed-dptr_resolve cuBLASLt fix).
2. **Process-local exec handles (why replay must exist).** A worker-process
   clone can never launch the golden's `CUgraphExec` verbatim — the handle
   is process-local — and node rebuild can't reproduce cuBLAS-emitted
   kernel nodes. Capture-replay is the correct mechanism: the golden
   records every capturable op between Begin/EndCapture; the log ships in
   the clone blob keyed by exec_vh; at first `GraphLaunch` the clone runs a
   **warmup eager pass** (binds library streams/workspaces outside the
   capture window — the classic capture-time `NOT_INITIALIZED` source),
   then re-captures the sequence in its own context (re-dispatch applies
   all pointer/handle translation), instantiates, and launches natively
   from then on.

**Default ON** (`SMOLVM_CUDA_CLONE_GRAPH_REPLAY=0` opts out to the old
node-rebuild/patch path, known-broken for library graphs). Per-graph
one-time cost: one eager warmup + one re-capture (~seconds, folded into
the clone's first request alongside lazy module reload).

## P4 — Smaller

- Drop the per-VM proxy hop (daemon on vsock directly, or splice()).
- Adaptive quiet-op fencing; coalesced writes.
- MPS for multi-replica time-slicing (helps both arms).

## Measurement discipline

Every lever gets a before/after on the same harness that measured the
floor (`vllm_compare.py` b1/b40/b160 + the head-to-head), appended to
BENCHMARKS.md with the engine commit.

### P2b DAX probe (2026-07-20): NEGATIVE — virtiofs-DAX can't back clone rings

Tested the hypothesis that virtiofs-DAX gives coherent host↔guest shared
memory (which would make clone rings a smolvm-only change, no libkrun fork).
Result: **DAX is available ONLY on the ROOT virtiofs in the bundled
libkrun; every user `-v` mount has no shm/DAX region.** Guest dmesg is
decisive:
- root: `virtiofs virtio3: Cache len: 0x20000000 @ 0x240000000` (DAX window)
- user mount: `virtio_fs_setup_dax: No cache capability` +
  `dax can't be enabled as filesystem device does not support it`

A `mount -t virtiofs -o dax` on a user mount fails `rc=32` and falls back
to writeback. Coherence probe (guest heartbeat + host echo, no msync)
confirmed writeback semantics: guest→host visible only on slow cache flush
(~40 ms/tick), host→guest **never** — fatal for a ring's shared indices.
Adding the DAX window size to `add_virtiofs3` for user mounts had no effect
(libkrun doesn't wire a shm region for non-root virtiofs devices).

**Conclusion stands:** clone rings (P2b) require a libkrun change —
either shm regions on additional virtiofs devices, or a dedicated
per-clone shared window API. It is not reachable from the smolvm side with
this libkrun build. Probe scripts + agent DAX-mount change reverted; no
code shipped.

### P2b via virtiofs-DAX (2026-07-20): transport VALIDATED, clone-restore is the one remaining defect

The earlier "only root gets DAX" diagnosis was WRONG — libkrun fully supports
per-device windows (ShmManager::create_fs_region per fs index); smolvm's
STATIC launcher (the `machine start` path) simply passed shm_size=0 for user
mounts (launcher_dynamic asked for 2 GiB, but machine start doesn't use it).

**Implemented (SMOLVM_MOUNT_DAX=1 gate):** static launcher requests a 512 MB
DAX window per user mount; agent mounts virtiofs `dax,sync` with plain-sync
fallback. **Validated on the 3070:** guest/host MAP_SHARED mmaps of a file on
a DAX mount are genuinely coherent shared memory — heartbeat at full rate,
**echo RTT p50 = 2.09 ms, bounded by the probe's own 2 ms poll loop** (i.e.
sub-poll-interval latency). This is the clone-ring transport, working, with
zero libkrun changes — for a LIVE VM.

**The one remaining defect (clone path):** DAX does not survive
snapshot-restore. Inherited mappings die AND a FRESH post-fork mmap SIGSEGVs
in the clone — libkrun's fork restores RAM regions CoW but shm windows come
back as unbacked anonymous regions ("SHM/GPU stay anonymous", builder.rs),
with the guest kernel holding stale setupmapping state. Two fix paths, both
now unblocked because the libkrun submodule source IS in-tree (~/smolvm/libkrun,
smol-machines fork, one commit ahead of the bundle):
1. Restore-path fix: re-create the virtiofs DAX window backing at restore +
   have the agent remount (or the shim re-map) post-fork to rebuild mappings.
2. Original design: per-clone fresh MAP_SHARED memfd RAM window at restore
   (the fork machinery already classes regions — "only RAM regions are
   CoW-fork-backed" — add a fresh-shared class), advertised via the existing
   SMVGRAM2 machinery the daemon already consumes.

Either is a contained libkrun change now, not a fork-the-VMM project.

### P2b FEASIBILITY SOLVED (2026-07-20, H100): clone shared-memory transport works, zero libkrun changes

Full fork-DAX probe on the H100 with the SHIPPED libkrun bundle:
- Golden: coherent bidirectional shared memory, echo RTT p50 2.12 ms
- **CLONE, fresh mmap post-fork: RTT p50 2.11 ms — identical to golden.**
  A forked clone that re-mmaps the DAX file (the shim's remap-on-fork
  pattern) gets fully coherent host↔guest shared memory.

The entire enabler was smolvm-side (commit d623d14): the static launcher
now requests a 512 MB DAX window per user mount (SMOLVM_MOUNT_DAX=1) and
the agent mounts virtiofs `dax,sync` (guest shows `dax=always`; dmesg shows
`Cache len` per device). The earlier "needs a libkrun fork" conclusion was
wrong twice over: libkrun's per-device ShmManager was always there, and the
clone path works because DAX mappings are DEVICE state re-established by
fresh FUSE setupmapping in the clone — sidestepping the guest-RAM COW wall
entirely. (A diagnostic libkrun build was used to localize one probe
failure; it broke boots and is retired — the bundle needs no changes.)

**Remaining work to ship clone rings (all smolvm, scoped):** file-backed
ring setup — guest shim places its rings + doorbell in a file on the DAX
mount and re-mmaps on fork-detect; daemon mmaps the same file MAP_SHARED
(replacing the memfd/GPA advert path for clones); wire RingSetup to carry
file offsets instead of GPAs for this mode. Expected effect: clone
per-call transport drops from socket RTT to shared-memory latency — the
same 318→87 ms class of win the golden got from rings, applied to clones,
compounding with graph replay (P3b) and the sync-elimination work.

### P2b SHIPPED (2026-07-20): clone file-rings live — [ring-file] active

End-to-end on the local 3070 vLLM graphs gate: both clones negotiate the
DAX file-ring transport (`[ring-file] file rings active`) and serve at
**127–134 ms steady-state vs 169–235 ms on sockets (~40% faster), within
~1.4× of the golden's 91 ms** (was 2.5×). Implementation (commits 37cb826,
9b44267, 47dc1d7): `RingSetupFile` protocol op; shim falls back to file
rings when GPA rings are rejected (fresh file + fresh MAP_SHARED mmap on
the dax mount — the fork-safe pattern); implicit per-CUDA-machine ring
mount (/opt/smolvm-ring, 512 MB DAX window) injected by the launcher and
merged into every container's mounts by the agent; per-VM ring-dir advert
(SMVRDIR1) carried by both real channels and the warm dial so workers
spawn knowing the dir. H100 training re-measure queued (training was
measured 86% transport-idle — rings collapse those socket round-trips).

## 2026-07-21 — sync-tally findings: count is the wrong metric

Per-op sync tally of a 30-step QLoRA run (0.5B, 3070 clone): StreamSynchronize
1,667 (~55/step, bnb/unsloth-driven), LibCall(6,1) 499, EventCreate 240,
DeviceGetAttribute 210 (one-time misses), MemcpyGpaDtoH 174 (each a wasted
double-trip — clone GPA-map gap), EventElapsedTime 118. Clean-pipeline sync
elision implemented (client tracks pending-work state; syncs on a settled
stream return locally) — fired ~1/1,667: the training interleave is
launch-dense, the syncs are real. At ring RTTs the whole sync class is ~4% of
step time. CONCLUSION: the per-learner gap is NOT sync-count-bound; next
measurement must attribute TIME per op class (extend count_sync with
durations) before more targeting. The generic classification table remains
the right frame — entries just need time-weighting. Elision kept: correct,
free, and pays in idle-heavy serving patterns.

## 2026-07-21 (cont.) — time-weighted tally results and the corrected picture

Time-ranked sync profile (30-step 0.5B clone run): MemcpyGpaDtoH 1,483ms/174
calls dominates — but the A/B with a fast-fail latch showed most of those
SUCCEED (golden phase) and the 8.5ms/call is largely SYNC-POINT WAIT (the GPU
draining queued kernels before a D2H), not transport. Three metric
corrections in one evening: (1) sync COUNT pointed at required waits
(elision fired 1/1,667); (2) sync TIME pointed at an op that is mostly
GPU-busy time; (3) the honest residual per-learner gap remains the H100
solo number (clone 1,434 vs native 2,507 = 57%), and its next lever is
host-side pipeline OVERLAP (serve-loop batching between deferred ops), not
guest-side round-trip elimination. Shipped from this arc: time-weighted
tally tooling (COUNT_SYNC now reports ms + counts, incl. bridged ops),
clean-pipeline sync elision, clone GPA fast-fail latch. Local native 0.5B
baseline blocked by an Arch torch-cu124 quirk (cuInit fine, torch refuses)
— not worth chasing; H100 numbers carry the comparison.
