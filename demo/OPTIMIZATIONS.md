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

**Design**: the per-VM proxy sends a one-time control preamble on daemon
connections carrying (memfd via SCM_RIGHTS, region table gpa→offset);
daemon mmaps and installs per-VM guest-RAM maps on that connection's
backend → `gpa_to_hva` works → RingSetup succeeds → doorbell+shared-page
transport replaces per-call socket round-trips. Also un-breaks the
MemcpyGpa* zero-copy fallbacks (the benign 0xb3→500s).

**Gate**: `[ring]` establishes in-VM; batch-1 p50 re-measured (expect
~405 ms → double-digit ms).

## P3 — CUDA graphs inside forkable sessions

Capture fails today (found by QA; forced every benchmark to eager). With
graphs, a decode step is ONE remoted launch instead of hundreds of calls —
the big algorithmic multiplier on top of P2. Needs root-cause first;
repro: torch graph capture in a forkable VM.

## P4 — Smaller

- Drop the per-VM proxy hop (daemon on vsock directly, or splice()).
- Adaptive quiet-op fencing; coalesced writes.
- MPS for multi-replica time-slicing (helps both arms).

## Measurement discipline

Every lever gets a before/after on the same harness that measured the
floor (`vllm_compare.py` b1/b40/b160 + the head-to-head), appended to
BENCHMARKS.md with the engine commit.
