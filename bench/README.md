# Fork-pool benchmark harness

Measures the same post-training workload two ways on one GPU, so claims about
smolvm's fork pool can be checked rather than believed:

- **native** — N learner processes on bare metal, each loading its own base model
- **fork** — one smolvm golden VM loads the base once, then N `--share-weights`
  clones, CUDA remoted to the host daemon

Both arms run the *same* workload file with the same
`STEPS/BATCH/MAXSEQ/MODEL`, and are measured the same way: wall clock from t0 to
the last learner finishing, 1 Hz `nvidia-smi` peak sampling, and per-learner
tok/s taken from the workload's own JSONL. Every run writes
`results/<run-id>.json` including an environment manifest (smolvm version +
binary md5, rootfs proto-hash, shim md5, driver, torch, GPU, host cores).

## Prerequisites

The harness does not build or install anything. You need, on the GPU host:

| Requirement | Default | Override |
|---|---|---|
| smolvm binary | `~/smolvm/smolvm` | `SMOLVM=` |
| libkrun dir | `~/smolvm/lib/linux-x86_64` | `SMOLVM_LIB_DIR=` |
| Python venv with torch + unsloth + trl | `~/ptwork/bin/python` | `PY_VENV=` |
| Machine image (`.smolmachine`) with that venv baked in | `~/qlora-baked.smolmachine` | `PACK=` |
| Model in the HF cache (`~/hf`) | `unsloth/Qwen2.5-7B-bnb-4bit` | `MODEL=` |
| NVIDIA GPU + driver | — | — |

**The agent rootfs must carry CUDA guest shims built from the same tree as the
smolvm binary.** If they disagree you get
`PROTOCOL MISMATCH: client wire hash … != server …` and the golden never loads.
Stage them together:

```sh
T=<repo>/target/release
R=~/.local/share/smolvm/agent-rootfs/usr/local/lib/smolvm-cuda
cp $T/libcudart.so $R/libcudart-shim.so
cp $T/libcuda.so   $R/libcuda.so.1
cp $T/libnvidia_ml.so $R/libnvidia-ml.so.1
ln -sf libcuda.so.1 $R/libcuda.so          # Triton's JIT links -lcuda
ln -sf libcudart-shim.so $R/libcudart.so
$T/smolvm-cuda-run --proto-hash > $R/proto-hash
```

## Running

```sh
./bench.sh --arm native --n 4 --steps 20 --cpus 4
./bench.sh --arm fork   --n 4 --steps 20 --cpus 4 --share on
./summarize.py                    # median + spread per (arm, N, batch), and the ratio
```

Flags that exist because leaving them out produces misleading numbers:

- `--cpus K` — pin **each** native learner to its own K-core set, matching the
  per-VM vCPU count in the fork arm. Without this, native silently gets the
  whole host (26 cores here) while each clone VM gets 4. `--cpus 0` = unpinned.
- `--share on|off|default` — sets `SMOLVM_CUDA_FORK_SHARE_WEIGHTS` **and checks
  the daemon honoured it**, printing `!! CONTROL FAILED` if a copy-mode arm
  actually shared. An earlier control silently ran the wrong configuration; this
  is the guard against repeating that.
- `--reps R` — repeat; `summarize.py` reports median and min–max. Single runs are
  not evidence: the golden load is bimodal (~15s vs ~156s) and one N=16 run in
  three produced `nan` learners.
- `--cold` — drop the page cache first (default warms both arms identically).
- `--batch` / `--maxseq` — kernel size. The default (2 × 256) is launch-latency
  bound, which flatters neither arm honestly.

`matrix.sh` (scaling + kernel-size sweep) and `highn.sh` (native vs fork at high
N) drive `bench.sh` sequentially — the GPU must be exclusive or every number is
noise. `bench.sh` refuses to start if the GPU already holds >500 MiB.

## Reading the output

```
wall=253.79s done=4/4 agg_tok_s=546 peak_gpu=14550MiB golden_load=165.59s
```

- `done` — learners that reported `event: done`. **Less than N usually means OOM**;
  `summarize.py` flags those rows, since a partial aggregate looks like a real
  datapoint otherwise.
- `peak_gpu` — whole-device peak, so it includes the golden's own context in the
  fork arm. For a per-process split use `probe_mem.sh` during a run.
- `golden_load` — fork arm only; paid once per pool, not per learner.

Analysis helpers: `nan_census.py` (nan count per run across `results/`),
`parse_losses.py <run-dir>` (per-learner losses for one run).

## Caveats a reader should know

1. **Throughput and density are separate questions.** Weight sharing changes
   VRAM, not FLOPs — measured +6% aggregate at N=4, i.e. noise.
2. **CPU becomes the limit before VRAM does.** At 4 vCPU per clone on a 26-core
   host, aggregate throughput peaks near N=8 and falls at N=16. High-N results
   measure a memory ceiling, not useful throughput.
3. **`nan` learners appear intermittently at N=16** (1 run in 3; never at N≤8).
   Not yet attributed — a copy-mode control at N=16 is impossible because it
   needs ~118 GiB on an 80 GiB card.
4. **A ~750 MiB CUDA context can leak after a fork run.** The preflight check
   catches it and aborts rather than measuring on a dirty GPU; kill stray
   `_cuda-daemon` / `_cuda-clone-worker` processes between runs.
5. The workload (`workload_dpo.py`) writes its trainer output under `$OUTBASE`;
   it is a copy of the DPO fork workload with that path made configurable so the
   same file runs both in-VM (as root) and on the host.
