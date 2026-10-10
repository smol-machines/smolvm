# Core operation benchmarks

`smolbench.py` times the operations most workflows are made of: starting and
stopping a machine, one-shot runs, exec, file copy, checkpoint and restore,
branching, and packing. It needs no GPU and no network beyond one image pull.

```bash
# baseline for one binary
python3 bench/core/smolbench.py --bin ./target/release/smolvm

# A/B two binaries, e.g. main against a branch
python3 bench/core/smolbench.py --bin main=/tmp/smolvm-main --bin pr=./target/release/smolvm

# a subset, more rounds
python3 bench/core/smolbench.py --bin ./target/release/smolvm --only exec,cp --rounds 11
```

Set `SMOLVM_AGENT_ROOTFS` and `SMOLVM_LIB_DIR` as you would for a dev build;
they are passed through to every run.

## Method

- Each binary runs in its own HOME under `/tmp`, so the benchmark never sees
  or touches your machines, and two arms never share a cache. The ext4
  templates from `~/.smolvm` are linked in so checkpoint and pack work.
- With two binaries, rounds alternate between them and flip which one goes
  first each round. Thermal drift and background load land on both arms.
- Every timed operation must exit 0 and is checked: exec output is compared,
  copied files are size checked, a restored machine must read back state
  written before the checkpoint, a branch child must exec. A broken arm fails
  instead of looking fast.
- Setup (creating machines, building the image seed) is not timed. Image runs
  are measured warm; `--only pull_cold` measures the first run with an empty
  seed cache.
- The table reports medians. In A/B mode a change is called better or worse
  only when the two arms' interquartile ranges do not overlap, otherwise
  "within noise".
- `results/<run-id>.json` keeps every sample plus a manifest: binary version
  and md5, OS, CPU, cores, memory.

| Scenario | Metrics | What is timed |
|---|---|---|
| `start_stop` | `start_ms`, `stop_ms` | `machine start` and `machine stop` of an existing bare machine |
| `run_bare` | `run_bare_ms` | `machine run -- echo`, no image |
| `run_image` | `run_image_ms` | `machine run --net --image alpine:3.20 -- echo`, seed warm |
| `exec` | `exec_ms` | `machine exec -- echo` on a running machine |
| `cp` | `cp_upload_mbps`, `cp_download_mbps` | `machine cp` of a random file (`--cp-mib`, default 256) each way |
| `checkpoint` | `checkpoint_ms`, `checkpoint_pause_ms`, `restore_ms` | `machine checkpoint`, the source pause it reports, and create `--from` + start + first exec |
| `branch` | `branch_ms` | `machine branch` of one named child from a `--branchable` source |
| `pack` | `pack_ms` | `pack create --from-vm` of a stopped bare machine |
| `pull_cold` (opt-in) | `pull_cold_ms` | first image run with the seed cache cleared |

## Baseline

Apple M1 Pro, 8 cores, 16 GiB, macOS 26.6, smolvm 1.25.4 at 8616d4e1, 7 rounds
([results/20261009-224353.json](results/20261009-224353.json)).

| Metric | Median | p25 to p75 |
|---|---|---|
| start | 140 ms | 138 to 146 |
| stop | 27 ms | 26 to 28 |
| run bare | 164 ms | 157 to 167 |
| run image (warm) | 865 ms | 828 to 897 |
| exec | 11 ms | 10 to 11 |
| cp upload | 151 MB/s | 149 to 151 |
| cp download | 184 MB/s | 182 to 185 |
| checkpoint | 2243 ms | 2209 to 2318 |
| checkpoint source pause | 1968 ms | 1828 to 2049 |
| restore to first exec | 1177 ms | 1162 to 1201 |
| branch | 225 ms | 215 to 233 |
| pack | 15516 ms | 15148 to 15908 |

The same binary run against itself as an A/B (6 rounds) put every metric
within noise, with medians 0 to 4% apart and branch 10% apart. Treat smaller
differences on branch as noise.
