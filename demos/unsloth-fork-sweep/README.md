# Concurrent Unsloth fine-tunes from one loaded model

`smolvm machine fork` clones a running CUDA VM. This demo boots a golden VM
that loads Qwen2.5-1.5B (4-bit) with unmodified Unsloth and freezes; three
forked clones then fine-tune different tasks concurrently.

```
golden (frozen) ──fork──► uns-add  ┐
                ──fork──► uns-mul  │ train concurrently, isolated
                ──fork──► uns-sub  ┘
```

Measured on an RTX 3070, 8 GB (`demo-output.txt`): cold start to first
training step ~54 s; fork to first training step ~4 s; peak VRAM 3.9 GB for
the golden plus all three clones, with base weights shared across them.

## Run it

```sh
./demo.sh                                    # defaults to Qwen2.5-1.5B 4-bit
SMOLVM_DEMO_VENV=~/ptwork ./demo.sh unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit
```

Requirements: linux + NVIDIA driver, a smolvm build with CUDA forking, a host
venv containing unsloth/torch (mounted read-only into the VM), and the smolvm
CUDA shim libs in `./drvlib` (`libcudart.so.12`, `libcuda.so.1`). The first
run downloads the model into the coord mount's HF cache; later runs are
offline.

## How it works

- The golden loads the model + LoRA, runs `fix_untrained_tokens` once
  (recommended for 3+ clones with weight sharing), writes a READY marker, and
  blocks on a GO file. `machine fork` snapshots it in that state.
- Each clone claims a distinct task via `O_CREAT|O_EXCL` files on the shared
  mount, builds its trainer, trains, and writes its result.
- Weight sharing is opt-in (`SMOLVM_CUDA_FORK_SHARE_WEIGHTS=1`): a chunk is
  shared only if fork-time verification shows its device content still matches
  the uploaded weights; everything else is copied per clone.
