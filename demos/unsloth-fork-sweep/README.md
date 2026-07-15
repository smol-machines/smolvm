# Fork a warm GPU: one Unsloth model, N concurrent fine-tunes

`smolvm machine fork` clones a **running** CUDA VM — model weights hot on the
GPU, Python fully imported, trainer one call away. Each clone gets its own VM,
its own CUDA state, and the golden's warm memory at the same addresses, so
**unmodified Unsloth with default torch settings** resumes in seconds instead
of re-paying boot + import + model load.

```
golden (frozen, model hot) ──fork──► clone A  teaches addition      ┐
                            ──fork──► clone B  teaches multiplication │ concurrent,
                            ──fork──► clone C  teaches subtraction   ┘ isolated
```

## Numbers from the run in `demo-output.txt` (RTX 3070, 8 GB)

| | cold start | warm fork |
|---|---|---|
| time to first training step | ~54 s | **~4 s** |

- Three concurrent Qwen2.5-**1.5B** QLoRA fine-tunes on one 8 GB card — base
  weights live **once** (content-verified sharing), adapters/optimizer private.
- Clones are fully isolated: each learned only its own task; sequential
  re-forks are bit-identical.
- Zero config: `--forkable` auto-enables warm CUDA forking.

## Run it

```sh
./demo.sh                                    # defaults to Qwen2.5-1.5B 4-bit
SMOLVM_DEMO_VENV=~/ptwork ./demo.sh unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit
```

Requirements: linux + NVIDIA driver, a smolvm build with CUDA forking, a host venv containing
unsloth/torch (mounted read-only into the VM), and the smolvm CUDA shim libs
in `./drvlib` (`libcudart.so.12`, `libcuda.so.1`). First run downloads the
model into the coord mount's HF cache; later runs are offline.

## Why this matters for Unsloth users

- **Hyperparameter sweeps without reloading**: fork the warm base per config.
- **Colab-style timeouts, inverted**: the env, HF cache, and checkpoints live
  in the VM/overlay and survive restarts; the warm model survives as a frozen
  golden you can keep forking.
- **Reproducible env without Docker**: the pinned venv is mounted read-only;
  every clone sees the identical stack.
