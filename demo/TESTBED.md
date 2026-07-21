# smolvm GPU testbed — replicable fork experiments

## The artifact: `smolvm-gpu-testbed.smolmachine` (133 MB)

A packed smolvm machine (debian bookworm + gcc + ca-certificates + the
experiment scripts baked at `/opt/experiments/`):
- `heartbeat.py` — minimal fork-correctness probe (plain torch)
- `density_train3.py` — 3-way QLoRA fine-tune fork sweep (Unsloth, alpaca)
- `realsweep.py` — full LR sweep with held-out eval + saved adapters
- `vllm_compare.py` — vLLM serving replica (cold-vs-fork comparisons)

## Host prerequisites (not in the artifact)

1. smolvm >= v1.6.12 (+ PR #675 fixes for vLLM/H100) with its shim pack
   (`drvlib/`: libcudart.so.12, libcuda.so.1, libcublas/Lt, libnvidia-ml —
   PROTO_HASH must match the binary).
2. A guest venv dir with torch 2.6.0+cu124 / unsloth 2026.7.2 / trl 0.18.2 /
   datasets 4.3.0 / vllm 0.8.5 (pin exactly; newer torch wheels demand cudart
   symbols the shim doesn't export).
3. HF model cache pre-downloaded on the host (virtiofs breaks HF's cache
   locking across VMs): Qwen2.5-0.5B/7B-Instruct (+ bnb-4bit variants).
   On Lambda: persistent filesystem `smolvm-testbed` (us-east-1) has all of
   the above prepared — launch with file_system_names and run testbed_boot.sh.

## Run an experiment

    smolvm machine create --name g --from smolvm-gpu-testbed.smolmachine \
      --cuda --net \
      -v $VENVDIR:/home/binsquare/ptwork:ro \
      -v $DRVLIB:/opt/drvlib:ro -v $COORD:/opt/coord:rw \
      -- sh -c "export LD_PRELOAD='/opt/drvlib/libcudart.so.12 /opt/drvlib/libcuda.so.1' \
        HF_HOME=/opt/hf PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True; \
        /home/binsquare/ptwork/venv/bin/python /opt/experiments/<script>"
    SMOLVM_CUDA_SHARED=1 smolvm machine start --forkable --name g
    # wait for READY in $COORD, then:
    smolvm machine fork --golden g --name exp1 --share-weights
    echo go > $COORD/GO

vLLM runs additionally need `VLLM_USE_V1=0` and `GPU_UTIL` sized to the card.
Harnesses that drive full comparisons: vllm_compare.sh, l8_vllm_scale.sh,
real-sweep.sh, unique-demo.sh (this directory / testbed FS scripts/).

Sharing: `smolvm pack push` can publish the artifact to an OCI registry.
