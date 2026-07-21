#!/bin/bash
# Shared config for the smolvm-vs-containers benchmark. Override any of these
# by exporting them before running ./benchmark.sh, or edit here. Every path is
# a host path on the GPU box.

# --- required tooling (build from the same source; see QUICKSTART.md) ---------
: "${SMOLVM:=$HOME/smolvm/smolvm}"                 # the smolvm binary
: "${SMOLVM_LIB_DIR:=$HOME/smolvm/lib/linux-x86_64}" # libkrun/libkrunfw bundle
export SMOLVM_LIB_DIR
: "${DRVLIB:=$HOME/drvlib}"                         # guest CUDA shims (libcudart.so.12, libcuda.so.1) from the SAME build

# --- the guest workload environment -------------------------------------------
# The smolvm arm boots from a BAKED machine: a packed VM with the venv + model
# cache on its own block storage, so the guest never mounts them over virtiofs
# (a host symlink/venv mount can't be followed across the guest boundary) and
# never re-downloads. Build it once with ./make-baked.sh (needs VENV + HF).
: "${BAKED:=$HOME/qlora-baked.smolmachine}"
: "${VENV:=$HOME/ptwork}"           # python venv (used only by make-baked.sh + the container arm)
: "${HF:=$HOME/hf}"                 # HuggingFace cache with the model pre-downloaded (used by make-baked.sh + containers)
: "${MODEL:=unsloth/Qwen2.5-7B-bnb-4bit}"
: "${WORKLOAD:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/qlora_train.py}"  # demo/qlora_train.py
# Where the venv lives INSIDE the baked machine (make-baked.sh copies it here):
: "${GUEST_PYBIN:=/home/ubuntu/ptwork/bin/python}"

# --- the sweep knobs ----------------------------------------------------------
: "${N:=8}"        # number of concurrent learners
: "${STEPS:=8}"    # training steps per learner
: "${IMG:=qlora-base}"  # docker image for the container arm (same venv + CUDA)
