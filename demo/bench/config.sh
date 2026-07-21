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
: "${VENV:=$HOME/ptwork}"           # python venv with torch/unsloth/trl/bnb (see REPRODUCIBILITY.md l7_freeze.txt)
: "${PYBIN:=$VENV/bin/python}"      # python inside VENV (as mounted in guest)
: "${HF:=$HOME/hf}"                 # HuggingFace cache with the model pre-downloaded
: "${MODEL:=unsloth/Qwen2.5-7B-bnb-4bit}"
: "${WORKLOAD:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/qlora_train.py}"  # demo/qlora_train.py

# --- the sweep knobs ----------------------------------------------------------
: "${N:=8}"        # number of concurrent learners
: "${STEPS:=8}"    # training steps per learner
: "${IMG:=qlora-base}"  # docker image for the container arm (same venv + CUDA)

# Where the guest sees the venv (must match how VENV is mounted). The workload's
# python path inside the guest is derived from this.
: "${GUEST_VENV:=/home/binsquare/ptwork}"
: "${GUEST_PYBIN:=$GUEST_VENV/bin/python}"
