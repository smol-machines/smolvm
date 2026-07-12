# PyTorch worker image for `smolvm --cuda`.
#
# torch (and its nvidia-* wheels) MUST be present at image PULL time so smolvm's
# auto-staging can overlay the guest CUDA shims onto the RPATH-pinned NVIDIA
# libraries under site-packages/nvidia/*/lib/. Installing torch at runtime inside
# `machine run` is too late — see AGENTS.md "PyTorch worker images".
#
#   docker build -t torch-cuda .
#   docker save torch-cuda -o torch-cuda.tar
#   smolvm machine run --net --cuda --mem 16384 --image ./torch-cuda.tar -- ...
FROM python:3.11-slim-bookworm
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cu124
