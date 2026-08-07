# PyTorch on smolvm with `--cuda`

Run unmodified PyTorch (Runtime API) inside a microVM by forwarding CUDA to the
host NVIDIA GPU. The `smolvm-cudart-shim` + `smolvm-cuda-shim` libraries are
auto-staged over the official PyTorch image's NVIDIA libraries — **no code
changes, local image build, or manual `LD_LIBRARY_PATH`**.

> This example depends on [#602](https://github.com/smol-machines/smolvm/pull/602)
> (conda library discovery) and
> [#638](https://github.com/smol-machines/smolvm/pull/638) (the Runtime exports
> required by conda PyTorch). Land all three together.

## The requirement: torch present at pull time

Auto-staging (`crates/smolvm-agent/src/cuda.rs`) scans the image rootfs when
smolvm pulls it and bind-mounts the guest shims over the CUDA libraries that
PyTorch resolves by RPATH. The supported layouts are pip NVIDIA wheels under
`.../site-packages/nvidia/*/lib/` and, with #602, conda libraries under
`/opt/conda/lib` and `/opt/conda/pkgs/*/lib`.

The image must therefore already contain PyTorch before the pull. This example
uses the upstream-maintained
`pytorch/pytorch:2.4.0-cuda12.4-cudnn9-runtime` image directly; smolvm remains
the only local runtime required.

## Run

```bash
smolvm machine run --net --cuda --mem 16384 \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False \
  --image pytorch/pytorch:2.4.0-cuda12.4-cudnn9-runtime -- \
  python3 -c "
import torch
print('cuda:', torch.cuda.is_available())
x = torch.randn(4, 4, device='cuda', requires_grad=True)
(x @ x).sum().backward()
print('backward ok')
"
```

## Verify staging worked

Inside the VM the pinned sonames should be small shim bind-mounts (~600 KB), not
the full NVIDIA libraries (tens–hundreds of MB):

```bash
smolvm machine run --net --cuda \
  --image pytorch/pytorch:2.4.0-cuda12.4-cudnn9-runtime -- \
  ls -lh /opt/conda/lib/libcudart.so.12
# → small shim bind-mount: staging worked
# → full NVIDIA library: staging did not run
```

## What does NOT work

| Layout | Symptom | Fix |
|--------|---------|-----|
| `pip install torch` at runtime | CUDA init fails / real libs load | use an image that already contains PyTorch |
| libraries in another custom directory | real CUDA libraries load | add the guest path with `SMOLVM_CUDA_STAGE_EXTRA_DIRS` (#602) |

## Known limitation: attention backward

Fused scaled-dot-product-attention (flash / memory-efficient) **backward**
kernels currently fail through the remoting path with
`CUDA error: invalid argument`. Training frameworks should select the **math**
SDPA backend until this is fixed:

```python
import torch
torch.backends.cuda.enable_flash_sdp(False)
torch.backends.cuda.enable_mem_efficient_sdp(False)
torch.backends.cuda.enable_math_sdp(True)
```

Forward inference (including flash attention) is unaffected.

## Smolfile

See [`pytorch.smolfile`](pytorch.smolfile) for the declarative form:

```bash
smolvm machine run --cuda -s examples/cuda-pytorch/pytorch.smolfile -- python3 train.py
```
