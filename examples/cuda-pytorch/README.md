# PyTorch on smolvm with `--cuda`

Run unmodified PyTorch (Runtime API) inside a microVM by forwarding CUDA to the
host NVIDIA GPU. The `smolvm-cudart-shim` + `smolvm-cuda-shim` libraries are
auto-staged over the image's pip NVIDIA wheels — **no code changes, no manual
`LD_LIBRARY_PATH`** — provided the image is built the right way.

## The one requirement: torch present at pull time

Auto-staging (`crates/smolvm-agent/src/cuda.rs`) scans the image rootfs **when
smolvm pulls it** and bind-mounts the guest shims over
`.../site-packages/nvidia/*/lib/{libcudart,libcublas,libcublasLt,libcudnn}.so.*`.
Those sonames are RPATH-pinned by PyTorch ahead of `LD_LIBRARY_PATH`, so
overlaying them in place is the only way to interpose. The wheels must therefore
exist in the image before the pull — not be `pip install`ed at runtime.

```bash
docker build -t torch-cuda .
docker save torch-cuda -o torch-cuda.tar
```

## Run

```bash
smolvm machine run --net --cuda --mem 16384 \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False \
  --image ./torch-cuda.tar -- \
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
smolvm machine run --net --cuda --image ./torch-cuda.tar -- \
  find /usr/local/lib/python3.11/site-packages/nvidia -name 'libcublas.so.12' -exec ls -la {} \;
# → ~600K  .../nvidia/cublas/lib/libcublas.so.12   (shim, good)
# → ~109M  ...                                       (real lib, staging did not run)
```

## What does NOT work

| Layout | Symptom | Fix |
|--------|---------|-----|
| conda `pytorch/pytorch` (`/opt/conda/lib/`) | `backward()` → `CUDA error` | build a pip-wheel image like this one, or `-e LD_PRELOAD=/opt/smolvm-cuda/libcudart-shim.so` |
| `pip install torch` at runtime | CUDA init fails / real libs load | bake torch into the image (this Dockerfile) |

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
