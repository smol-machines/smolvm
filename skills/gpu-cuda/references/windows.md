# CUDA on Windows

**Re-run on 2026-10-03 against smolvm v1.22.2** on Windows 11 Home build 10.0.26200 UBR 9457
x86_64 with an **NVIDIA GeForce RTX 4050 Laptop GPU** (driver 32.0.15.6626), in an elevated
session: the probe, the two absences, the shim in a plain `alpine` guest and the Vulkan note all
reproduced, and a real compute workload ran (below). The transcripts that follow are from the
**2026-09-11 run against v1.14.6** on build 10.0.26200.0 UBR 9445, where they read the same.

`--cuda` injects the same remoting shim as on Linux and the guest reaches the real device.
`$exe` is the path to `smolvm.exe` and `$probe` the packet's `scripts` folder.

```powershell
& $exe machine run --cuda --net --mem 6144 -v "${probe}:/probe:ro" --image python:3.12-slim -- python3 /probe/cuda-probe.py
```

This line is corrected from the one the runs used and has not been run itself.

Observed on v1.14.6, from the packet's own `scripts/cuda-probe.py`:

```
load_shim -> ok /opt/smolvm-cuda/libcuda.so.1
cuInit -> 0
cuDeviceGetCount -> 0 count = 1
cuDeviceGetName -> 0 name = NVIDIA GeForce RTX 4050 Laptop GPU
cuCtxCreate -> 0
cuMemGetInfo -> 0 total MiB = 6140
cuMemAlloc   -> 0
cuMemcpyHtoD -> 0
cuMemcpyDtoH -> 0
roundtrip first 16 bytes match: True
cuMemFree    -> 0
exit : 0
```

**The 1 MiB round trip is the assertion that matters**: the 16 marked bytes went to the device and
came back, so this is not a stub. The device name is the other one.

## A real workload, and one that silently does nothing

On v1.22.2, from `python:3.12-slim` with no CUDA toolkit, through Python `ctypes` against
`/opt/smolvm-cuda/libcuda.so.1`: a PTX vector add (`.target sm_50`) over 16777216 elements ran in
10.7 ms including the synchronize, and every sampled element equalled the float32 sum computed on
the host. Compare in float32: at magnitudes around four million float32 spacing is 0.5, and a
double-precision expectation reports false mismatches.

`cublasSgemm_v2`, reached through the shim's `libcublas`, **returns 0 and does not write its
output.** With C preloaded to 5, `alpha=1`, `beta=2` and all-ones inputs, a 256 by 256 product
should read 266 and read 5.0, on v1.22.2 as on v1.14.3. Preload the output and pick a `beta` that
separates "computed", "beta only" and "untouched" before trusting any BLAS call here.

## The two absences are correct

In a `--cuda` guest on v1.14.6, `/opt/smolvm-cuda` holds sixteen entries including `libcuda.so.1`,
`libcudart*`, `libcublas*`, `libcudnn*` and `proto-hash`, while:

```
ls: cannot access '/dev/nvidia*': No such file or directory
nvidia-smi absent
```

Both absences are the documented remoting design, not a broken setup. The driver API is the check,
and the probe above is what runs it.

The shim is injected even in a non-CUDA image: on v1.14.6 `machine run --cuda --image alpine` still
shows `/opt/smolvm-cuda` populated in a plain `alpine` guest. It cannot be loaded there, because
the shim is glibc, which is the next note.

## Windows-specific notes

- **Use a glibc image.** The shim is glibc and an Alpine guest cannot load it. `python:3.12-slim`
  is small and already has Python.
- **Load the shim by absolute path**, `/opt/smolvm-cuda/libcuda.so.1`, rather than by soname.
- **Large CUDA images may not pull.** `nvidia/cuda:12.4.1-base-ubuntu22.04` failed after 582 s
  with `crane blob failed ... unexpected EOF` on this host's network. A transfer failure, not a
  CUDA one, but another reason to prefer a small image.
- **Do not capture `machine run` output in PowerShell.** See the `install` packet's Windows page.
- **Vulkan is a different story.** `machine run --gpu` boots and exits 0, and in the guest
  `/dev/dri` does not exist and `dmesg` has zero `virtio_gpu` lines. No error, no warning, no
  mention that the flag was dropped.
