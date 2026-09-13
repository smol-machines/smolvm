# CUDA on Windows: it works, and the documentation says it does not

**Re-run on 2026-09-11 against smolvm v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445
x86_64 with an **NVIDIA GeForce RTX 4050 Laptop GPU** (driver 32.0.15.6626), in an elevated
session. The probe, the two absences and the shim in a plain `alpine` guest all reproduced. The
Vulkan note and the documentation section further down are from the earlier run on v1.14.2.

`--cuda` injects the same remoting shim as on Linux and the guest reaches the real device:

```powershell
& $exe machine run --cuda --net --mem 6144 -v "$probe:/probe" --image python:3.12-slim -- python3 /probe/probe.py
```

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

**The 1 MiB round trip is the assertion that matters**: bytes went to the device and came back
unchanged, so this is not a stub. The device name is the other one.

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

## What the docs say, and which one is right

At v1.14.2 three places state that Windows has no GPU acceleration, and **all three are wrong for
CUDA**:

- `AGENTS.md:13`, "no GPU acceleration"
- `README.md:300`, "Not yet available on Windows: GPU acceleration"
- the shipped `README.txt`, "NOT YET SUPPORTED ON WINDOWS: GPU acceleration"

The accurate page is `introduction/concepts/supported-platforms.md:29`, which says Windows "lacks
**Vulkan** GPU acceleration, VM fork, and snapshots". Saying Vulkan specifically is exactly right.

This branch corrects the first three to say Vulkan rather than GPU.
