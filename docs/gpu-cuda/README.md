# CUDA inside a machine

`--cuda` remotes the guest's CUDA **Driver API** calls to the host's NVIDIA GPU over vsock. It is a
different feature from `--gpu`, which is Vulkan graphics; they share nothing but the word GPU.

`SKILL.md` is the procedure and carries the version stamps and the per-platform results.

## What the host and the guest need

The host needs a working NVIDIA driver, meaning `libcuda.so.1` and a loaded kernel module. **No
CUDA toolkit is required on either side for the Driver API**, and nothing needs installing beyond
that: no container toolkit, no device plugin, no root. Enable it with `--cuda` on `machine run` or
`machine create`, or `cuda = true` in a Smolfile.

The guest gets **no NVIDIA driver and no `/dev/nvidia*`**. A compatibility `libcuda.so.1` is
injected at `/opt/smolvm-cuda` and forwards Driver API calls to a host daemon that owns the device.
`nvidia-smi` is absent inside the guest and that is correct; neither its absence nor the absence of
`/dev/nvidia*` tells you anything about whether the GPU is reachable.

## Because the API is remoted, an exit code proves nothing

A program can start, link against `libcuda.so.1` and exit zero without a GPU ever being reached.
The packet's probe asserts a device name and a transferred result instead.

**A device name and a passing round trip are not enough either.** When the host cannot load the
NVIDIA driver library (`libcuda.so.1` on Linux), the host side answers with a CPU emulation device:
`cuDeviceGetName` returns `smolvm CPU emulation device`, memory is reported as 1024 MiB, and the
first 16 bytes of a 1 MiB round trip come back as sent. The device **name** is what tells them
apart, and `scripts/run-cuda-probe.sh` reports `device_kind=cpu_emulation` and
`result=cpu_emulation_not_gpu` rather than a pass. Seen on macOS arm64 on v1.16.1, v1.18.2 and
v1.22.2 and on Linux aarch64 on v1.18.2.

**To answer "can this machine run CUDA", run the preflight and nothing else.** It reports
`gpu_present`, the driver version and whether your user can open `/dev/kvm`, and it starts no VM.
Reaching for the probe on a GPU-less host starts a machine and comes back with something that reads
like a yes.

## What is covered

Init and device queries, contexts including the primary-context flow the CUDA runtime uses, module
load and unload for PTX, cubin and fatbin, allocation and copies in both directions, kernel launch,
streams, events and `cuGetProcAddress`. Work executes synchronously on the host, and `*Async` calls
complete before returning, which the CUDA contract permits. This covers programs written against
the Driver API, the `cu*` C functions.

## Use a glibc image, and load the shim by path

The shim is glibc, so an Alpine guest cannot load it. Load it as
`/opt/smolvm-cuda/libcuda.so.1` rather than relying on the loader path, which picks up whatever the
image carries.

## Isolation, and the host kernel

[GPU and CUDA](../gpu.md) is the reference for both: GPU isolation under remoting is process-level
rather than a VM boundary, and Linux hosts that branch many machines want the KVM fix it names. It
also links the design write-up.

## Platforms

macOS has no CUDA driver, so `--cuda` has nothing to load there. CUDA remoting was verified on
Windows on v1.22.2 against an RTX 4050, including a device round trip; where the project's pages
say GPU acceleration is unavailable on Windows, they mean the Vulkan `--gpu` path, a different
feature. `references/windows.md` has that run.
