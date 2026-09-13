---
name: gpu-cuda
description: Runs CUDA compute workloads inside a smolvm microVM against a real host NVIDIA GPU, using smolvm's --cuda API remoting. Use when a workload in a machine needs a GPU; when nvidia-smi or /dev/nvidia* is missing inside a --cuda guest; when a CUDA program in a machine exits zero but seems not to touch the device; when the shim will not load in an Alpine image; or when checking whether CUDA is available on a given platform, including Windows. Do not use it for Vulkan graphics (--gpu), which is a separate feature that works on no tested host, and do not expect it on a Mac, which has no NVIDIA hardware.
---

# CUDA inside a machine

Verified on **smolvm v1.14.6** against an **NVIDIA A10** (driver 580.105.08, Linux x86_64,
kernel 6.8.0-1046-nvidia), and on the same version against an **NVIDIA GeForce RTX 4050**
(driver 32.0.15.6626, Windows x86_64). Done means a program in the VM opens the device, creates a context, and moves
data to and from it.

> **Read this before trusting a step here.** **The Linux GPU path was re-run end to end on
> v1.14.6**, on a rented A10 instance: the preflight, the probe against the real device with two
> different glibc images, all three eval prompts, and the cleanup. **Windows was re-run on
> v1.14.6 too**, on 2026-09-11 against an RTX 4050: the probe, the two absences and the shim in a
> plain `alpine` guest. The section "What was not run" lists every remaining step individually.

## How this works, and why the checks are shaped this way

The guest gets **no NVIDIA driver and no `/dev/nvidia*`**. A compatibility `libcuda.so.1` is
injected at `/opt/smolvm-cuda` inside the guest and forwards CUDA driver calls over vsock to a host
daemon that owns the device. Nothing is needed on the host beyond a working NVIDIA driver: no extra
packages, no container toolkit, no device plugin.

Because the API is **remoted rather than passed through**, a program can start, link against
`libcuda.so.1` and exit zero without a GPU ever being reached. **Assert a device name and a
transferred result, never an exit code.**

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

Read-only: it starts no VM and touches no NVIDIA state. It reports the GPU and driver version,
whether your user can open `/dev/kvm`, and the host's own `libcuda` count. `result=blocked` with
`gpu_present=no` is the answer that saves the most time, because the failure without it names
neither CUDA nor the GPU.

**2. Run the probe.**

```bash
scripts/run-cuda-probe.sh                     # python:3.12-slim
scripts/run-cuda-probe.sh <other glibc image>
```

It mounts `scripts/` into the guest and runs `cuda-probe.py` under `--cuda`, then asserts two
values from the output:

```
device_named=ok
data_roundtrip=ok
result=cuda_ok
```

On the A10 on v1.14.6, `cuda-probe.py`'s own output was:

```
load_shim -> ok /opt/smolvm-cuda/libcuda.so.1
cuInit -> 0
cuDeviceGetCount -> 0 count = 1
cuDeviceGetName -> 0 name = NVIDIA A10
cuCtxCreate -> 0
cuMemGetInfo -> 0 total MiB = 22587
cuMemAlloc   -> 0
cuMemcpyHtoD -> 0
cuMemcpyDtoH -> 0
roundtrip first 16 bytes match: True
cuMemFree    -> 0
```

`roundtrip ... True` is the one that matters. It is the only line that proves bytes reached the
device.

**3. Clean up.** CUDA images are large.

```bash
scripts/cleanup.sh --purge
smolvm machine prune --name <NAME> --all   # any persistent --cuda machine you kept
```

The probe runs are ephemeral and leave nothing to prune; `machine prune` takes a machine name and
is rejected without one.

`--cuda` changes nothing on the host: the shim is injected inside the guest only. Verified after a
full session of CUDA runs plus a Kubernetes install and teardown on the same box, where
`nvidia-smi` still reported the device and a whole-filesystem sweep for `*smolvm*` came back empty.

## Traps

Full detail in `references/traps.md`.

- **A zero exit code proves nothing.** The remoted API is why.
- **`nvidia-smi` is absent inside the guest and that is correct.** So is `/dev/nvidia*`. Neither is
  a useful check.
- **Use a glibc image and load the shim by absolute path.** The shim is glibc, so an Alpine guest
  cannot load it, and relying on the loader path picks up whatever the image carries.
- **A fresh GPU cloud instance does not have KVM access for your user**, and the installer says the
  install succeeded anyway. `sg kvm -c` applies the group without a logout.
- **On a host with no NVIDIA GPU the error names neither CUDA nor the GPU.** Observed on Ubuntu
  24.04 aarch64: `agent did not become ready within 30 seconds`, which reads exactly like host
  load. The preflight is the only thing that tells the two apart.
- **`--cuda` and `--gpu` are different features.** `--cuda` is compute over vsock and works;
  `--gpu` is Vulkan over virtio-gpu and works on no host tested. On Windows `--gpu` is accepted and
  silently does nothing.

## Security defaults, and why they are the defaults

- **The guest never gets the device, and that is the isolation.** No `/dev/nvidia*` is passed
  through, so a workload in the machine cannot reach the driver directly, reprogram it, or see
  another VM's device state through it. What it gets is a forwarded API surface.
- **What that surface exposes is still real.** A remoted CUDA call runs against the host's driver
  and the host's memory allocator, so treat a `--cuda` machine as having a channel to a privileged
  host component. The VM boundary is what makes that acceptable; it is not zero authority.
- **Nothing here needs root or a container toolkit on the host.** If a procedure asks you to
  install a device plugin or run the CLI as root to get CUDA working, it is not this procedure.
- **The scripts wrap the public CLI only**, mount only this packet's own `scripts/` directory into
  the guest, and cleanup deletes only names it recorded under the `smolskill-` prefix.

## Platform arms

- **Linux x86_64 with an NVIDIA GPU**: **verified on an A10 on v1.14.6** (driver 580.105.08,
  kernel 6.8.0-1046-nvidia), preflight through cleanup, with the probe run against two glibc
  images.
- **Windows x86_64 with an NVIDIA GPU**: **verified on an RTX 4050 on v1.14.6**, on 2026-09-11
  (driver 32.0.15.6626), including the device name and a 1 MiB device round trip.
  `references/windows.md`. **This contradicts three documentation pages**, which this branch
  corrects.
- **macOS arm64 and Intel**: **not applicable.** No Mac has an NVIDIA GPU, so `--cuda` has nothing
  to reach. The preflight says so rather than letting a run time out.
- **Linux aarch64**: no NVIDIA hardware on the hosts available here. Only the preflight and the
  failure path were run.
- **Multi-GPU, GPU forks and clones, and a real training or inference workload**: not run anywhere.

## Eval prompts, and what they produced

The first two need a GPU host and are recorded from the earlier runs; the third was run in this
session. Which is which is stated per prompt.

**1. "Run a CUDA workload in a smolvm machine and prove it reached the GPU." (re-run on v1.14.6
on the A10)**

```
load_shim -> ok /opt/smolvm-cuda/libcuda.so.1
cuInit -> 0
cuDeviceGetCount -> 0 count = 1
cuDeviceGetName -> 0 name = NVIDIA A10
cuCtxCreate -> 0
cuMemGetInfo -> 0 total MiB = 22587
cuMemAlloc   -> 0
cuMemcpyHtoD -> 0
cuMemcpyDtoH -> 0
roundtrip first 16 bytes match: True
cuMemFree    -> 0
```

**2. "`nvidia-smi` is not in my `--cuda` guest and there is no `/dev/nvidia0`. Is the GPU
working?" (re-run on v1.14.6 on the A10)**

Both absences are correct. Inside a `--cuda` guest on `python:3.12-slim`:

```
--- /opt/smolvm-cuda ---
libcublas.so.11
libcublas.so.12
libcublas.so.13
libcublasLt.so.11
libcublasLt.so.12
libcublasLt.so.13
libcuda.so
libcuda.so.1
--- /dev/nvidia* ---
ls: cannot access '/dev/nvidia*': No such file or directory
--- nvidia-smi ---
nvidia-smi: not present in the image
--- SMOLVM_CUDA env ---
SMOLVM_CUDA_ZEROCOPY=1
```

The driver API is the check, and the probe above is what runs it.

**3. "Can this machine run CUDA?" (re-run on v1.14.6; the A10 answer is new, the two negative
answers are from hosts with no NVIDIA hardware)**

On the A10, where the answer is yes:

```
platform=linux-x86_64
accel=kvm
accel_access=ok
gpu_present=yes
gpu=NVIDIA A10, 580.105.08
host_libcuda=1
guest_needs_glibc_image=yes
guest_shim_path=/opt/smolvm-cuda/libcuda.so.1
result=ready
```

And where it is no:

macOS 26.6.2 arm64:

```
platform=darwin-aarch64
gpu_present=no
unsupported=cuda,vulkan
note=no Apple Silicon or Intel Mac has an NVIDIA GPU, so --cuda has nothing to reach here. This is a hardware fact, not a smolvm limitation.
result=blocked
```

Lima `linux-kvm`, Ubuntu 24.04 aarch64:

```
platform=linux-aarch64
accel_access=ok
gpu_present=no
note=no nvidia-smi on this host, so there is no GPU for the remoting daemon to own
host_libcuda=0
result=blocked
```

and running the probe anyway, to record what a user sees when they skip the preflight:

```
Starting ephemeral machine (vm-5d98e4be)...
Error: agent operation failed: start machine: agent operation failed: wait for ready:
agent did not become ready within 30 seconds
device_named=FAIL
data_roundtrip=FAIL
result=FAILED
```

The error names neither CUDA nor the missing device.

## Re-verified on v1.14.6

Run 2026-09-11 PT against v1.14.6 from the published release, installed into an isolated data root
on a rented **NVIDIA A10** instance: 30 vCPU Intel Xeon Platinum 8358, 222 GiB memory, kernel
6.8.0-1046-nvidia, driver 580.105.08, 23028 MiB of device memory.

**The GPU path is no longer written from an earlier run.** preflight, probe, all three eval
prompts and cleanup were executed in the packet's own order:

```
preflight            result=ready, gpu_present=yes, gpu=NVIDIA A10, 580.105.08, host_libcuda=1
probe, default image device_named=ok, data_roundtrip=ok, result=cuda_ok
probe, second image  device_named=ok, data_roundtrip=ok, result=cuda_ok
cleanup --purge      machines=clean, vm_processes=none
```

The probe was run against **two** glibc images, `python:3.12-slim` and `python:3.12-bookworm`, and
both reported `name = NVIDIA A10` and `total MiB = 22587` with the 1 MiB round trip returning the
same bytes.

**The host is untouched by `--cuda`, and that is now measured rather than quoted.** After the
session `nvidia-smi` reported `NVIDIA A10, 580.105.08, 23028 MiB, 0 MiB` used, a whole-filesystem
sweep for `*smolvm*` outside the install prefix and the data root returned nothing, and the eight
NVIDIA kernel modules were still loaded.

**The KVM precondition in the traps reproduced on this instance.** A fresh box has `/dev/kvm` as
`root:kvm` with the login user outside the group, so the preflight reported `KVM_DENIED` until the
group was granted. The single-command `sg kvm -c` form the traps recommend was not the route used
here; a group change plus a new login session was.

**One step failed as written on v1.14.6 and is now fixed.** The cleanup section said `smolvm
machine prune` bare, which the CLI rejects:

```
$ smolvm machine prune
Usage: smolvm machine prune --name <NAME>
```

Its help reads as host-wide ("Remove unused images and layers to free disk space") while the
command prunes one machine's unreferenced layers, `--all` its cached images. The section now names
the machine and says the ephemeral probe runs leave nothing to prune.

## What was not run

The Linux GPU path was re-run on v1.14.6, and the Windows one on 2026-09-11. What remains unrun:

- **The preflight and the cleanup on Windows.** `scripts/*.sh` are POSIX shell and do not run
  there, so the 2026-09-11 v1.14.6 run issued the probe and the eval prompts by hand.
- **`--cuda` with a CUDA base image** (`nvidia/cuda:...`), and the `apt-get install -y python3`
  those images need. Both probe runs used a Python image, which is what the packet recommends.
- **The `sg kvm -c` single-command remedy.** The `KVM_DENIED` state it addresses did reproduce on
  a fresh instance; the fix applied was a group change and a new session.

Never run anywhere, then or now:

- **GPU forks and clones.** `introduction/concepts/gpu.md` sells this as a reason for the remoting
  design, and a CUDA clone has its own shorter 10 s ready timeout.
- **Multi-GPU**, and contention between two machines sharing one device.
- **A real workload.** These are driver-API assertions, not a training or inference run, and say
  nothing about throughput or how much of the CUDA API surface is implemented.

## Related packets

- `install` for the KVM group precondition, which a fresh GPU instance fails.
- `teardown` for the cleanup script. CUDA images are large enough that `machine prune` is worth it.
