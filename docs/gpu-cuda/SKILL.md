---
name: gpu-cuda
description: Runs CUDA compute workloads inside a smolvm microVM against a real host NVIDIA GPU, using smolvm's --cuda API remoting. Use when a workload in a machine needs a GPU; when nvidia-smi or /dev/nvidia* is missing inside a --cuda guest; when a CUDA program in a machine exits zero but seems not to touch the device; when the shim will not load in an Alpine image; or when checking whether CUDA is available on a given platform, including Windows. Do not use it for Vulkan graphics (--gpu), which is a separate feature, in docs/gpu.md, and do not expect it on a Mac, which has no CUDA driver.
---

# CUDA inside a machine

Verified on **smolvm v1.22.2** against an **NVIDIA GeForce RTX 4050** (driver 32.0.15.6626,
Windows x86_64), 2026-10-03, and on **v1.14.6** against an **NVIDIA A10** (driver 580.105.08,
Linux x86_64, kernel 6.8.0-1046-nvidia). Done means a program in the VM opens the device, creates a context, and moves
data to and from it.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

> **The GPU path was last run end to end on Linux x86_64 on v1.14.6**, on an A10: the
> preflight, the probe against two glibc images, all three eval prompts and the cleanup. **Windows
> was re-run on v1.22.2** against an RTX 4050: the probe, the two absences, the shim in a plain
> `alpine` guest, and a vector add over 16777216 elements; see `references/windows.md`. The macOS
> arm64 and Linux aarch64 hosts have no NVIDIA hardware, so what runs there is the no-GPU answer,
> on v1.22.2 on macOS and v1.18.2 on Linux aarch64: the preflight reports `gpu_present=no` without
> starting anything, and `--cuda` reaches a CPU emulation device, which the probe names rather than
> passing. "What was not run" lists every remaining step.

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
`gpu_present=no` is the answer that saves the most time, because a run without a GPU does not
fail: it reaches the CPU emulation device.

**If the question is "can this machine run CUDA", the preflight answers it and nothing else needs
to run.** Do not reach for the probe to decide that: on a host with no NVIDIA GPU the probe starts
a VM, reaches a CPU emulation device and returns a passing round trip, which reads like a yes.
Verified on macOS arm64 on v1.16.1, v1.18.2 and v1.22.2: `gpu_present=no` and `unsupported=cuda`;
on v1.22.2 the note read `macOS has no CUDA driver, so --cuda has nothing to reach here.`

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
device_kind=gpu
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

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

The probe runs are ephemeral and leave nothing to prune; `machine prune` takes a machine name and
is rejected without one.

`--cuda` changes nothing on the host: the shim is injected inside the guest only. Verified after a
series of CUDA runs plus a Kubernetes install and teardown on the same host, where
`nvidia-smi` still reported the device and a whole-filesystem sweep for `*smolvm*` came back empty.

## Traps

Full detail in `references/traps.md`.

- **A zero exit code proves nothing.** The remoted API is why.
- **A device name and a passing round trip do not prove a GPU either.** When the host cannot load
  the NVIDIA driver library, the host side answers with a CPU emulation device: `cuInit -> 0`,
  `cuDeviceGetCount -> 0 count = 1`, `cuDeviceGetName -> 0 name = smolvm CPU emulation device`,
  `total MiB = 1024`, and `roundtrip first 16 bytes match: True`. **The device name is the
  discriminator.** `scripts/run-cuda-probe.sh` now reports `device_kind=cpu_emulation` and
  `result=cpu_emulation_not_gpu` for it instead of `result=cuda_ok`.
- **`nvidia-smi` is absent inside the guest and that is correct.** So is `/dev/nvidia*`. Neither is
  a useful check.
- **Use a glibc image and load the shim by absolute path.** The shim is glibc, so an Alpine guest
  cannot load it, and relying on the loader path picks up whatever the image carries.
- **A fresh GPU cloud instance does not have KVM access for your user**, and the installer says the
  install succeeded anyway. `sg kvm -c` applies the group without a logout.
- **`agent did not become ready within 30 seconds` from the probe is about memory, not the GPU.**
  The probe asks for 8192 MiB. On v1.18.2 a Linux aarch64 host with no NVIDIA GPU failed that way,
  reached the CPU emulation device with the same probe at 1024 MiB, and failed the same way on a
  plain `machine run --mem 8192` with no `--cuda` at all.
- **`--cuda` and `--gpu` are different features.** `--cuda` is compute over vsock; `--gpu` is
  Vulkan over virtio-gpu, which reached a Venus device on macOS arm64 on v1.18.2 and is covered by
  `docs/gpu.md` in the repository. On Windows, on v1.14.6 and v1.22.2, `--gpu` boots and the guest
  has no GPU device; nothing reports that the flag was dropped (`references/windows.md`).

## Security defaults, and why they are the defaults

- **The guest never gets the device, and that is the isolation.** No `/dev/nvidia*` is passed
  through, so a workload in the machine cannot reach the driver directly, reprogram it, or see
  another VM's device state through it. What it gets is a forwarded API surface.
- **What that surface exposes is still real.** A remoted CUDA call runs against the host's driver
  and the host's memory allocator, so treat a `--cuda` machine as having a channel to a privileged
  host component. The VM boundary is what makes that acceptable; it is not zero authority.
- **Nothing here needs root or a container toolkit on the host.** If a procedure asks you to
  install a device plugin or run the CLI as root to get CUDA working, it is not this procedure.
- **The scripts wrap the public CLI only**, mount only this packet's own `scripts/` directory
  read-only into the guest, and cleanup deletes only names it recorded under the `smolskill-`
  prefix.

## Platform arms

- **Linux x86_64 with an NVIDIA GPU**: **verified on an A10 on v1.14.6** (driver 580.105.08,
  kernel 6.8.0-1046-nvidia), preflight through cleanup, with the probe run against two glibc
  images.
- **Windows x86_64 with an NVIDIA GPU**: **verified on an RTX 4050 on v1.22.2**, on 2026-10-03,
  and on v1.14.6 on 2026-09-11 (driver 32.0.15.6626), including the device name and a 1 MiB device round trip.
  `references/windows.md`.
- **macOS arm64 and Intel**: **not applicable.** macOS has no CUDA driver, so `--cuda` has nothing
  to reach. The preflight says so rather than letting a run time out.
- **Linux aarch64**: no NVIDIA hardware on the host tested. The preflight and the probe
  against the CPU emulation device were run on v1.18.2. On v1.22.2 the probe timed out on that
  host's memory before reaching the device.
- **Multi-GPU, branches of a `--cuda` machine, machines restored from its checkpoint, and a
  training or inference workload**: not run anywhere.

## Eval prompts, and what they produced

**1. "Run a CUDA workload in a smolvm machine and prove it reached the GPU." (re-run on v1.14.6
on the A10)**

`cuda-probe.py`'s output is the block under step 2 above, from this run.

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

**3. "Can this machine run CUDA?"**

On the A10 on v1.14.6, where the answer is yes:

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

macOS 27.0.1 arm64 on v1.22.2:

```
platform=darwin-aarch64
gpu_present=no
unsupported=cuda
note=macOS has no CUDA driver, so --cuda has nothing to reach here.
result=blocked
```

Lima `linux-kvm`, Ubuntu 24.04 aarch64, on v1.22.2:

```
platform=linux-aarch64
accel_access=ok
gpu_present=no
note=no nvidia-smi on this host; --cuda needs the driver library libcuda.so.1, which host_libcuda reports
host_libcuda=0
note=libcuda.so.1 is not in this host's loader cache; --cuda loads it on the host, and without it the guest reaches the CPU emulation device
result=blocked
```

## Re-verified on v1.22.2, the no-GPU path

Run 2026-10-03 PT against v1.22.2 from the published release, under an isolated `HOME` on macOS
27.0.1 arm64, twice, the second time from a fresh `HOME`. The preflight said
`gpu_present=no` and `result=blocked` without starting anything. The probe reached the emulation
device, `name = smolvm CPU emulation device` and `roundtrip first 16 bytes match: True`, and
reported `device_kind=cpu_emulation` and `result=cpu_emulation_not_gpu`. In the second pass Docker
Hub refused the default image with `TOOMANYREQUESTS`, the anonymous pull limit, and the probe passed
on `scripts/run-cuda-probe.sh mirror.gcr.io/library/python:3.12-slim`, the same image from a
mirror. A probe that reaches no device now says `device_kind=none`; earlier versions of the script
said `gpu`.

On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the probe's 8192 MiB guest timed out on a host that
booted 2048 MiB and no more on 2026-10-03, and the script named that cause first. Linux aarch64 was
last verified on v1.18.2, where the probe at `--mem 1024` reached the emulation device with the
same lines as macOS.

## Re-verified on v1.14.6

Run 2026-09-11 PT against v1.14.6 from the published release, installed into an isolated data root
on an **NVIDIA A10** cloud instance: 30 vCPU Intel Xeon Platinum 8358, 222 GiB memory, kernel
6.8.0-1046-nvidia, driver 580.105.08, 23028 MiB of device memory.

**The GPU path ran end to end on this release.** preflight, probe, all three eval prompts and
cleanup were executed in the packet's own order:

```
preflight            result=ready, gpu_present=yes, gpu=NVIDIA A10, 580.105.08, host_libcuda=1
probe, default image device_named=ok, data_roundtrip=ok, result=cuda_ok
probe, second image  device_named=ok, data_roundtrip=ok, result=cuda_ok
cleanup --purge      machines=clean, vm_processes=none
```

The probe was run against **two** glibc images, `python:3.12-slim` and `python:3.12-bookworm`, and
both reported `name = NVIDIA A10` and `total MiB = 22587`, and the first 16 bytes of the 1 MiB round
trip came back as sent.

**The host is untouched by `--cuda`, and that is now measured rather than quoted.** After these
runs `nvidia-smi` reported `NVIDIA A10, 580.105.08, 23028 MiB, 0 MiB` used, a whole-filesystem
sweep for `*smolvm*` outside the install prefix and the data root returned nothing, and the eight
NVIDIA kernel modules were still loaded.

**The KVM precondition in the traps reproduced on this instance**: a fresh instance has
`/dev/kvm` as `root:kvm` with the login user outside the group, so the user could not open it until
the group was granted; the preflight, run after that, reported `accel_access=ok`.

## What was not run

- **The preflight and the cleanup on Windows.** `scripts/*.sh` are bash and do not run
  there, so the Windows runs issued the probe and the eval prompts by hand.
- **`--cuda` with a CUDA base image** (`nvidia/cuda:...`), and the `apt-get install -y python3`
  those images need. Both probe runs used a Python image, which is what the packet recommends.
- **The `sg kvm -c` single-command remedy.** The state it addresses, a user who cannot open
  `/dev/kvm`, did reproduce on a fresh instance; the fix applied was a group change and a new
  login session.

Not run on any platform or release:

- **Branches and restores of a `--cuda` machine.** The docs site's `introduction/concepts/gpu.md`
  (smolmachines.com/docs) gives this as a reason for the remoting design, and a restored CUDA
  machine has its own shorter 10 s ready timeout.
- **Multi-GPU**, and contention between two machines sharing one device.
- **A training or inference workload.** The furthest run is the vector add on Windows; the rest
  are driver-API assertions, and say nothing about how much of the CUDA API surface is
  implemented.

## Related packets

- `install` for the KVM group precondition, which a fresh GPU instance fails.
- `teardown` for the cleanup script. CUDA images are large enough that `machine prune` is worth it.
