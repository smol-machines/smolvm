# CUDA traps

## A zero exit code proves nothing on a remoted API

**This is the trap the whole packet is shaped around.** CUDA in smolvm is remoted, not passed
through: the guest gets no NVIDIA driver and no `/dev/nvidia*`, and a compatibility `libcuda.so.1`
forwards driver calls over vsock to a host daemon that owns the device. A program can therefore
start, link against `libcuda.so.1`, and exit zero without a GPU ever being reached.

Assert a **device name** and a **computed or copied result**. `scripts/cuda-probe.py` asserts both:
`cuDeviceGetName` returning a real name, and a 1 MiB host to device to host round trip whose first
16 bytes come back as sent.

## `nvidia-smi` is absent inside a `--cuda` guest, and that is correct

So is `/dev/nvidia*`. Both are the documented remoting design, not a fault, and neither is a useful
check. Use the driver API.

## Use a glibc image, and load the shim by absolute path

The injected shim is glibc, so an Alpine (musl) guest cannot load it. `python:3.12-slim` is small
and already has Python.

Load it as `/opt/smolvm-cuda/libcuda.so.1` rather than by soname: relying on the loader path picks
up whatever the image happens to carry, and the shim is at a fixed location.

**CUDA base images do not ship `python3`**, so `nvidia/cuda:...-base-...` needs
`apt-get install -y python3` in the guest first, or a `-devel` image. That is a reason to prefer a
small glibc image over a CUDA one for a probe.

## A fresh GPU cloud instance does not have KVM access for your user

`/dev/kvm` is `crw-rw---- root:kvm` and your account is not in the `kvm` group. The installer warns
and continues, so the install succeeds and the first VM fails. Apply the group without logging out:

```bash
sudo usermod -aG kvm "$USER"
sg kvm -c 'smolvm machine run --mem 2048 --net --image alpine -- echo OK'
```

## "agent did not become ready within 30 seconds" with `--cuda` was the guest's size, not the GPU

Observed on Ubuntu 24.04 aarch64 on 2026-09-07, running `machine run --cuda` on a host with no
NVIDIA hardware:

```
Starting ephemeral machine (vm-5d98e4be)...
Error: agent operation failed: start machine: agent operation failed: wait for ready:
agent did not become ready within 30 seconds
```

**Re-measured on v1.18.2, 2026-09-24, and the missing GPU was not the cause.** On the same kind of
host, Lima `linux-kvm` with no NVIDIA hardware, `scripts/run-cuda-probe.sh` at its `--mem 8192`
failed with the message above; the same probe at `--mem 1024` reached `smolvm CPU emulation
device` and returned `result=cpu_emulation_not_gpu`; and `machine run --mem 8192 --net --image
alpine` with no `--cuda` failed with the same message. That host booted 2048 MiB and not 2560 on
2026-09-24. So the timeout is the guest's size on that host, and a host that cannot load the driver
library answers `--cuda` with the emulation device instead.

## Large CUDA images may not pull

`nvidia/cuda:12.4.1-base-ubuntu22.04` failed after 582 s with `crane blob failed ... unexpected
EOF` on the Windows host's network. That is a transfer failure, not a CUDA one, but it is another
reason to prefer a small image.

## Memory: give the machine real headroom

The Linux GPU runs used `--mem 8192`, and the Windows probe line in `references/windows.md` uses
`--mem 6144`. On a small host, see the ready-timeout trap in the `install` packet: the 30 s limit is
a hard-coded constant and no flag raises it for `machine run` or `machine start`.

## `--cuda` changes nothing on the host

The remoting shim is injected at `/opt/smolvm-cuda` **inside the guest only**, and no host NVIDIA
state is touched. Verified after a series of CUDA runs plus a Kubernetes install and teardown on
the same host: `nvidia-smi` still reported the device, and a whole-filesystem sweep for
`*smolvm*` came back empty.

## `--cuda` and `--gpu` are different features

`--cuda` is compute over vsock. `--gpu` is Vulkan graphics over virtio-gpu; on the hosts tested
through v1.16.1 the host renderer reported the Venus capset at version 0, and on v1.18.2 on macOS
arm64 a guest reached `Virtio-GPU Venus (Apple M4)`. `docs/gpu.md` in the repository covers it. They share nothing
but the word GPU. On Windows, on v1.14.6 and v1.22.2, `--gpu` boots and the guest has no GPU
device; nothing reports that the flag was dropped.
