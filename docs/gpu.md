# GPU Acceleration

smolvm exposes the host GPU to guests via **virtio-gpu / Venus** (Vulkan-over-virtio). Guest workloads see a real Vulkan device; on Linux + Intel this renders as:

```
ANGLE (Intel, Vulkan 1.4 (Virtio-GPU Venus (Intel(R) UHD Graphics ...)), venus)
```

## Host requirements

**macOS**: virglrenderer and MoltenVK are bundled in the smolvm distribution. No extra installs needed.

**Linux**: virglrenderer and a host Vulkan driver must be installed from the system package manager:

| Distro | Packages |
|--------|----------|
| Alpine | `apk add virglrenderer mesa-vulkan-intel` (or `mesa-vulkan-ati` for AMD) |
| Debian/Ubuntu | `apt install virglrenderer0 mesa-vulkan-drivers` |
| Nix / NixOS | the flake does not put virglrenderer on the loader path; export `LD_LIBRARY_PATH` with the nixpkgs `virglrenderer` and `libepoxy` lib dirs (and `/run/opengl-driver/lib` on NixOS), see the [GPU page](https://smolmachines.com/docs/introduction/concepts/gpu) |

> virglrenderer depends on libEGL and libdrm from the host GPU driver stack. These are hardware-specific and cannot be bundled. Any GPU-capable Linux host will already have them installed via its GPU driver.

## Usage

```bash
# CLI
smolvm machine run --net --gpu --image alpine -- sh -c '
  apk add --no-cache mesa-vulkan-virtio vulkan-loader vulkan-tools
  vulkaninfo --summary | grep deviceName
'
# → deviceName = Virtio-GPU Venus (Apple M1 Pro)

# Smolfile
# gpu = true
# gpu_vram = 2048   # MiB, default 4096
```

Nothing needs to set `VK_ICD_FILENAMES`: the guest's Mesa installs an ICD
manifest the Vulkan loader finds on its own, and on a glibc image smolvm also
bind-mounts its own Venus driver and points the loader at it. Set the variable
only to override that choice, and note the manifest name carries the
architecture (`virtio_icd.x86_64.json` / `virtio_icd.aarch64.json`), so a
hardcoded path is wrong on the other arch.

## Headless browser example

See [`examples/headless-browser/`](../examples/headless-browser/) for a working Chromium setup using ANGLE + Venus for hardware-accelerated WebGL inside a headless VM.

## CUDA API Remoting

`--gpu` and `--cuda` provide different interfaces. `--gpu` exposes Vulkan through virtio-gpu / Venus; it does not provide CUDA. `--cuda` enables CUDA API remoting: driverless guest shims forward CUDA calls over vsock to a host process, which executes them through the host's NVIDIA driver.

CUDA remoting requires an NVIDIA GPU and a working NVIDIA driver on the host. It is not GPU passthrough: the guest receives neither the physical device nor an NVIDIA driver.

Fork-heavy Linux hosts should use a kernel containing upstream KVM fix
[`916b7f4`](https://github.com/torvalds/linux/commit/916b7f42b3b3b539a71c204a9b49fdc4ca92cd82).
Affected kernels can intermittently report `ENOMEM` on the first `KVM_RUN` even
with ample host memory; smolvm reduces exposure and replaces a failed worker,
but the kernel update is the definitive fix.

The VM boundary still isolates the workload's CPU, memory, and filesystem. GPU access is mediated by host processes and the shared host GPU, so GPU isolation remains process-level rather than a hardware or VM boundary. Do not treat CUDA remoting as a hardened multi-tenant GPU isolation boundary.

See [GPU access by API remoting: how a driverless microVM runs CUDA](https://smolmachines.com/engineering/gpu-over-vsock) for the design, trade-offs, and comparison with passthrough.
