# GPU Acceleration

smolvm exposes the host GPU to guests via **virtio-gpu / Venus** (Vulkan-over-virtio). Enable it with `--gpu` on `machine run` or `machine create`, or `gpu = true` in a Smolfile. Guest workloads see a real Vulkan device, which ANGLE can use as its WebGL and OpenGL ES backend; on Linux + Intel this renders as:

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

**An NVIDIA host needs virglrenderer 1.2.0 or newer.** Older render servers preload Vulkan in a way NVIDIA's driver rejects, so the guest's `vkCreateDevice` fails with `VK_ERROR_INITIALIZATION_FAILED`; 1.2.0 turns that preload off by default ([upstream MR 1557](https://gitlab.freedesktop.org/virgl/virglrenderer/-/merge_requests/1557)). Ubuntu 24.04 packages 1.0.0, so on such a host build 1.2.0 or newer from source, keeping `vulkan-preload=false`, or use a release that ships it ([#730](https://github.com/smol-machines/smolvm/issues/730)).

**Windows**: not available (WHP); `--gpu` has no effect there.

## Usage

```bash
# CLI
smolvm machine run --net --gpu --image alpine -- sh -c '
  apk add --no-cache mesa-vulkan-virtio vulkan-loader vulkan-tools
  vulkaninfo --summary | grep deviceName
'
# → deviceName = Virtio-GPU Venus (Apple M1 Pro)

# Persistent GPU machine
smolvm machine create --name browser --gpu --gpu-vram 2048
smolvm machine start --name browser
smolvm machine exec --name browser -- \
  chromium --headless=new --no-sandbox --use-gl=angle --use-angle=vulkan \
    --screenshot=/tmp/out.png --window-size=1280,800 https://example.com

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

CUDA remoting requires an NVIDIA GPU and a working NVIDIA driver on the host (`libcuda.so.1` and a loaded kernel module); no CUDA toolkit is required on the host or in the guest. Enable it with `--cuda` on `machine run` or `machine create`, or `cuda = true` in a Smolfile. It is not GPU passthrough: the guest receives neither the physical device nor an NVIDIA driver.

Guest programs reach the GPU through drop-in libraries the release's agent
rootfs bundles. With `--cuda` the guest agent bind-mounts them read-only at
`/opt/smolvm-cuda` in the workload container and appends that directory to
`LD_LIBRARY_PATH`, so `libcuda.so.1` resolves to the driver shim built from
[`crates/smolvm-cuda-shim`](../crates/smolvm-cuda-shim) and unmodified
Driver-API programs work with no code changes. The shim is glibc, so use a
glibc image.

Covered surface: init/device queries (name, attributes, uuid, total/free mem),
contexts (incl. the primary-context flow the CUDA runtime uses), module
load/unload (PTX, cubin, fatbin), mem alloc/free/HtoD/DtoH/DtoD/memset,
kernel launch (param sizes come from the host via `cuFuncGetParamInfo`,
CUDA 12.4+ drivers), streams, events, `cuGetProcAddress`. All work executes
synchronously host-side; `*Async` calls complete before returning (permitted
by the CUDA contract).

**The Runtime API goes through a second shim.** NVIDIA's own `libcudart`
bootstraps through a private driver interface (`cuGetExportTable`) that a
`libcuda` shim cannot provide, so
[`crates/smolvm-cudart-shim`](../crates/smolvm-cudart-shim) replaces `libcudart`
instead: it lowers each Runtime-API call to the public Driver API and remotes
that. The bundled copy sits in the same directory under the `libcudart`,
`libcublas`, `libcublasLt` and `libcudnn` sonames of CUDA 11, 12 and 13, and
is bind-mounted over those libraries where a pip wheel installed them under
`site-packages/nvidia/`, since programs such as PyTorch find them by RPATH
ahead of `LD_LIBRARY_PATH`. Set `SMOLVM_CUDA_SHIM_TRACE=1` to log which
driver entry points a program resolves through the shim.

Without an NVIDIA driver the host serves a CPU-emulation backend (test-only:
it knows the `vecadd` test kernel), so the transport stays testable anywhere.
The [gpu-cuda packet](../skills/gpu-cuda/README.md) has the procedure and what tells that
backend apart from a real GPU.

Fork-heavy Linux hosts should use a kernel containing upstream KVM fix
[`916b7f4`](https://github.com/torvalds/linux/commit/916b7f42b3b3b539a71c204a9b49fdc4ca92cd82).
Affected kernels can intermittently report `ENOMEM` on the first `KVM_RUN` even
with ample host memory; smolvm reduces exposure and replaces a failed worker,
but the kernel update is the definitive fix.

The VM boundary still isolates the workload's CPU, memory, and filesystem. GPU access is mediated by host processes and the shared host GPU, so GPU isolation remains process-level rather than a hardware or VM boundary. Do not treat CUDA remoting as a hardened multi-tenant GPU isolation boundary.

See [GPU access by API remoting: how a driverless microVM runs CUDA](https://smolmachines.com/engineering/gpu-over-vsock) for the design, trade-offs, and comparison with passthrough.
