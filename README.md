<p align="center">
  <img src="assets/logo.png" alt="smol machines" width="80">
</p>

<p align="center">
  <a href="https://discord.gg/E5r8rEWY9J"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/smol-machines/smolvm/releases"><img src="https://img.shields.io/github/v/release/smol-machines/smolvm?label=Release" alt="Release"></a>
  <a href="https://github.com/smol-machines/smolvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

smolvm
======

Ship and run software with isolation by default.

This is a CLI tool that lets you:
1. Manage and run custom Linux virtual machines locally with: sub-second cold start, cross-platform (macOS, Linux), elastic memory usage.
2. Pack a stateful virtual machine into a single file (.smolmachine) to rehydrate on any supported platform.

Install
-------

```bash
# install (macOS + Linux)
curl -sSL https://smolmachines.com/install.sh | bash

# for coding agents — install + discover all commands
curl -sSL https://smolmachines.com/install.sh | bash && smolvm --help
```

Or download from [GitHub Releases](https://github.com/smol-machines/smolvm/releases), and place it into `~/.local/share/`.

Quick Start
-----------

```bash
# run a command in an ephemeral VM (cleaned up after exit)
smolvm machine run --net --image alpine -- sh -c "echo 'Hello world from a microVM' && uname -a"

# interactive shell
smolvm machine run --net -it --image alpine -- /bin/sh
# inside the VM: apk add sl && sl && exit
```

Use This For
------------

**Sandbox untrusted code** — run untrusted programs in a hardware-isolated VM. Host filesystem, network, and credentials are separated by a hypervisor boundary.

```bash
# network is off by default — untrusted code can't phone home
smolvm machine run --image alpine -- nslookup example.com
# fails — no network access

# lock down egress — only allow specific hosts
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -q -O /dev/null https://registry.npmjs.org
# works — allowed host

smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -q -O /dev/null https://google.com
# fails — not in allow list
```

**Pack into portable executables** — turn any workload into a self-contained binary. All dependencies are pre-baked — no install step, no runtime downloads, boots in <200ms.

```bash
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
# Python 3.12.x — isolated, no pyenv/venv/conda needed
```

**Persistent machines for development** — create, stop, start. Installed packages survive restarts.

```bash
smolvm machine create --net --name myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add sl
smolvm machine exec --name myvm -it -- /bin/sh
# inside: sl, ls, uname -a — type 'exit' to leave
smolvm machine stop --name myvm
```

**Use git and SSH without exposing keys** — forward your host SSH agent into the VM. Private keys never enter the guest — the hypervisor enforces this. Requires an SSH agent running on your host (`ssh-add -l` to check).

```bash
smolvm machine run --ssh-agent --net --image alpine -- sh -c "apk add -q openssh-client && ssh-add -l"
# lists your host keys, but they can't be extracted from inside the VM

smolvm machine exec --name myvm -- git clone git@github.com:org/private-repo.git
```

**Declare environments with a Smolfile** — reproducible VM config in a simple TOML file.

```toml
image = "python:3.12-alpine"
net = true

[network]
allow_hosts = ["api.stripe.com", "db.example.com"]

[dev]
init = ["pip install -r requirements.txt"]
volumes = ["./src:/app"]

[auth]
ssh_agent = true
```

```bash
smolvm machine create --name myvm -s Smolfile
smolvm machine start --name myvm
```

More examples: [python](https://github.com/smol-machines/smolvm/tree/main/examples/python-app) · [node](https://github.com/smol-machines/smolvm/tree/main/examples/node-app) · [doom](https://github.com/smol-machines/smolvm/tree/main/examples/doom-web)

How It Works
------------

Each workload gets real hardware isolation — its own kernel on [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS) or KVM (Linux). [libkrun](https://github.com/containers/libkrun) VMM with custom kernel: [libkrunfw](https://github.com/smol-machines/libkrunfw). Pack it into a `.smolmachine` and it runs anywhere the host architecture matches, with zero dependencies.

Images use the [OCI](https://opencontainers.org/) format — the same open standard Docker uses. Any image on Docker Hub, ghcr.io, or other OCI registries can be pulled and booted as a microVM. No Docker daemon required.

Defaults: 4 vCPUs, 8 GiB RAM. Memory is elastic via virtio balloon — the host only commits what the guest actually uses and reclaims the rest automatically. vCPU threads sleep in the hypervisor when idle, so over-provisioning has near-zero cost. Override with `--cpus` and `--mem`.

Comparison
----------

|                     | smolvm | Containers | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------------|--------|------|-------------|------|
| Isolation           | VM per workload | Namespace (shared kernel) | Namespace (1 VM) | Separate VM | Separate VM | VM per container |
| Boot time           | <200ms | ~100ms | ~seconds | ~15-30s | <125ms | ~500ms |
| Architecture        | Library (libkrun) | Daemon | Daemon (in VM) | Process | Process | Runtime stack |
| Per-workload VMs    | Yes | No | No (shared) | Yes | Yes | Yes |
| macOS native        | Yes | Via Docker VM | Yes (krunkit) | Yes | No | No |
| Embeddable SDK      | Yes | No | No | No | No | No |
| Portable artifacts  | `.smolmachine` | Images (need daemon) | No | No | No | No |

Platform Support
----------------

| Host | Guest | Requirements |
|------|-------|-------------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | macOS 11+ (untested) |
| Linux x86_64 | x86_64 Linux | KVM (`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM (`/dev/kvm`) |

Known Limitations
-----------------

* Network is opt-in (`--net` on `machine create`). TCP/UDP only, no ICMP.
* Volume mounts: directories only (no single files). Mounting at `/workspace` (`-v /host/dir:/workspace`) takes priority over the default storage-disk workspace — your host directory is used instead.
* macOS: binary must be signed with Hypervisor.framework entitlements.
* `--ssh-agent` requires an SSH agent running on the host (`SSH_AUTH_SOCK` must be set).
* GPU acceleration requires libkrun built with `GPU=1` and virglrenderer + a Vulkan driver on the host (see [GPU Acceleration](#gpu-acceleration) below).

GPU Acceleration
----------------

smolvm exposes the host GPU to guests via **virtio-gpu / Venus** (Vulkan-over-virtio). Guest workloads see a real Vulkan device; on Linux + Intel this renders as:

```
ANGLE (Intel, Vulkan 1.4 (Virtio-GPU Venus (Intel(R) UHD Graphics ...)), venus)
```

### Host requirements

**macOS** — virglrenderer and MoltenVK are bundled in the smolvm distribution. No extra installs needed.

**Linux** — virglrenderer and a host Vulkan driver must be installed from the system package manager:

| Distro | Packages |
|--------|----------|
| Alpine | `apk add virglrenderer mesa-vulkan-intel` (or `mesa-vulkan-ati` for AMD) |
| Debian/Ubuntu | `apt install virglrenderer0 mesa-vulkan-drivers` |

> virglrenderer depends on libEGL and libdrm from the host GPU driver stack — these are hardware-specific and cannot be bundled. Any GPU-capable Linux host will already have them installed via its GPU driver.

### Usage

```bash
# CLI
smolvm machine run --gpu --image alpine -- vulkaninfo --summary

# Smolfile
# gpu = true
# gpu_vram = 2048   # MiB, default 4096
```

The guest Vulkan loader must be pointed at the virtio ICD:

```bash
export VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/virtio_icd.x86_64.json
```

### Headless browser example

See [`examples/headless-browser/`](examples/headless-browser/) for a working Chromium setup using ANGLE + Venus for hardware-accelerated WebGL inside a headless VM.

Development
-----------

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

[Apache-2.0](LICENSE) · made by [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
