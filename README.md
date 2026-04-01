<p align="center">
  <img src="assets/logo.png" alt="smol machines" width="80">
</p>

<p align="center">
  <a href="https://discord.gg/qhQ7FHZ2zd"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/smol-machines/smolvm/releases"><img src="https://img.shields.io/github/v/release/smol-machines/smolvm?label=Release" alt="Release"></a>
  <a href="https://github.com/smol-machines/smolvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

smolvm
======

A local tool to build and run portable, lightweight, self-contained virtual machines.

Each workload runs in its own Linux microVM with a separate kernel. The host
filesystem, network, and credentials are isolated unless explicitly shared.

Install
-------

```bash
curl -sSL https://smolmachines.com/install.sh | bash
```

Or download from [GitHub Releases](https://github.com/smol-machines/smolvm/releases).

Quick Start
-----------

```bash
# Run a command in an ephemeral VM (cleaned up after exit)
smolvm machine run --image alpine -- echo "hello from a microVM"

# Interactive shell
smolvm machine run -it --image alpine

# Persistent machine (survives stop/start)
smolvm machine create --net myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add sl
smolvm machine exec --name myvm -it -- /bin/sh
smolvm machine stop --name myvm

# Pack into a portable executable
smolvm pack create --image python:3.12-alpine -o ./my-pythonvm
./my-pythonvm python3 -c "print('hello from a packed VM')"
```

How It Works
------------

[libkrun](https://github.com/containers/libkrun) VMM with
[Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS)
or KVM (Linux). No daemon — the VMM is a library linked into the binary.
Custom kernel: [libkrunfw](https://github.com/smol-machines/libkrunfw).

* <200ms boot
* Single binary, no runtime dependencies
* Runs OCI container images inside microVMs
* Packs workloads into portable `.smolmachine` executables
* Embeddable via Node.js and Python SDKs

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

* Network is opt-in (`--net` on `machine create`). The default machine has networking enabled. TCP/UDP only, no ICMP.
* Volume mounts: directories only (no single files).
* macOS: binary must be signed with Hypervisor.framework entitlements.

Development
-----------

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

> Alpha — APIs may change.

License
-------

Apache-2.0
