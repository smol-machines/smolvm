<p align="center">
  <img src="assets/logo.png" alt="smol machines" width="80">
</p>

<p align="center">
  <a href="https://discord.gg/E5r8rEWY9J"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/smol-machines/smolvm/releases"><img src="https://img.shields.io/github/v/release/smol-machines/smolvm?label=Release" alt="Release"></a>
  <a href="https://github.com/smol-machines/smolvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://www.npmjs.com/package/smolmachines"><img src="https://img.shields.io/npm/v/smolmachines?label=npm&logo=npm" alt="npm"></a>
  <a href="https://pypi.org/project/smolmachines/"><img src="https://img.shields.io/pypi/v/smolmachines?label=PyPI&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://crates.io/crates/smolmachines"><img src="https://img.shields.io/crates/v/smolmachines?label=crates.io&logo=rust" alt="crates.io"></a>
</p>

smolvm
======

**Branchable microVMs for AI agents.**
Embed them in your app, ship them as a file, and run them free on your own machine.

Install
-------

```bash
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows: unzip the `windows-x86_64` [release](https://github.com/smol-machines/smolvm/releases) and run `smolvm.exe` (needs the [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)). Coding agents: run `smolvm --help` after installing to discover every command.

Quick Start
-----------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

Local
-----

Real VMs with their own kernel, free on your laptop or your own servers. They boot in under a second, and memory is elastic, so the host only commits what the guest uses. Machines persist across restarts, and any OCI image works, including ones you build locally.

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

Declare a machine in a [Smolfile](docs/smolfile.md): image, resources, ports, mounts and network policy in one checked-in file.

Embeddable
----------

Drive machines from your own code with one `Machine` API. The SDKs run in your process with no daemon, locally or on [smol cloud](https://smolmachines.com).

```bash
npm install smolmachines     # Node / TypeScript
pip install smolmachines     # Python
cargo add smolmachines       # Rust
```

Source and docs: [smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

Branchable
----------

Save a running machine mid-execution, rewind it, or branch it into copies that keep running from the same point. Checkpoints capture RAM, CPU state and disks; branches are copy-on-write children of a live machine.

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

Rewind to an earlier generation with `--from <checkpoint> --at ~N` (see `machine checkpoint-log`), and stop without losing execution with [pause and resume](docs/pause-resume.md). More in [Branching](docs/branching.md) and [incremental checkpoints](docs/incremental-checkpoints.md).

Portable
--------

Pack a machine, however you set it up, into a single `.smolmachine` file. Push it to any OCI registry, or run it as a self-contained executable that boots in under 200 ms with nothing to install.

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

Checkpoints are portable too: restore one on another host or on smol cloud.

Safe
----

Each workload gets a hardware-isolated VM with its own kernel. Networking is off by default, egress can be limited to named hosts, and code can use a credential without ever reading it.

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

See [credential substitution](docs/credential-substitution.md) and the [security model](docs/security-model.md).

How It Works
------------

Each workload runs in a hardware-virtualized VM with its own guest kernel on [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS), KVM (Linux), or the [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (Windows). [libkrun](https://github.com/containers/libkrun) is the VMM and [libkrunfw](https://github.com/smol-machines/libkrunfw) supplies the guest kernel. Images use the [OCI](https://opencontainers.org/) format, so anything on Docker Hub, ghcr.io or another registry boots as a microVM, with no Docker daemon.

Defaults: 4 vCPUs, 8 GiB RAM. Memory is elastic via virtio balloon and idle vCPUs sleep in the hypervisor, so over-provisioning costs almost nothing. Override with `--cpus` and `--mem`.

Comparison
----------

|                     | smolvm | Containers | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------------|--------|------|-------------|------|
| Workload boundary   | VM + guest kernel | Namespace + shared kernel | Namespace inside shared VM | VM + guest kernel | VM + guest kernel | VM per container |
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
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform (WHP) enabled |

Windows does not yet support branching, checkpoints or GPU acceleration. See [known limitations](docs/limitations.md).

More
----

* [Kubernetes](docs/kubernetes.md): run pods as microVMs through a `RuntimeClass`.
* [GPU and CUDA](docs/gpu.md): Vulkan via virtio-gpu / Venus, and CUDA API remoting.
* [Examples](examples/): python, node, docker-in-vm, local-llm, headless-browser, doom.
* [Development](docs/DEVELOPMENT.md) · User docs at [smolmachines.com/docs](https://smolmachines.com/docs/), written in [smol-machines/docs](https://github.com/smol-machines/docs) (corrections welcome there; runtime bugs stay here).

[Apache-2.0](LICENSE) · made by [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
