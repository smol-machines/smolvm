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

Ship and run software with isolation by default. Sub-second cold start. No dependency management.

VMs that feel like a CLI tool. Boot in under 200ms, configure with a Smolfile, ship as a single executable. No daemon, no YAML, no cloud account.

Install
-------

```bash
curl -sSL https://smolmachines.com/install.sh | bash
```

Or download from [GitHub Releases](https://github.com/smol-machines/smolvm/releases).

Quick Start
-----------

```bash
# run a command in an ephemeral VM (cleaned up after exit)
smolvm machine run --net --image alpine -- echo "hello from a microVM"

# interactive shell
smolvm machine run --net -it --image alpine
```

Use This For
------------

**Sandbox untrusted code** — run untrusted programs in a hardware-isolated VM. Host filesystem, network, and credentials are separated by a hypervisor boundary.

```bash
smolvm machine run --image alpine -- sh -c "pip install sketchy-package"
# runs in its own kernel — can't touch your host filesystem or network

# lock down egress — only allow specific hosts
smolvm machine run --allow-host registry.npmjs.org --image node:20-alpine -- npm install
# npm install works, but malicious postinstall scripts can't phone home
```

**Pack into portable executables** — turn any workload into a self-contained binary.

```bash
smolvm pack create --image python:3.12-alpine -o ./my-app
./my-app run -- python3 -c "print('runs anywhere — no dependencies')"
```

**Persistent machines for development** — create, stop, start. Installed packages survive restarts.

```bash
smolvm machine create --net myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add sl
smolvm machine exec --name myvm -it -- /bin/sh
# try: sl, ls, uname -a — type 'exit' to leave
smolvm machine stop --name myvm
```

**Use git and SSH without exposing keys** — forward your host SSH agent into the VM. Private keys never enter the guest — the hypervisor enforces this. Requires an SSH agent running on your host (`ssh-add -l` to check).

```bash
smolvm machine run --ssh-agent --net --image alpine -- ssh-add -l
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
smolvm machine create myvm -s Smolfile
smolvm machine start --name myvm
```

More examples: [python](https://github.com/smol-machines/smolvm/tree/main/examples/python-app) · [node](https://github.com/smol-machines/smolvm/tree/main/examples/node-app) · [doom](https://github.com/smol-machines/smolvm/tree/main/examples/doom-web)

How It Works
------------

Each workload gets real hardware isolation — its own kernel on [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS) or KVM (Linux). [libkrun](https://github.com/containers/libkrun) VMM with custom kernel: [libkrunfw](https://github.com/smol-machines/libkrunfw). Pack it into a `.smolmachine` and it runs anywhere the host architecture matches, with zero dependencies.

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

* Network is opt-in (`--net` on `machine create`). The default machine has networking enabled. TCP/UDP only, no ICMP.
* Volume mounts: directories only (no single files).
* macOS: binary must be signed with Hypervisor.framework entitlements.
* `--ssh-agent` requires an SSH agent running on the host (`SSH_AUTH_SOCK` must be set).

Development
-----------

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

> Alpha — APIs may change.

[Apache-2.0](LICENSE) · made by [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
