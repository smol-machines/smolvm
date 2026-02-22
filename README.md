# smolVM

Run microVMs locally to sandbox workloads.

> **Alpha** - APIs can change, there may be bugs. [Report issues](https://github.com/smol-machines/smolvm/issues)

## install + usage

```bash
# install (macOS only, Linux coming soon)
curl -sSL https://smolmachines.com/install.sh | bash

# sandbox - ephemeral isolated environments
smolvm sandbox run --net alpine:latest -- echo "hello"
smolvm sandbox run --net -v /tmp:/workspace alpine:latest -- ls /workspace

smolvm sandbox run --net python:3.12-alpine -- python -V

# microvm - persistent linux VMs
smolvm microvm start
smolvm microvm exec -- apk add git  # changes persist across reboots
smolvm microvm exec -- echo "hello"
smolvm microvm exec -it -- /bin/sh   # interactive shell (exit with Ctrl+D)
smolvm microvm stop

# pack - build a portable, executable virtual machine.
smolvm pack alpine:latest -o ./my-sandbox        # creates ./my-sandbox + ./my-sandbox.smolmachine
smolvm pack alpine:latest -o ./my-sandbox --single-file  # single executable, no sidecar

./my-sandbox uname -a # this will return results of running sys info within the guest linux vm

smolvm pack python:3.12-alpine -o ./my-pythonvm
./my-pythonvm python3 -c "import sys; print(sys.version)"

# uninstall
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
```

## about

microVMs are lightweight VMs - security and isolation of VMs with the speed of containers.

They power AWS Lambda and Fly.io, but are inaccessible to average developers due to setup complexity.

smolVM makes microVMs easy: <200ms boot, works on macOS and Linux, single binary distribution.

## use this for

- run coding agents locally and safely
- run microVMs locally on macOS and Linux with minimal setup
- run containers within microvm for improved isolation
- distribute self-contained sandboxed applications

## demo: run OpenAI Codex in a sandbox

```bash
# create a persistent microVM with networking
smolvm microvm create codex-sandbox --net --cpus 2 --mem 1024
smolvm microvm start codex-sandbox

# install Node.js + Codex CLI
smolvm microvm exec --name codex-sandbox -- sh -c "apk add nodejs npm && npm i -g @openai/codex"

# login (pipe your API key)
smolvm microvm exec --name codex-sandbox -- sh -c "echo $OPENAI_API_KEY | codex login --with-api-key"

# run Codex interactively — fully isolated in a microVM
smolvm microvm exec --name codex-sandbox -it -- codex
```

## comparison

|                     | Containers | QEMU | Firecracker | Kata | smolvm |
|---------------------|------------|------|-------------|------|--------|
| kernel isolation    | shared ¹   | separate | separate | separate | separate |
| boot time           | ~100ms ²   | ~15-30s ³ | <125ms ⁴ | ~500ms ⁵ | <200ms |
| setup               | easy       | complex | complex | complex | easy |
| macOS               | via Docker | yes | no ⁶ | no ⁷ | yes |
| guest rootfs        | layered    | disk image | DIY ⁸ | bundled + DIY | bundled |
| embeddable          | no         | no | no | no | yes |
| distribution        | daemon+CLI ⁹ | multiple | binary+rootfs | runtime stack ¹⁰ | single binary |

<details>
<summary>References</summary>

1. [Container isolation](https://www.docker.com/blog/understanding-docker-container-escapes/)
2. [containerd benchmark](https://github.com/containerd/containerd/issues/4482)
3. [QEMU boot time](https://wiki.qemu.org/Features/TCG)
4. [Firecracker website](https://firecracker-microvm.github.io/)
5. [Kata boot time](https://github.com/kata-containers/kata-containers/issues/4292)
6. [Firecracker requires KVM](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
7. [Kata macOS support](https://github.com/kata-containers/kata-containers/issues/243)
8. [Firecracker rootfs setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md)
9. [Docker daemon docs](https://docs.docker.com/config/daemon/)
10. [Kata installation](https://github.com/kata-containers/kata-containers/blob/main/docs/install/README.md)

</details>

## how it works

[libkrun](https://github.com/containers/libkrun) VMM + Hypervisor.framework (macOS) / KVM (Linux) + crun container runtime.

## platform support

| host | guest | requirements |
|------|-------|--------------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | macOS 11+ (untested) |
| Linux x86_64 | x86_64 Linux | KVM (`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM (`/dev/kvm`) |

## known limitations

- **Network is opt-in**: Use `--net` to enable outbound network access (required for image pulls from registries). TCP/UDP only — ICMP (`ping`) and raw sockets do not work.
- **Volume mounts**: Directories only (no single files)
- **macOS**: Binary must be signed with Hypervisor.framework entitlements

## development

```bash
# build
./scripts/build-dist.sh

# run tests
./tests/run_all.sh
```

### troubleshooting tests

**Database lock errors** ("Database already open"):
```bash
pkill -f "smolvm serve"
pkill -f "smolvm-bin microvm start"
```

**Hung tests**: Check for stuck VM processes:
```bash
ps aux | grep smolvm
```

## license

Apache-2.0
