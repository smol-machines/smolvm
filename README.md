# smolVM

Run microVMs locally to sandbox workloads.

> **Alpha** - APIs can change, there may be bugs. [Report issues](https://github.com/smol-machines/smolvm/issues)

## install + usage

```bash
# install (macOS only, Linux coming soon)
curl -sSL https://smolmachines.com/install.sh | bash

# uninstall
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall

# sandbox - ephemeral isolated environments
smolvm sandbox run alpine:latest -- echo "hello"
smolvm sandbox run -v /tmp:/workspace alpine:latest -- ls /workspace

smolvm sandbox run python:3.12-alpine -- python -V

# microvm - persistent linux VMs
smolvm microvm start
smolvm microvm exec -- echo "hello"
smolvm microvm stop

# pack - portable executable container-in-VM
smolvm pack alpine:latest -o ./my-sandbox
./my-sandbox echo "hello"

smolvm pack python:3.12-alpine -o ./my-pythonvm
./my-pythonvm python3 -c "import sys; print(sys.version)"
```

## about

microVMs are lightweight VMs - security and isolation of VMs with the speed of containers.

They power AWS Lambda and Fly.io, but are inaccessible to average developers due to setup complexity.

smolVM makes microVMs easy: <250ms boot, works on macOS and Linux, single binary distribution.

## use this for

- run coding agents locally and safely
- run microVMs locally on macOS and Linux with minimal setup
- run containers within microvm for improved isolation
- distribute self-contained sandboxed applications

## comparison

|                     | Containers | QEMU | Firecracker | Kata | smolvm |
|---------------------|------------|------|-------------|------|--------|
| kernel isolation    | shared ¹   | separate | separate | separate | separate |
| boot time           | ~100ms ²   | ~15-30s ³ | <125ms ⁴ | ~500ms ⁵ | <250ms |
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

- **Container rootfs writes**: Writes to container filesystem (`/tmp`, `/home`, etc.) fail due to a libkrun TSI bug with overlayfs. **Writes to mounted volumes work**.
- **Network: TCP/UDP only**: ICMP (`ping`) and raw sockets do not work. Use `curl`, `wget` for connectivity.
- **Volume mounts**: Directories only (no single files)
- **macOS**: Binary must be signed with Hypervisor.framework entitlements

**File writes for coding agents:**
```bash
# Works: top-level mount path
smolvm sandbox run -v /tmp:/workspace alpine:latest -- sh -c "echo 'hello' > /workspace/out.txt"

# Fails: nested mount path or container rootfs
smolvm sandbox run -v /tmp:/mnt/data alpine:latest -- sh -c "echo 'hello' > /mnt/data/out.txt"
```

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
