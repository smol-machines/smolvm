<p align="center">
  <img src="../../assets/logo.png" alt="smol machines" width="80">
</p>

<p align="center">
  <a href="https://discord.gg/E5r8rEWY9J"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/smol-machines/smolvm/releases"><img src="https://img.shields.io/github/v/release/smol-machines/smolvm?label=Release" alt="Release"></a>
  <a href="https://github.com/smol-machines/smolvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://www.npmjs.com/package/smolmachines"><img src="https://img.shields.io/npm/v/smolmachines?label=npm&logo=npm" alt="npm"></a>
  <a href="https://pypi.org/project/smolmachines/"><img src="https://img.shields.io/pypi/v/smolmachines?label=PyPI&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://crates.io/crates/smolmachines"><img src="https://img.shields.io/crates/v/smolmachines?label=crates.io&logo=rust" alt="crates.io"></a>
</p>

<p align="center">
  <sub><a href="../../README.md">English</a> · <b>中文</b> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.ru.md">Русский</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a></sub>
</p>

smolvm
======

**为 AI 智能体打造、可分支的微型虚拟机。**
把轻量级虚拟机嵌入你的软件，用于可移植的开发环境和本地沙箱。

安装
----

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows：解压 `windows-x86_64` [发布包](https://github.com/smol-machines/smolvm/releases)，然后运行 `smolvm.exe`（需要启用 [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)）。编码智能体：安装后运行 `smolvm --help` 即可发现所有命令。

面向人类和智能体的文档都在 [`docs/`](../README.md) 中，每个任务一个文件夹：一个讲事实的 `README.md`，一个智能体可以照着执行的 `SKILL.md` 及其脚本，旁边是每个功能的参考页面。

快速开始
--------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

本地
----

真正的虚拟机，拥有自己的内核，在你的笔记本或自己的服务器上免费运行。启动不到一秒，内存是弹性的，宿主机只提交客户机实际使用的部分。机器在重启后依然保留，任何 OCI 镜像都能用，包括你在本地构建的镜像。

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

用 [Smolfile](../smolfile.md) 声明一台机器：镜像、资源、端口、挂载和网络策略，都写在一个纳入版本控制的文件里。

可嵌入
------

用同一个 `Machine` API，从你自己的代码里驱动机器。SDK 在你的进程内运行，无需守护进程，可在本地或 [smol cloud](https://smolmachines.com) 上使用。

```bash
npm install smolmachines     # Node / TypeScript
pip install smolmachines     # Python
cargo add smolmachines       # Rust
```

```ts
import { Machine } from 'smolmachines';

const m = await Machine.create({ image: 'python:3.12-alpine', network: true });
const r = await m.exec(['python3', '-c', 'print(2 ** 10)']);
console.log(r.stdout); // 1024
await m.delete();
```

源码与文档：[smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

可分支
------

在运行中途保存一台机器，把它倒回，或者把它分支成多个从同一时刻继续运行的副本。检查点会保存内存、CPU 状态和磁盘；分支是运行中机器的写时复制（copy-on-write）子机。

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

用 `--from <checkpoint> --at '~N'` 倒回到更早的一代（参见 `machine checkpoint-log`），用[暂停与恢复](../pause-resume.md)停下机器而不丢失执行状态。在 arm64 Mac 上创建的检查点可以在 arm64 Linux 上恢复，参见[把运行中的机器从 Mac 迁移到 Linux](../mac-to-linux.md)。更多内容见[分支](../branching.md)和[增量检查点](../incremental-checkpoints.md)。

可移植
------

无论你怎样配置一台机器，都可以把它打包成一个 `.smolmachine` 文件。推送到任意 OCI 镜像仓库，或者作为一个自包含的可执行文件运行：不到 200 毫秒即可启动，无需安装任何东西。

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

检查点同样可移植：可以在另一台主机或 smol cloud 上恢复。

安全
----

每个工作负载都运行在一台硬件隔离、拥有独立内核的虚拟机里。网络默认关闭，出站流量可以限制到指定主机，代码可以使用某个凭据而永远读不到它。

安全是共同的责任。smolvm 提供边界：每个工作负载一台独立的虚拟机和内核，除非你允许，否则什么都到达不了宿主机。由你决定什么可以跨越这条边界。你挂载的每个文件夹、开放的每个端口、允许的每个主机、转发的每个密钥或 SSH agent，都会成为工作负载可以使用的东西，所以只给不受信任的工作负载它真正需要的。

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

参见[凭据替换](../credential-substitution.md)和[安全模型](../security-model.md)。
用 `--allow-host-pattern '*.example.com'` 只允许子域名；`--allow-host example.com` 允许该域名本身及其子域名。`smolvm machine update` 可以添加（`--allow-host`、`--allow-host-pattern`、`--allow-cidr`）和移除（`--remove-allow-host`，按添加时的写法填写主机或模式；`--remove-allow-cidr`）条目，对以允许列表启动、正在运行的机器同样有效：新授权在下一次连接或查询时生效，移除某个主机时，它已解析出的地址也会一并移除。

工作原理
--------

每个工作负载都运行在一台硬件虚拟化的虚拟机里，拥有自己的客户机内核，底层是 [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)（macOS）、KVM（Linux）或 [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)（Windows）。[libkrun](https://github.com/containers/libkrun) 是虚拟机监视器（VMM），[libkrunfw](https://github.com/smol-machines/libkrunfw) 提供客户机内核。镜像使用 [OCI](https://opencontainers.org/) 格式，所以 Docker Hub、ghcr.io 或其他仓库里的任何镜像都能作为微型虚拟机启动，无需 Docker 守护进程。

默认：4 个 vCPU、8 GiB 内存。内存通过 virtio balloon 弹性伸缩，空闲的 vCPU 在虚拟机监视器中休眠，因此超额分配几乎没有成本。可用 `--cpus` 和 `--mem` 覆盖。

对比
----

|                     | smolvm | 容器 | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------|--------|------|-------------|------|
| 工作负载边界        | 虚拟机 + 客户机内核 | 命名空间 + 共享内核 | 共享虚拟机内的命名空间 | 虚拟机 + 客户机内核 | 虚拟机 + 客户机内核 | 每个容器一台虚拟机 |
| 启动时间            | 不到 200ms 即可就绪 | ~100ms | 数秒 | ~15-30s | <125ms | ~500ms |
| 架构                | 库（libkrun） | 守护进程 | 守护进程（在虚拟机中） | 进程 | 进程 | 运行时栈 |
| 每个工作负载一台虚拟机 | 是 | 否 | 否（共享） | 是 | 是 | 是 |
| macOS 原生          | 是 | 通过 Docker 虚拟机 | 是（krunkit） | 是 | 否 | 否 |
| 可嵌入 SDK          | 是 | 否 | 否 | 否 | 否 | 否 |
| 可移植制品          | `.smolmachine` | 镜像（需要守护进程） | 否 | 否 | 否 | 否 |

平台支持
--------

| 宿主机 | 客户机 | 要求 |
|--------|--------|------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | 未发布构建；未经测试 |
| Linux x86_64 | x86_64 Linux | KVM（`/dev/kvm`） |
| Linux aarch64 | aarch64 Linux | KVM（`/dev/kvm`） |
| Windows x86_64 | x86_64 Linux | 已启用 Windows Hypervisor Platform（WHP） |

Windows 支持可移植检查点、暂停/恢复，以及使用 `--freeze-source` 的分支。GPU 加速仍不可用；参见[已知限制](../limitations.md)。

更多
----

* [Kubernetes](../kubernetes.md)：通过 `RuntimeClass` 把 Pod 作为微型虚拟机运行。
* [GPU 与 CUDA](../gpu.md)：通过 virtio-gpu / Venus 使用 Vulkan，以及 CUDA API 远程调用。
* [示例](../../examples/)：python、node、docker-in-vm、local-llm、headless-browser、doom。
* [开发](../DEVELOPMENT.md) · 用户文档位于 [smolmachines.com/docs](https://smolmachines.com/docs/)，源文件在 [smol-machines/docs](https://github.com/smol-machines/docs)（欢迎在那里提交修正；运行时的问题请在本仓库提出）。

smolvm 是 [smol machines](https://smolmachines.com) 背后的开源运行时，与其他名为 SmolVM 的项目无关。

本译文可能落后于[英文原版](../../README.md)，如有出入，以英文版为准。

[Apache-2.0](../../LICENSE) · 作者 [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
