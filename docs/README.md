# smolvm documentation

The flat pages here, listed under [Reference pages](#reference-pages), are the reference for each
feature. A skill packet is a tested procedure for one task and links the
reference page it builds on. Each packet is a folder in [`skills/`](../skills/): a `README.md` with
the facts and why they hold, and a `SKILL.md` an agent can follow, with its own `scripts/` and
`references/`. The repository installs them as an agent plugin; see the top-level README.
Each packet's `SKILL.md` opens with the release and platforms it last ran on. No CI runs the packet scripts.

`llms.txt` lists every packet's `SKILL.md` for agents that read the tree directly.

## Start here

Find the task, then run its packet's first step: a read-only check that ends in `result=ready`
(`result=clean` for teardown) when this host can do the task. Call each script by its path under
`skills/`, from a working directory of your own, since the scripts write to the current directory. Each first step ran as written on v1.29.0 on
macOS arm64, where throwaway-machine's says `result=blocked`; its `SKILL.md` says why.

| Task | Packet | First step |
|---|---|---|
| Install smolvm and prove a VM boots | [install](../skills/install/SKILL.md) | `skills/install/scripts/preflight.sh` |
| Run code you do not trust, with no network | [throwaway-machine](../skills/throwaway-machine/SKILL.md) | `skills/throwaway-machine/scripts/preflight.sh --mounts 2 --ports 0` |
| Keep a machine you come back to | [dev-env](../skills/dev-env/SKILL.md) | `skills/dev-env/scripts/preflight.sh` |
| Give a workload an API key it never reads | [credentials](../skills/credentials/SKILL.md) | `skills/credentials/scripts/preflight.sh --var <HOST_ENV_VAR> --host <api.example.com>` |
| Leave nothing running | [teardown](../skills/teardown/SKILL.md) | `skills/teardown/scripts/verify-clean.sh` |

## Skill packets

| Packet | What it covers | Procedure |
|---|---|---|
| [branch-and-checkpoint](../skills/branch-and-checkpoint/README.md) | scheduled checkpoints with history, restores, pause and resume, and branches with their branch point kept | [SKILL.md](../skills/branch-and-checkpoint/SKILL.md) |
| [credentials](../skills/credentials/README.md) | an API key a workload can use but never read, substituted on the way out | [SKILL.md](../skills/credentials/SKILL.md) |
| [dev-env](../skills/dev-env/README.md) | a machine you come back to, and what survives a stop and start | [SKILL.md](../skills/dev-env/SKILL.md) |
| [coding-agent](../skills/coding-agent/README.md) | a coding agent with full permissions inside a machine, the project mounted | [SKILL.md](../skills/coding-agent/SKILL.md) |
| [docker-in-machine](../skills/docker-in-machine/README.md) | a Docker daemon inside a machine, for tools that call Docker themselves | [SKILL.md](../skills/docker-in-machine/SKILL.md) |
| [gpu-cuda](../skills/gpu-cuda/README.md) | the guest's CUDA Driver API calls, and Runtime API calls through a `libcudart` shim, remoted to the host's NVIDIA GPU | [SKILL.md](../skills/gpu-cuda/SKILL.md) |
| [install](../skills/install/README.md) | installing smolvm and proving the host can boot a microVM | [SKILL.md](../skills/install/SKILL.md) |
| [local-api](../skills/local-api/README.md) | driving the machine lifecycle over the local HTTP API | [SKILL.md](../skills/local-api/SKILL.md) |
| [pack](../skills/pack/README.md) | packing an image or a machine into a portable artifact | [SKILL.md](../skills/pack/SKILL.md) |
| [teardown](../skills/teardown/README.md) | what state exists, where it lives, and how to leave nothing running | [SKILL.md](../skills/teardown/SKILL.md) |
| [throwaway-machine](../skills/throwaway-machine/README.md) | running untrusted code in a throwaway machine, with egress granted one host at a time | [SKILL.md](../skills/throwaway-machine/SKILL.md) |

## Reference pages

| Page | What it covers |
|---|---|
| [smolfile.md](smolfile.md) | the Smolfile format: keys, tables and `stop_on_exit` |
| [security-model.md](security-model.md) | what the VM boundary protects, and what each forwarded capability gives the workload |
| [limitations.md](limitations.md) | known limitations, host mount behaviour and the relay limit |
| [credential-substitution.md](credential-substitution.md) | credentials a workload can use and never read, and the external interceptor |
| [mediated-egress.md](mediated-egress.md) | a host decider for each guest TCP flow, and its protocol |
| [branching.md](branching.md) | live branches, frozen sources and batch branches |
| [pause-resume.md](pause-resume.md) | pausing a running machine and resuming it under the same name |
| [volumes.md](volumes.md) | S3 buckets as volumes, and staged copies of host directories |
| [usage-journal.md](usage-journal.md) | the local record of machine lifecycle events, what it contains, and how to read, disable or share it |
| [incremental-checkpoints.md](incremental-checkpoints.md) | checkpoint stores, history, export and pruning |
| [mac-to-linux.md](mac-to-linux.md) | moving a running machine from an arm64 Mac to arm64 Linux |
| [pack-layer-ownership.md](pack-layer-ownership.md) | why a pack built before 1.8.1 loses its files' owners |
| [gpu.md](gpu.md) | Vulkan through virtio-gpu, and CUDA API remoting |
| [nested-virtualization.md](nested-virtualization.md) | running KVM, and so smolvm or QEMU, inside a machine |
| [named-networks.md](named-networks.md) | machines that reach each other by IP on a shared named network |
| [browser-display.md](browser-display.md) | a machine's display in the browser or a VNC client, with keyboard and pointer |
| [hardware-video.md](hardware-video.md) | H.264 streaming of a machine's browser display |
| [kubernetes.md](kubernetes.md) | pods as microVMs through a `RuntimeClass` |
| [install-arch.md](install-arch.md), [install-debian.md](install-debian.md), [install-fedora.md](install-fedora.md), [install-nix.md](install-nix.md) | the packaged installs |
| [DEVELOPMENT.md](DEVELOPMENT.md) | building and testing smolvm itself |
