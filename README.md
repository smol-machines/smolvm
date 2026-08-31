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
1. Manage and run custom Linux virtual machines locally with: sub-second cold start, cross-platform (macOS, Linux, Windows), elastic memory usage.
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

**Windows:** download the `windows-x86_64` release (bundles `krun.dll` + `libkrunfw.dll`), unzip it, and run `smolvm.exe`. Requires the [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (WHP) feature enabled.

Quick Start
-----------

```bash
# run a command in an ephemeral VM (cleaned up after exit)
smolvm machine run --net --image alpine -- sh -c "echo 'Hello world from a microVM' && uname -a"

# interactive shell
smolvm machine run --net -it --image alpine -- /bin/sh
# inside the VM: apk add sl && sl && exit
```

Smolfile
--------

A Smolfile declares a machine in TOML — the equivalent of a `Dockerfile` or a
cloud-init file, but for a whole VM: image, resources, network policy, mounts,
ports, and setup commands in one checked-in file.

```toml
image = "python:3.12-alpine"
net = true
cpus = 4
memory = 4096

ports = ["8000:8000", "5173-5180:5173-5180"]
volumes = ["./src:/app"]
init = ["pip install -r /app/requirements.txt"]

[network]
allow_hosts = ["api.stripe.com", "pypi.org"]

[auth]
ssh_agent = true
```

```bash
smolvm machine create --name myvm -s Smolfile   # or --smolfile <PATH>
smolvm machine start --name myvm
```

Port mappings accept a single port (`"8080"`), an explicit mapping (`"8080:80"`), or equal-length one-to-one ranges (`"5173-5180:5173-5180"`). A machine can publish at most 64 concrete mappings.

Unknown keys are rejected rather than ignored, so a typo fails at create time
instead of silently doing nothing.

Common keys: `image`, `cpus`, `memory`, `net`, `ports`, `volumes`, `env`,
`init`, `workdir`, `gpu`, `cuda`, `docker_socket`, `storage`, `overlay`, and the
`[network]`, `[dev]`, `[auth]`, `[health]`, `[restart]`, `[service]` tables.

### Snapshot a machine into a reusable image

You don't need a Dockerfile to keep an environment. Set a machine up however you
like — by hand, or from a Smolfile — then pack the stopped machine into a
`.smolmachine` artifact and push it to any OCI registry:

```bash
smolvm machine shell --name myvm          # install and configure interactively
smolvm machine stop  --name myvm
smolvm pack create --from-vm myvm -o myvm
smolvm pack push --file myvm.smolmachine ghcr.io/you/myvm:v1
```

Anyone can then pull it and boot the exact same machine:

```bash
smolvm pack pull ghcr.io/you/myvm:v1
```

Working Smolfiles: [python](https://github.com/smol-machines/smolvm/tree/main/examples/python-app) · [node](https://github.com/smol-machines/smolvm/tree/main/examples/node-app) · [docker-in-vm](https://github.com/smol-machines/smolvm/tree/main/examples/docker-in-vm) · [local-llm](https://github.com/smol-machines/smolvm/tree/main/examples/local-llm) · [headless-browser](https://github.com/smol-machines/smolvm/tree/main/examples/headless-browser) · [doom](https://github.com/smol-machines/smolvm/tree/main/examples/doom-web)

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

**Use local container images** — for CI, air-gapped hosts, and fast iteration. Feed `--image` a `docker save` / `podman save` archive, pipe one on stdin, or point it at an unpacked rootfs directory. Image work is delegated to your container tooling; smolvm just boots the result.

```bash
# build locally, run in the VM with no push/pull
docker build -t myapp .
docker save myapp | smolvm machine run --image - -- ./app

# from an archive file (boots with no network)
smolvm machine run --image ./myapp.tar -- ./app

# from an already-unpacked rootfs directory
smolvm machine run --image ./rootfs/ -- ./app
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

**Use git and SSH without copying private keys into the guest.** Forward your host SSH agent into the VM. The guest can ask the agent to sign with any forwarded key while the socket is available, so forward it only to workloads you trust. Requires an SSH agent running on your host (`ssh-add -l` to check).

```bash
smolvm machine run --ssh-agent --net --image alpine -- sh -c "apk add -q openssh-client && ssh-add -l"
# lists your host keys; private key material remains in the host agent

smolvm machine exec --name myvm -- git clone git@github.com:org/private-repo.git
```

**Run guest GUI apps on your host desktop over vsock.** `--waypipe` bridges a guest [waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe) vsock port to a host Unix socket in the VM data dir — no X11, no SSH server, no TCP port forward. The guest agent runs `waypipe server` as a daemon inside the workload container and exports `WAYLAND_DISPLAY` automatically, and on the host smolvm starts the matching `waypipe client` next to your Wayland compositor for you (Linux hosts). So you just run your GUI app — both ends are wired up. One daemon serves every app (like a normal Wayland display), and it starts on first launch — no per-app `waypipe server` wrapper.

```bash
smolvm machine create --name gui --net --waypipe --image ubuntu:24.04
smolvm machine start --name gui

# Guest: run any GUI app. WAYLAND_DISPLAY is set, the guest daemon is started,
# and the host waypipe client is running against your compositor.
smolvm machine exec --name gui -- weston-terminal
```

The host client is started automatically on Linux when `$WAYLAND_DISPLAY` is set and `waypipe` is on the host `PATH`; it lives as long as the VM and is killed with it. If either is missing, smolvm skips it and you can run one by hand:

```bash
waypipe -s "$(smolvm machine data-dir --name gui)/waypipe.sock" client &
```

`--waypipe` takes an optional value selecting which `waypipe` binary the guest daemon runs:

- `--waypipe` or `--waypipe=host` (default) — share the **host** waypipe binary into the guest, so the guest server and your host client are the exact same binary (no wire-version drift) and the image needs no waypipe installed. Requires the host glibc to be compatible with the guest image's (usually true for a recent image).
- `--waypipe=container` — use the image's **own** `waypipe` (install it yourself, e.g. `apt-get install -y waypipe`). The daemon starts on the first launch after waypipe is present, with no restart.
- `--waypipe=/path/to/waypipe` — share that specific host binary.

Requires a `--vsock`-capable waypipe (>= 0.9) on the host, and (for `container`) in the guest. `--waypipe` needs an `--image`: the guest daemon runs inside the workload container (the agent's own rootfs is musl and cannot exec a glibc waypipe), which a bare VM does not have — so `--waypipe` without an image is rejected up front.

One waypipe daemon in the guest serves every app (like the X11 display socket), and it starts lazily — the first launch after you install waypipe brings it up with no VM restart. The bridge uses the same vsock mechanism as `--cuda`, so no networking is required for forwarding itself (`--net` is only needed to install waypipe in the guest).

If the daemon can't start, smolvm says so rather than failing silently: `machine exec -- cmd` prints the reason on stderr (without disturbing the command's own output), and an interactive `machine exec -it` shell prints it at the top of the session. Either way the message says whether waypipe isn't installed yet (with how to install it — the daemon then comes up on the next command) or is present but failed to start (e.g. a host/guest glibc mismatch in `host` mode — try `--waypipe=container`).

**Or bridge the raw X11 socket, no waypipe.** `--x11` resolves the host `$DISPLAY` at launch and bridges a guest vsock port straight to that X server's Unix socket. X was designed for network transparency, so guest X clients talk to your host X server directly. The guest agent sets up the display socket and exports `DISPLAY=:10` for you — no `socat`, just run an X client. Needs a running host X server (a native X session, or an Xwayland/`Xephyr` on a Wayland host).

```bash
smolvm machine create --name xgui --net --x11 --image ubuntu:24.04
smolvm machine start --name xgui               # start with $DISPLAY set

xhost +local:                                  # allow the bridged connections

# DISPLAY=:10 is already set in the VM — just run an X client.
smolvm machine exec --name xgui -- sh -c 'apt-get install -y x11-apps && xeyes'
```

The X11 bridge is a plain byte pipe (guest connects out to host CID 2, port 7002), so it cannot pass `SCM_RIGHTS` ancillary fds — MIT-SHM and DRI3 fall back to wire-image transport (correct, just slower). For per-window Wayland integration and correct fd/GPU handling, prefer `--waypipe`.

**Declare environments in a file** — see [Smolfile](#smolfile) above for
reproducible machine config, and for snapshotting a configured machine into a
reusable `.smolmachine` image without writing a Dockerfile.

How It Works
------------

Each workload runs in a hardware-virtualized VM with its own guest kernel on [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS), KVM (Linux), or the [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (Windows). [libkrun](https://github.com/containers/libkrun) is the VMM and [libkrunfw](https://github.com/smol-machines/libkrunfw) supplies the guest kernel. Pack it into a `.smolmachine` and it runs anywhere the host architecture matches, with zero dependencies.

Images use the [OCI](https://opencontainers.org/) format — the same open standard Docker uses. Any image on Docker Hub, ghcr.io, or other OCI registries can be pulled and booted as a microVM. No Docker daemon required.

Defaults: 4 vCPUs, 8 GiB RAM. Memory is elastic via virtio balloon — the host only commits what the guest actually uses and reclaims the rest automatically. vCPU threads sleep in the hypervisor when idle, so over-provisioning has near-zero cost. Override with `--cpus` and `--mem`.

Security Model
--------------

smolvm strengthens the guest/host boundary by giving each workload a separate VM and guest kernel. It is not, by itself, a hardened multi-user control plane:

* The `smolvm` CLI and VMM processes run with the permissions of the invoking host user. That user account, the host OS, the hypervisor backend, libkrun, and smolvm are in the trusted computing base.
* Host directories passed with `--volume` are intentionally exposed to the guest with the requested access. Do not mount secrets or sensitive paths into an untrusted workload.
* `--ssh-agent` does not copy private key material into the guest, but it grants the guest access to the forwarded agent socket and therefore the ability to request signatures while the VM is running.
* `--waypipe` opens a vsock channel from the guest to a host Unix socket that a `waypipe client` reads next to your Wayland compositor. A guest with this enabled can drive that client; only enable it for workloads whose GUI you intend to display.
* `--x11` bridges a guest vsock port straight to your host X server socket, giving the guest a direct connection to that X server. X11 has weak client isolation, so treat a guest with `--x11` as having access to the whole X server (input, other windows, clipboard); only enable it for trusted GUI workloads, and rely on X access control (`xhost`) deliberately.
* Networking is disabled by default. Enabling `--net`, port forwarding, or host services expands the workload's reachable surface.
* In standalone local use, smolvm's state and control endpoints are scoped to the invoking user's environment. For hostile local co-tenants, add host-level account separation and OS confinement around the VMM process. This section does not describe the separate smolmachines cloud control plane or its tenant-isolation guarantees.
* Release archives publish SHA-256 checksums and the installer rejects a mismatch when the checksum file is available. Releases are not currently signed or accompanied by provenance attestations, and the installer permits installation when the checksum file cannot be downloaded.

Treat root in the guest as untrusted. The VM boundary limits its direct access to the host, while every explicitly forwarded capability, including mounts, network access, ports, and SSH agent access, becomes part of the workload's authority.

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

Known Limitations
-----------------

* Network is opt-in (`--net` on `machine create`). TCP/UDP only, no ICMP.
* Volume mounts: directories only (no single files). Mounting at `/workspace` (`-v /host/dir:/workspace`) takes priority over the default storage-disk workspace — your host directory is used instead.
* macOS: binary must be signed with Hypervisor.framework entitlements (`com.apple.security.hypervisor`). The shipped release is; a re-signed or freshly built binary silently loses it and every VM start then fails with `krun_start_enter returned: -22 (EINVAL)`. Re-sign it (ad-hoc is fine): `codesign --force --sign - --entitlements hv.entitlements <smolvm-bin>` where `hv.entitlements` is a plist containing `<key>com.apple.security.hypervisor</key><true/>`.
* `--ssh-agent` requires an SSH agent running on the host (`SSH_AUTH_SOCK` must be set).
* GPU acceleration requires libkrun built with `GPU=1` and virglrenderer + a Vulkan driver on the host (see [GPU Acceleration](#gpu-acceleration) below).
* Windows: `--net` works the same as on other platforms (virtio-net with inbound port-forwarding; TSI for outbound-only VMs), as do `machine exec` / interactive sessions and `machine stats`. Not yet available on Windows: GPU acceleration and `machine fork` / snapshot. Pack *create* needs `storage-template.ext4` / `overlay-template.ext4` next to `smolvm.exe` (Windows has no host `mkfs.ext4`).

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

CUDA API Remoting
-----------------

`--gpu` and `--cuda` provide different interfaces. `--gpu` exposes Vulkan through virtio-gpu / Venus; it does not provide CUDA. `--cuda` enables CUDA API remoting: driverless guest shims forward CUDA calls over vsock to a host process, which executes them through the host's NVIDIA driver.

CUDA remoting requires an NVIDIA GPU and a working NVIDIA driver on the host. It is not GPU passthrough: the guest receives neither the physical device nor an NVIDIA driver.

Fork-heavy Linux hosts should use a kernel containing upstream KVM fix
[`916b7f4`](https://github.com/torvalds/linux/commit/916b7f42b3b3b539a71c204a9b49fdc4ca92cd82).
Affected kernels can intermittently report `ENOMEM` on the first `KVM_RUN` even
with ample host memory; smolvm reduces exposure and replaces a failed worker,
but the kernel update is the definitive fix.

The VM boundary still isolates the workload's CPU, memory, and filesystem. GPU access is mediated by host processes and the shared host GPU, so GPU isolation remains process-level rather than a hardware or VM boundary. Do not treat CUDA remoting as a hardened multi-tenant GPU isolation boundary.

See [GPU access by API remoting: how a driverless microVM runs CUDA](https://smolmachines.com/engineering/gpu-over-vsock) for the design, trade-offs, and comparison with passthrough.

Development
-----------

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

[Apache-2.0](LICENSE) · made by [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
