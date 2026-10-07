# Install traps, and what each message actually means

## Contents

- `krun_start_enter returned: -22 (EINVAL ...)` on macOS
- `KVM_DENIED` on a fresh Linux box
- `agent did not become ready within 30 seconds`
- `TOOMANYREQUESTS` from `crane manifest`
- `machine list` shows a just-finished VM as `unreachable (eph)`
- The boot subprocess hides its own errors
- `DYLD_PRINT_LIBRARIES` prints nothing on macOS
- Two assertion habits that apply beyond install

Each entry is "if you see X, it means Y". Every one of these was hit on a real host, and each
message points somewhere other than its cause.

## `krun_start_enter returned: -22 (EINVAL ...)` on macOS

**It means your install path is too long.** The error text names disks and device options; the
cause is the path length. The one other cause is a binary that lost its hypervisor entitlement by being
re-signed or built locally; [known limitations](../../limitations.md) has the fix for that, and the
release binary the installer lays down has it.

A VM's agent socket is `$HOME/Library/Caches/smolvm/vms/<16 hex>/agent.sock`. macOS
`sockaddr_un.sun_path` holds 104 bytes including the terminator, so once `$HOME` is deep enough
the socket path no longer fits and **every** VM start fails immediately. Measured by installing
into `$HOME` directories of increasing length:

| socket path bytes | result |
|---|---|
| 100 | boots |
| 102 | `-22` |
| 104 | `-22` |
| 106 | `-22` |

`scripts/preflight.sh` computes that path and reports `socket_path_bytes` and
`socket_path_status` before you install anything.

Of the traps here this one took longest to diagnose, and it was first concluded to be "macOS is
broken". Everything else was ruled out by running it. The same release boots from a short `$HOME`
on the same machine; v1.14.1, v1.13.0 and v1.11.0 all fail identically at a long path, so it is
not a regression; the installed binary matches the tarball byte for byte; `kern.hv_support` is 1;
and an ad-hoc-signed C program linking the release's own `libkrun.dylib` runs a VM to completion
and accepts smolvm's own `storage.raw` and `overlay.raw`.

**A CI job or an agent harness that installs under a deep temporary directory will hit this and
will not be able to tell why.** Nothing in the README or the installer mentions a path-length
limit.

## `KVM_DENIED` on a fresh Linux box

**It means your user is not in the `kvm` group, and the install said nothing about it.** The
installer warns and then continues when `/dev/kvm` is inaccessible, so a successful install says
nothing about whether a VM will start. This was the out-of-the-box state on a fresh cloud GPU
instance.

The installer tells you to log out and back in. You do not have to:

```bash
sudo usermod -aG kvm "$USER"
sg kvm -c 'smolvm machine run --mem 2048 --net --image alpine -- echo OK'
```

`sg kvm -c '<command>'` (or `newgrp kvm`) applies the new group to a single command immediately,
which is what you want over SSH or inside a script.

## `agent did not become ready within 30 seconds`

**Suspect host load before you suspect the install.** This was reproduced on both macOS and a
nested-virt Linux host purely by running other VMs at the same time, and the identical command
passed on a quiet host seconds later.

**Then suspect the guest's size.** A host that is slow to fault in guest memory can boot a small
guest and time out on a large one, and the message is the same. Measured on Lima `linux-kvm`
(Ubuntu 24.04 aarch64, nested virtualisation on a 16 GiB Mac that was paging), 2026-09-24:

| `--mem` | v1.18.2 | v1.16.1 |
|---|---|---|
| 512, 1024 | booted, about 14 s | not run |
| 2048 | booted, 33 s | booted, 36 s |
| 2560 to 8192 | `agent did not become ready within 30 seconds` | the same at 4096 and 8192 |

The default is 8192, so on such a host `machine create` without `--mem` gives a machine that never
starts, while `scripts/verify-boot.sh` at 2048 passes. Bisect on `--mem` before designing around
it: the same host booted 8192 on v1.14.6 on 2026-09-10, when its host was not paging.

**From v1.22.0 a first boot can wait out that timeout before it starts.** The first run of each
registry image builds a shared seed of it in a helper machine, `image-seed-<hash>-<pid>`, which
boots at 8192 MiB whatever `--mem` asks for. On Lima `linux-kvm` on 2026-10-03, which booted 2048
and timed out at 4096 and 8192, `scripts/verify-boot.sh` printed
`WARN no image seed; pulling in the guest ... agent did not become ready within 30 seconds`, fell
back to pulling inside its own 2048 MiB guest, and passed in 87 s. On a host that boots 8192 the
seed is built once and later runs of that image start in about a second.

The 30 s limit is a hard-coded constant (`src/agent/manager.rs`, `AGENT_READY_TIMEOUT`) and
**there is no flag or environment variable that raises it** for `machine run` or `machine start`.
`SMOLVM_AGENT_READY_TIMEOUT_SECS` exists but is read only by `pack run`.

## `TOOMANYREQUESTS` from `crane manifest`

**It means Docker Hub has refused this address's anonymous pulls, not that the install is broken.**
The guest pulls with `crane`, and a pull of `alpine` by its short name then fails as
`fetching manifest docker.io/library/alpine:latest: ... TOOMANYREQUESTS: You have reached your
unauthenticated pull rate limit`, at once and before any timeout. Name the same image from a
mirror, `mirror.gcr.io/library/alpine` or `public.ecr.aws/docker/library/alpine`, as
`scripts/verify-boot.sh --image` does.

To see the remaining count before a run, ask the endpoint the guest uses, `index.docker.io`, with
a `HEAD` request, which does not count against it:

```bash
T=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s --head -H "Authorization: Bearer $T" https://index.docker.io/v2/library/alpine/manifests/latest | grep -i ratelimit-remaining
```

On 2026-10-03 this answered `0` while the same request to `registry-1.docker.io` still answered
`63`, so ask `index.docker.io`. Setting a registry `mirror` for `docker.io` in
`~/.config/smolvm/config.toml` is not a substitute on v1.22.2: every run then ended with
`run command: image not found: docker.io/library/<image>`.

## `machine list` shows your just-finished VM as `unreachable (eph)`

**Nothing is wrong.** The entry retires asynchronously after the run returns; observed gone by
20 s. On v1.22.2 it was already gone when `machine list` ran straight after the run, 4 of 4 on
macOS arm64; the wait stays for the releases that need it. A cleanup assertion that runs immediately after `machine run` fails on a healthy system,
which is why `scripts/cleanup.sh` waits before asserting.

## The boot subprocess hides its own errors

The child's stdout and stderr go to `/dev/null` unless `SMOLVM_BOOT_DEBUG=1`, and even that
showed nothing useful. To see the real failure, run the child yourself:

```bash
smolvm-bin _boot-vm <vm-dir>/boot-config.json
```

That is how the vCPU panics behind the macOS `-22` were read. **The child deletes its own
`boot-config.json` as soon as it has read it**, before the VM starts, so a copy has to be taken in
the moment between the CLI writing it and the child reading it: loop on `cp` while you start the
machine.
`RUST_LOG=debug` on the CLI shows the disk-template and boot timeline, which separates a template
problem from a hypervisor problem.

## `DYLD_PRINT_LIBRARIES` prints nothing on macOS

**Do not conclude anything from it.** `smolvm-bin` carries entitlements, so dyld strips `DYLD_*`
from its environment. The binary finds its libraries through `@executable_path/lib` regardless,
so the stripping is harmless and tells you nothing about a library problem.

## Two assertion habits that apply beyond install

- **Assert values, never exit codes.** A pack that lost its rootfs still boots and exits zero; a
  guest command that fails still returns HTTP 200 from the local API; a CUDA program can link and
  exit zero without ever reaching a GPU. `scripts/verify-boot.sh` asserts a marker the guest
  printed and that the guest kernel differs from the host's, for this reason.
- **Find leftover VMs by the process name, not by `pgrep -f _boot-vm` and not by `readlink
  /proc/<pid>/exe`.** The pattern form matches any shell whose text contains that string, including
  the cleanup script itself, and it produced a phantom "1 orphan survived" result.
  **The `/proc/<pid>/exe` route then fails for a different reason**: the VM process is not
  dumpable, so its `/proc/<pid>/exe` is root-owned and `readlink` returns `Permission denied` to
  the very user who started it, leaving a reaper that reports "no orphans" while an orphan runs.
  Both were observed on Ubuntu 24.04 aarch64 on 2026-09-07. `scripts/cleanup.sh` matches the VM
  process's name in `/proc/<pid>/comm` (`libkrun VM`, or `VM:<hostname>` when `HOSTNAME` is
  exported), which a shell cannot hold, then keeps only those whose boot config lives under this
  `HOME`'s smolvm state, or whose executable is under the install prefix, so another session's VM
  is left alone. On macOS it scopes by the executable path under the prefix and the parent chain
  over `ps -axo pid=,ppid=,command=`.
