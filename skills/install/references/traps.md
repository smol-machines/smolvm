# Install traps, and what each misleading message actually means

## Contents

- `krun_start_enter returned: -22 (EINVAL ...)` on macOS
- `KVM_DENIED` on a fresh Linux box
- `agent did not become ready within 30 seconds`
- `machine list` shows a just-finished VM as `unreachable (eph)`
- The boot subprocess hides its own errors
- `DYLD_PRINT_LIBRARIES` prints nothing on macOS
- Two assertion habits that apply beyond install

Each entry is "if you see X, it means Y". Every one of these was hit on a real host during the
runs this packet is built from, and each cost time because the message points somewhere else.

## `krun_start_enter returned: -22 (EINVAL ...)` on macOS

**It means your install path is too long.** The error text blames disks and device options and
is wholly misleading.

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

This is the single most expensive trap in the material behind this packet: it cost most of a
session and produced a false "macOS is broken" conclusion. Everything else was ruled out by
running it. The same release boots from a short `$HOME` on the same machine; v1.14.1, v1.13.0 and
v1.11.0 all fail identically at a long path, so it is not a regression; the installed binary
matches the tarball byte for byte; `kern.hv_support` is 1; and an ad-hoc-signed C program linking
the release's own `libkrun.dylib` runs a VM to completion and accepts smolvm's own `storage.raw`
and `overlay.raw`.

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
nested-virt Linux box purely by running other VMs at the same time, and the identical command
passed on a quiet host seconds later.

The 30 s limit is a hard-coded constant (`src/agent/manager.rs`, `AGENT_READY_TIMEOUT`) and
**there is no flag or environment variable that raises it** for `machine run` or `machine start`.
`SMOLVM_AGENT_READY_TIMEOUT_SECS` exists but is read only by `pack run`.

## `machine list` shows your just-finished VM as `unreachable (eph)`

**Nothing is wrong.** The entry retires asynchronously after the run returns; observed gone by
20 s. A cleanup assertion that runs immediately after `machine run` fails on a healthy system,
which is why `scripts/cleanup.sh` waits before asserting.

## The boot subprocess hides its own errors

The child's stdout and stderr go to `/dev/null` unless `SMOLVM_BOOT_DEBUG=1`, and even that
showed nothing useful. To see the real failure, run the child yourself:

```bash
smolvm-bin _boot-vm <vm-dir>/boot-config.json
```

That is how the vCPU panics behind the macOS `-22` were finally read. **The child deletes its own
`boot-config.json` on exit**, so copy it while a start is in flight if you want to re-run it.
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
- **Find leftover VMs by argv, not by `pgrep -f _boot-vm` and not by `readlink /proc/<pid>/exe`.**
  The pattern form matches any shell whose text contains that string, including the cleanup script
  itself, and it produced a phantom "1 orphan survived" result in the runs behind this packet.
  **The `/proc/<pid>/exe` route then fails for a different reason**: the VM process is not
  dumpable, so its `/proc/<pid>/exe` is root-owned and `readlink` returns `Permission denied` to
  the very user who started it, leaving a reaper that reports "no orphans" while an orphan runs.
  Both were observed on Ubuntu 24.04 aarch64 on 2026-09-07. `scripts/cleanup.sh` reads
  `/proc/<pid>/cmdline` and requires `argv[1]` to be exactly `_boot-vm`, which a shell cannot
  match, then keeps only the processes whose boot config lives under this `HOME`'s smolvm state so
  another session's VM is left alone. On macOS the same test runs over `ps -axo pid=,command=`.
