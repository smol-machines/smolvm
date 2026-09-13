---
name: install
description: Installs smolvm from a published release and proves the host can actually boot a microVM before any other work starts. Use when setting smolvm up on a new machine, a CI runner or an agent sandbox; when a first boot fails with krun_start_enter -22, KVM_DENIED or "agent did not become ready"; when checking whether a host meets smolvm's requirements at all; or when an install has to be isolated from an existing one and then removed. Do not use it to remove an existing install (see the teardown packet) or for anything after the first boot has succeeded.
---

# Installing smolvm and proving it works

Verified on **smolvm v1.14.6** on macOS arm64 and Linux aarch64, 2026-09-10. Done means `smolvm --version` prints the release version **and**
a throwaway VM has run one command and exited. A version number alone proves nothing: on every
platform here there is at least one way for the install to succeed and every VM start to fail.

`scripts/preflight.sh` reports the host as `key=value` lines and ends with `result=ready` or
`result=blocked`. Run it first, and run it again after the install if the first boot fails.

## Procedure

**1. Preflight.** Read-only. It starts no VM and writes no smolvm state.

```bash
scripts/preflight.sh
```

Stop on `result=blocked` and read the `note=` lines. The two that block a fresh host are
`accel_access=denied` on Linux (your user cannot open `/dev/kvm`) and `socket_path_status=too_long`
on macOS (the install path is too deep for a VM's Unix socket). Both have a fix in
`references/traps.md`, and neither announces itself later: the installer warns about KVM and
continues, and the path limit surfaces as an error about disks.

**2. Install from the published release.**

```bash
curl -sSL https://smolmachines.com/install.sh | bash -s -- --version 1.14.6
export PATH="$HOME/.local/bin:$PATH"
smolvm --version
```

On macOS two `warning:` lines about notarization appear on every install and are not a problem.
On Linux `info: KVM access verified` appears only when your user can already open `/dev/kvm`.

To install without touching an existing one, point `HOME` at a scratch directory: every path
smolvm uses moves with it on macOS and Linux. Keep that directory shallow on macOS. This does not
work on Windows, where state cannot be relocated at all. See `references/layout.md`.

Windows does not use this installer. See `references/windows.md`.

**3. Prove it boots.** This is the step that decides whether smolvm works here.

```bash
scripts/verify-boot.sh
```

It runs one ephemeral alpine VM and asserts two values: a marker the guest printed, and that the
guest kernel is not the host's. On failure it prints the three misreadings that cost the most
time, before you clean up and lose the evidence.

**4. Clean up.**

```bash
scripts/cleanup.sh
```

It waits before asserting an empty machine list, because a successful `machine run` returns
before its entry retires and an immediate assertion fails on a healthy host. It then reports VM
processes an interrupt left behind, and kills them only with `--reap`.

## What the preflight reports

| key | meaning |
|---|---|
| `smolvm_installed`, `smolvm_version` | whether the binary is on `PATH` and what it says |
| `verified_version`, `version_status` | `match`, `newer`, `older` or `unknown` against the 1.14.6 this packet was verified on |
| `platform` | `darwin-aarch64`, `linux-aarch64`, `linux-x86_64` |
| `accel`, `accel_access` | `hvf` and `kern.hv_support`, or `kvm` and whether `/dev/kvm` is readable and writable |
| `macos_version`, `hardware_verified` | `hardware_verified=no` on an Intel Mac: the installer accepts it and nothing here was run on one |
| `socket_path_bytes`, `socket_path_status` | macOS only, and the single most common cause of "macOS is broken" |
| `unsupported` | features this platform does not have |
| `result` | `ready` or `blocked` |

`version_status=newer` is a warning, not a failure. smolvm's flags and messages move every
release, so on a newer binary check each step's output against the binary before trusting the
text here.

## Security defaults, and why they are the defaults

- **The installer is a user-level install and needs no root.** Everything lands under `$HOME`,
  which is what lets an agent or a CI job install a private copy and remove it without a
  privileged step. Nothing in this packet escalates privilege.
- **`sudo usermod -aG kvm` is the one privileged step, and it is yours to run.** Group membership
  on `/dev/kvm` is the host's boundary between users who can start VMs and users who cannot, so a
  script should report `accel_access=denied` and stop rather than widen it for you. `sg kvm -c`
  then applies the group to a single command instead of your whole session.
- **The uninstaller leaves `~/.config/smolvm` and your `PATH` line on purpose.** Those hold
  registry credentials and a change you made to your own shell profile, so removing them is a
  separate, deliberate act. `references/layout.md` has both commands.

## Platform arms

- **macOS arm64**: verified. The path-length rule in `references/traps.md` applies to every install.
- **Linux aarch64 and x86_64**: verified. The `kvm` group check applies to every fresh host.
- **Intel Mac**: **unverified.** The installer accepts macOS 11 or later on Intel and nothing in
  the material behind this packet was run on one. `preflight.sh` reports `hardware_verified=no`
  there rather than implying it works.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-09-11 against v1.14.6** on
  Windows 11 Home build 10.0.26200.0 UBR 9445, where it confirmed. The
  three facts that break a Unix-shaped script are there: the zip unpacks into a nested versioned
  folder, state lives in `%LOCALAPPDATA%\smolvm` and cannot be moved, and a script must never
  capture `machine start` output because it never returns.

## Eval prompts, and what they produced

Run against this packet on 2026-09-07 PT, on smolvm v1.14.2 installed from the published release
into an isolated `HOME`. Output is verbatim.

**1. "Install smolvm on this machine and tell me whether it can actually run a VM."**

macOS 26.6.2 arm64:

```
smolvm_installed=yes
smolvm_version=1.14.2
version_status=match
platform=darwin-aarch64
accel=hvf
accel_access=ok
socket_path_bytes=62
socket_path_status=ok
result=ready

  BOOTED_OK
  Linux 6.12.95 aarch64
guest_ran=yes
guest_kernel=Linux 6.12.95
host_kernel=Darwin 25.6.0
is_a_vm=yes
result=boot_ok
```

Lima `linux-kvm`, Ubuntu 24.04 aarch64:

```
platform=linux-aarch64
accel=kvm
accel_access=ok
result=ready

  BOOTED_OK
  Linux 6.12.95 aarch64
guest_kernel=Linux 6.12.95
host_kernel=Linux 6.8.0-139-generic
is_a_vm=yes
result=boot_ok
```

Boot plus image pull took 8.9 s on macOS and 22.4 s on the nested-virt Linux box.

**2. "smolvm is installed but every `machine run` fails with `krun_start_enter returned: -22`.
What is wrong?"**

Reproduced deliberately on macOS by installing into a 49-character `HOME`. The preflight names
the cause before any VM is started:

```
socket_path_bytes=104
socket_path_status=too_long
note=HOME is too deep: every VM start will fail with krun_start_enter -22, whose text blames disks and device options. Install under a shorter HOME.
result=blocked
```

and the boot then fails exactly as reported, with the misleading text:

```
Error: agent operation failed: start machine: agent operation failed: monitor agent:
agent operation failed: start vm: krun_start_enter returned: -22 (EINVAL ... libkrun
rejected the VM configuration; usually a disk/overlay that could not be opened ... or an
unsupported device option) (boot process exited (code 1) before the agent was ready)
guest_ran=no
is_a_vm=no
result=boot_failed
```

**3. "Set up smolvm somewhere throwaway so it does not touch my existing install, then remove
it."**

Both isolated installs in this session ran under a scratch `HOME` and the uninstaller then
reported every path removed, with `find "$HOME" -iname '*smolvm*'` empty afterwards:

```
success: Removed <HOME>/.smolvm
success: Removed symlink <HOME>/.local/bin/smolvm
success: Removed data directory <HOME>/Library/Application Support/smolvm
success: Removed cache directory <HOME>/Library/Caches/smolvm
warning: You may want to remove the PATH entry from your shell profile.
success: smolvm has been uninstalled
```

## Re-verified on v1.14.6

Run 2026-09-10 PT against v1.14.6 from the published release, into a fresh isolated `HOME` on
macOS 26.6.2 arm64 and Lima `linux-kvm` (Ubuntu 24.04 aarch64). Both hosts: `result=ready`, then
`guest_ran=yes`, `guest_kernel=Linux 6.12.95`, `is_a_vm=yes`, `result=boot_ok`, and a clean
cleanup. The guest kernel is unchanged across 1.14.2, 1.14.3 and 1.14.6.

## What was not run

- **Intel Mac.** Nothing.
- **Windows.** `references/windows.md` records a run on Windows 11 Home build 26200 that was not
  repeated here. No PowerShell script ships with this packet for that reason.
- **The unprivileged Windows symlink path.** The Windows preflight check for Developer Mode or
  `SeCreateSymbolicLinkPrivilege` is written from reading the release's extraction path and from a
  session that already held the privilege. The failure it guards against has been reported from
  outside and reproduced by forcing the state, but the unprivileged install itself has not been
  run by anyone here.
- **Linux x86_64** was verified for install and boot in the material behind this packet, on a
  cloud GPU instance that no longer exists. The scripts here were re-run on macOS arm64 and Linux
  aarch64 only.

## Related packets

- `teardown` for the full removal sequence, and for what a leak check must exclude.
- `sandbox` for running untrusted work in a throwaway machine, which assumes this boot.
- `dev-env`, `local-api`, `docker-in-machine`, `gpu-cuda` and `pack` all assume it too.
