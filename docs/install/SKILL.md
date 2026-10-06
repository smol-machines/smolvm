---
name: install
description: Installs smolvm from a published release and proves the host can actually boot a microVM before any other work starts. Use when setting smolvm up on a new machine, a CI runner or an agent's own environment; when a first boot fails with krun_start_enter -22, KVM_DENIED or "agent did not become ready"; when checking whether a host meets smolvm's requirements at all; or when an install has to be isolated from an existing one and then removed. Do not use it to remove an existing install (see the teardown packet) or for anything after the first boot has succeeded.
---

# Installing smolvm and proving it works

Verified on **smolvm v1.23.0** on macOS arm64, 2026-10-04, and on **v1.18.2** on Linux aarch64, 2026-09-24. Done means `smolvm --version` prints the release version **and** a throwaway VM has run
one command and exited. A version number alone proves nothing: on every
platform here there is at least one way for the install to succeed and every VM start to fail.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

`scripts/preflight.sh` reports the host as `key=value` lines and ends with `result=ready`,
`result=not_installed` or `result=blocked`. Run it first, and run it again after the install if
the first boot fails.

## Procedure

**1. Preflight.** Read-only. It starts no VM and writes no smolvm state.

```bash
scripts/preflight.sh
```

`result=not_installed` on a fresh host means the host is fit and smolvm is simply missing: go on
to step 2 and run this again afterwards. With another smolvm first on `PATH`, it describes that one
instead and can end `result=ready`: read `smolvm_path=` and the `note=` before trusting it. Stop on `result=blocked` and read the `note=` lines. The
two that block a fresh host are
`accel_access=denied` on Linux (your user cannot open `/dev/kvm`) and `socket_path_status=too_long`
on macOS (the install path is too deep for a VM's Unix socket). Both have a fix in
`references/traps.md`, and neither announces itself later: the installer warns about KVM and
continues, and the path limit surfaces as an error about disks.

**2. Install from the published release.**

```bash
curl -sSL https://smolmachines.com/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
smolvm --version
```

The installer writes under `$HOME` only: `~/.smolvm`, the launcher in `~/.local/bin`, and the
agent rootfs in `~/Library/Application Support/smolvm` on macOS or `~/.local/share/smolvm` on
Linux. When `~/.local/bin` is not already on `PATH` it appends a `# smolvm` `export PATH=...` line
to your shell profile (`~/.zshrc` for zsh); `--no-modify-path` skips that.

**Install the newest release.** The installer with no `--version` takes the latest published
release, and a later release is expected to work with this packet. The version in the banner above
is what the packet was last verified on, not what you should install. Pin only to reproduce a
recorded run:

```bash
curl -sSL https://smolmachines.com/install.sh | bash -s -- --version 1.23.0   # a recorded run
```

On macOS two `warning:` lines about notarization appear on every install and are not a problem.
On Linux `info: KVM access verified` appears only when your user can already open `/dev/kvm`.

To install without touching an existing one, point `HOME` at a scratch directory: every path
smolvm uses moves with it on macOS, and on Linux once `XDG_DATA_HOME` and `XDG_CACHE_HOME` are
unset, since both outrank `HOME` there. Keep that directory shallow on macOS. This does not work on
Windows, where state cannot be relocated at all. See `references/layout.md`.

Windows does not use this installer. See `references/windows.md`.

**3. Prove it boots.** This is the step that decides whether smolvm works here.

```bash
scripts/verify-boot.sh
```

It runs one ephemeral alpine VM and asserts two values: a marker the guest printed, and that the
guest kernel is not the host's. `--image <ref>` boots another image; when Docker Hub answers
`TOOMANYREQUESTS`, its anonymous pull limit, name the same image from a mirror,
`scripts/verify-boot.sh --image mirror.gcr.io/library/alpine` or
`public.ecr.aws/docker/library/alpine`, and the step tells you so when it sees that error. On
failure it prints the three misreadings that cost the most time, before you clean up and lose the
evidence.

It boots a 2048 MiB guest, and a machine you create without `--mem` asks for 8192. A host can pass
this step and still fail every default-size machine with `agent did not become ready within 30
seconds`; if your work uses the default, boot one at that size too. `references/traps.md` has the
measurement. From v1.22.0 the first run of each registry image also starts a seed helper at 8192
MiB whatever `--mem` says. When that helper cannot start the run prints
`WARN no image seed; pulling in the guest` and goes on: after the helper's 30 s timeout on a host
that cannot boot 8192 MiB, or at once when the helper's own pull is refused, as it is under the rate
limit.

**4. Clean up.**

```bash
scripts/cleanup.sh
```

It waits up to 20 seconds, polling the machine list and printing `waiting=up to 20s` first,
before asserting an empty machine list, because a successful `machine run` returns before its
entry retires and an immediate assertion fails on a healthy host. It then reports VM processes
left under this `HOME`, and `--reap` kills every one of them, a running machine you meant to keep
included, so read the plain report first.

## What the preflight reports

| key | meaning |
|---|---|
| `smolvm_installed`, `smolvm_path`, `smolvm_version` | whether the binary is on `PATH`, which one, and what it says; a `note=` when that binary is not under the `HOME` being checked |
| `verified_version`, `version_status` | `match`, `newer`, `older` or `unknown` against the version this packet was last verified on. `newer` is the expected state on a current host and is not a failure |
| `platform` | `darwin-aarch64`, `linux-aarch64`, `linux-x86_64` |
| `accel`, `accel_access` | `hvf` and `kern.hv_support`, or `kvm` and whether `/dev/kvm` is readable and writable |
| `macos_version`, `hardware_verified` | `hardware_verified=no` and `result=blocked` on an Intel Mac: no `darwin-x86_64` archive is published for v1.23.0 |
| `socket_path_bytes`, `socket_path_status` | macOS only, and the single most common cause of "macOS is broken" |
| `unsupported` | features this platform does not have |
| `result` | `ready`, `not_installed` (the host is fit and smolvm is missing) or `blocked` |

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

- **macOS arm64**: verified on v1.23.0. The path-length rule in `references/traps.md` applies to
  every install.
- **Linux aarch64**: verified on v1.18.2, and run once on v1.22.2. **Linux x86_64**: verified on
  v1.14.2, and installed on v1.14.6 for the gpu-cuda run. The `kvm` group check applies to every
  fresh host.
- **Intel Mac**: the installer accepts macOS 11 or later on Intel and then stops at the download,
  because no `darwin-x86_64` archive is published for v1.23.0; `preflight.sh` says so.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-10-03 against v1.22.2** on
  Windows 11 Home build 10.0.26200 UBR 9457, where it confirmed. The
  three facts that break a Unix-shaped script are there: the zip unpacks into a nested versioned
  folder, state lives in `%LOCALAPPDATA%\smolvm` and cannot be moved, and a script must never
  capture `machine start` output because it never returns.

## Eval prompts, and what they produced

**1. "Install smolvm on this machine and tell me whether it can actually run a VM."** On macOS
arm64 on v1.23.0: `result=not_installed`, the install, then `result=ready`, `guest_ran=yes`,
`guest_kernel=Linux 6.12.95`, `is_a_vm=yes`, `result=boot_ok`.

**2. "smolvm is installed but every `machine run` fails with `krun_start_enter returned: -22`.
What is wrong?"** Reproduced on macOS on v1.22.2 by installing into a 52-character `HOME`. The
preflight names the cause before any VM is started:

```
socket_path_bytes=106
socket_path_status=too_long
result=blocked
```

and the boot then fails with `krun_start_enter returned: -22 (EINVAL ...)`, whose text blames
disks and device options.

**3. "Set up smolvm somewhere throwaway so it does not touch my existing install, then remove
it."** Install under a scratch `HOME`, then `install.sh --uninstall`; on v1.22.2 it printed
`success: smolvm has been uninstalled`, and `find "$HOME" -iname '*smolvm*'` was empty afterwards.

## Re-verified on v1.23.0

Run 2026-10-04 PT against v1.23.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.0.1 arm64, once. On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the
checks named below ran once, so the Linux stamp stays on its earlier release.

macOS: `result=not_installed` on the empty `HOME`; the installer with no `--version` printed
`Installing version: 1.23.0` and `Checksum verified`, and the pinned command above did the same.
Then `version_status=match`, `result=ready`, `guest_kernel=Linux 6.12.95`, `result=boot_ok` in
15 s and a clean cleanup, 23 s for the whole packet. Eval 2 repeated in a 52-character `HOME`:
`socket_path_bytes=106`, `socket_path_status=too_long`, `result=blocked`, and the boot failed with
the same `-22` text, printed twice. Eval 3 repeated: after an install, one boot and
`--uninstall`, `find` printed nothing.

Linux aarch64: `result=not_installed`, the installer took 1.23.0 with `Checksum verified`, then
`version_status=match` and `result=ready`. A first boot at 1024 MiB took 33 s and one at 2048 MiB
9 s.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) on 2026-10-03 guests above 2048 MiB timed out, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: `result=not_installed` on the empty `HOME`, the installer took the newest release,
`smolvm 1.22.2`, then `result=ready`, `guest_kernel=Linux 6.12.95`, `result=boot_ok` and a clean
cleanup, 41 s for the whole packet. The path trap repeated: a 52 byte `HOME` gave
`socket_path_bytes=106`, `socket_path_status=too_long`, and the boot failed with the same `-22`
text, printed twice because the image seed helper fails first. A default-size machine booted in
under a second once the image was seeded.

Linux aarch64: `result=boot_ok` in 87 s at 2048 MiB, after the seed helper's 30 s timeout and
`WARN no image seed; pulling in the guest`; the readiness trap has the measurement. Linux was last
verified on v1.18.2.

## What was not run

- **Intel Mac.** Nothing.
- **Windows through a script.** The v1.22.2 run on Windows issued the commands on
  `references/windows.md` by hand, and no PowerShell script ships with this packet.
- **The unprivileged Windows symlink path.** The Windows preflight check for Developer Mode or
  `SeCreateSymbolicLinkPrivilege` is written from reading the release's extraction path and from a
  Windows run whose account already held the privilege. The failure it guards against has been
  reported from outside and reproduced by forcing the state, but the unprivileged install itself
  has not been run.
- **Linux x86_64** was verified for install and boot on v1.14.2, and installed on v1.14.6 for the
  gpu-cuda run. The scripts here were re-run on macOS arm64 and Linux aarch64 only.

## Related packets

- `teardown` for the full removal sequence, and for what a leak check must exclude.
- `throwaway-machine` for running untrusted work in a throwaway machine, which assumes this boot.
- `dev-env`, `local-api`, `docker-in-machine`, `gpu-cuda` and `pack` all assume it too.
