---
name: dev-env
description: Keeps a persistent smolvm machine with its dependencies already installed and re-enters it cheaply across sessions. Use when a project needs an isolated development environment that survives stop and start; when deciding what belongs in a Smolfile's init versus what has to run on every boot; when a package installed in a machine has vanished after a restart; or when exec answers "the container smolvm-<hash> is not running". Do not use it for untrusted code, which needs a machine that leaves nothing behind (see the throwaway-machine packet), or for running a Docker daemon inside the machine (see docker-in-machine).
---

# A persistent dev machine

Verified on **smolvm v1.22.2** on macOS arm64, 2026-10-03, and on **v1.18.2** on Linux aarch64, 2026-09-24; the Linux runs used
the Smolfile with `memory = 1024`, for the host reason in "Platform arms". Done means a second `start` is fast, skips provisioning, and the packages installed in
the first session are still there.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

The whole use case turns on one fact: **`init` runs once, not on every start**, as
[`smolfile.md`](../smolfile.md) says, and as the docs site (smolmachines.com/docs) says under "When
init runs". `smolvm machine create --help` reads "Run command on every VM start" at v1.22.2;
provisioning that relies on that line is missing on the second boot.

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

Read-only. `restart_after_stop=verified` on macOS and Linux. The script covers macOS and Linux
only; elsewhere it prints `unknown` and a note pointing at `references/windows.md`, where a stopped
machine starts again on v1.14.6 and v1.22.2.

**2. Declare the machine.** `assets/dev.smolfile` is a working starting point, and the one
`verify-persistence.sh` is written against: it asserts the `app` user and the `/app` workdir that
file sets. `examples/python-app/python.smolfile` and `examples/node-app/node.smolfile` in the
repository are plainer examples without them.

```toml
image = "python:3.12-alpine"
net = true
cpus = 2
memory = 2048
volumes = ["./src:/app"]
init = [
  "sh -c \"id -un > /init-ran-as.txt\"",
  "sh -c \"date +%s >> /init-count.txt\"",
  "adduser -D app",
]
user = "app"
workdir = "/app"
```

**3. Create and bring it up.** Run this from the project directory: the Smolfile mounts `./src`,
which is relative to the working directory, and the script creates `./src` there if it is missing.

```bash
scripts/create-dev-machine.sh              # name defaults to smolskill-dev
scripts/create-dev-machine.sh smolskill-myproj ./my.smolfile
```

It creates the machine **with an explicit long-lived workload command**, records the name for
cleanup, starts it, waits for the workload container to answer with a value, and then reports what
actually happened rather than that nothing errored:

```
init_ran=yes
machine_running=yes
workload_ready_after_s=0
workload_ready=yes
init_ran_as=root
exec_user=app
workdir=/app
result=up
```

`init_ran_as=root` with `exec_user=app` is the correct outcome, not a bug: `init` provisions the
machine and runs as root regardless of `user`, while `exec` and `shell` run as `user`.

**4. Work in it.**

```bash
smolvm machine exec  --name smolskill-dev -- pip install --user requests
smolvm machine exec  --name smolskill-dev --user root -- sh -c 'mkdir -p /storage/keep'
smolvm machine shell --name smolskill-dev            # interactive, lands in workdir as `user`
```

**5. Prove it is worth keeping.**

```bash
scripts/verify-persistence.sh
```

It installs a package and records its **version**, seeds one file per filesystem, stops, starts,
and then asserts each value against what it recorded. A version comparison is the point: an import
that does not crash can be satisfied by a system copy and says nothing about your install. It
leaves the machine running.

When the setup is done, `smolvm machine stop --name smolskill-dev` and give the user its name; the
next `machine start` brings it back as it was.

**6. Clean up, when the machine is no longer wanted.** Not at the end of a setup: the machine is the
deliverable, so leave it stopped and tell the user its name.

```bash
scripts/cleanup.sh --purge
```

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

## What `init` and `user` actually do, observed on v1.14.2 and again on v1.22.2

Observed, not inferred:

| question | observed |
|---|---|
| when does `init` run? | on the **first `start`**, not on `create`, and not again |
| second start | prints `Init already completed, skipping N command(s)` |
| which user runs `init`? | **root**, even with `user = "app"` set |
| which user runs `exec` and `shell`? | the Smolfile `user` |
| override per command | `machine exec --user root` works |
| is there `machine start --init`? | **no** |

## What survives a stop and start

| location | survives | why |
|---|---|---|
| pip `--user` packages | yes | under `$HOME`, on the overlay |
| `$HOME/...` files | yes | overlay |
| files written at `/` | yes | overlay |
| `/tmp` | **no** | `tmpfs` |
| `/storage/...` | yes | the ext4 disk itself |

The root filesystem is an overlay whose upper layer lives on the machine's ext4 disk, which is why
writes to `/` persist while `tmpfs` mounts do not.

## Traps

Full detail in `references/traps.md`. The ones that cost the most:

- **`init` runs once.** `machine create --help` reads "Run command on every VM start" at
  v1.22.2. Anything that must hold on every boot, a bind mount above all, runs
  in the command that needs it.
- **Give a machine you `exec` into a long-lived workload.** Without one, an `exec` right after
  `start` can answer ``the container `smolvm-<hash>` is not running`` instead of running.
- **`machine shell` does not start a stopped machine** on v1.22.2, while its help says "starts it
  if stopped".
- **A machine that runs Tailscale or another carrier NAT VPN needs `--guest-subnet` at create**,
  which a Smolfile cannot carry:
  `smolvm machine create --name smolskill-dev -s dev.smolfile --guest-subnet 10.200.0.0/30`.
- `create` is instant and proves nothing, and a host `volumes` mount was not writable by the `app`
  user.

## Security defaults, and why they are the defaults

- **`user` in the Smolfile is what your workload runs as, and it is not root.** `init` running as
  root is the provisioning step, deliberately separated from the workload's identity. Keep them
  separate rather than setting `user = "root"` to make a mount writable: the mount carries host
  ownership, and running the workload as root to reach it hands root in the guest everything the
  mount exposes on the host.
- **A `volumes` mount is host authority handed to the guest**, so mount the narrowest directory
  that works and prefer `:ro` for anything the machine only reads. Treat root in the guest as
  untrusted, as the [security model](../security-model.md) says: every forwarded mount, port and
  network permission becomes part of the workload's authority.
- **`net = true` is outbound access for the whole machine.** A dev machine that only needs a
  package index does not need general egress; `--allow-host` scopes it.
- **These scripts wrap the public CLI only.** They edit no smolvm configuration and nothing under
  `~/.smolvm`, and cleanup deletes only names it recorded under the `smolskill-` prefix.

## Platform arms

- **Linux aarch64**: the scripts were run here on v1.18.2 with the Smolfile's memory at 1024 MiB,
  and once on v1.22.2 at 1024. At 2048 on v1.18.2 the restart failed with `agent did not become
  ready within 30 seconds`: on a small or busy host lower `memory` before suspecting smolvm, and
  check the mount source first (the `install` packet's traps have the numbers).
- **macOS arm64**: the scripts were run here on v1.22.2 as shipped, and every check passed.
- **Linux x86_64**: verified on v1.14.2 on an NVIDIA A10 cloud host, not re-run since.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-10-03 against v1.22.2** on
  Windows 11 Home build 10.0.26200 UBR 9457. Create, three stops and three starts, with a marker read back after each start: **a
  stopped machine starts again and its state survives**, as on v1.14.6, where on v1.14.2 it did
  not. That page also carries the WHP device ceiling a Windows preflight needs through v1.22.2:
  four `-v` mounts, three when a port is published.
- **`init` after a checkpoint restore**: not verified anywhere.

## Eval prompts, and what they produced

**1. "Set me up a Python dev machine I can come back to, and prove the packages survive a
restart."** On macOS arm64: the step 3 output above, on v1.22.2.

Then, after the stop and start, `verify-persistence.sh`:

```
workload_ready_after_s=0
installed_version=2.34.2
  Init already completed, skipping 3 command(s)
workload_ready_after_s=0
init_ran_once=ok (yes)
package_version=ok (2.34.2)
home_file=ok (SURVIVES)
storage_file=ok (SURVIVES)
tmp_file=ok (WIPED)
exec_user=ok (app)
workdir=ok (/app)
result=persistent
```

**2. "My bind mount is gone after I restarted the machine. It is right there in `init`."**

`init` ran once. The second start reports it, on v1.22.2 as in eval 1:

```
Init already completed, skipping 3 command(s)
```

There is no `machine start --init`, so the mount has to be re-applied by the command that needs
it. `docker-in-machine` is the packet built entirely around this.

**3. "`smolvm machine exec` just told me the container is not running, but the machine is
running."**

On v1.14.2, reproduced deliberately by creating the same machine without a workload command, then running 20
execs, on Lima:

```
 3: the container `smolvm-e51bb94127b751bf` is not running
failures=1/20
 4: the container `smolvm-32edffb50eaf0d20` is not running
failures_after_restart=1/20
```

and with the explicit long-lived workload `scripts/create-dev-machine.sh` passes:

```
failures=0/20
failures_after_restart=0/20
```

The changing hash is the tell: the workload container is being relaunched between execs.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) guests above 2048 MiB timed out on 2026-10-03, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: `result=up` with `init_ran_as=root` and `exec_user=app`, then `result=persistent`,
`package_version=ok (2.34.2)`, `tmp_file=ok (WIPED)`. `machine create --help` describes `--init` as
running "on every VM start", `machine shell` on a stopped machine answered `is not running. Use
'smolvm machine start ...' first` while its help says it starts one, and the exec race gave 0 of 20.

Linux aarch64 at `memory = 1024`: `result=persistent`, the exec race 0 of 20. Linux was last
verified on v1.18.2, at `memory = 1024`.

## What was not run

- **Windows beyond the restart.** The v1.22.2 run covered create, three stops and starts, the
  marker and `init` running once; the WHP device ceiling was confirmed by the `install`
  packet's Windows run on 2026-10-03.
- **Linux x86_64.**
- **`init` after a checkpoint restore.** Nowhere, on any platform.
- **The `USER` interaction still settling.** `init` runs as root on v1.22.2, and whether the
  image's own `USER` still governs it in some paths is open as
  [smolvm#1189](https://github.com/smol-machines/smolvm/issues/1189). Nothing here tested an image
  with a `USER` line.

## Related packets

- `install` for the boot this assumes, and `teardown` for the cleanup script.
- `docker-in-machine` for the clearest case of the `init`-runs-once trap.
- `pack` for turning the machine this packet builds into a portable artifact.
