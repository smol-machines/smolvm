# Throwaway machine traps

## Contents

- Ctrl-C does not stop the machine, and which release and route that applies to
- Assert no machines left only after a wait
- A network-off run that dies on the manifest means the bake was skipped
- A blocked host looks like a DNS bug, not a policy denial
- The bake helper ignores `--mem`
- A guest that runs a VPN loses its gateway and resolver
- `machine egress-events` cannot inspect an ephemeral run
- Counting orphans: why `pgrep -f`, `readlink` and `_boot-vm` alone all fail
- What is cache and what is residue
- There is no way to list what has been baked

## Ctrl-C does not stop the machine, and which release and route that applies to

**On v1.20.2, interrupting the CLI ends the VM; interrupting `run.sh` does not.** Measured
2026-09-29 on macOS 27.0.1 arm64 and Ubuntu 24.04 aarch64, a `sleep 600` workload, watching the VM
pid itself:

| what was interrupted | macOS arm64 | Linux aarch64 |
|---|---|---|
| the CLI, Ctrl-C, offline or network-on | VM gone within 1 s | VM gone within 1 s |
| the CLI, `SIGKILL`, offline or network-on | VM gone within 1 s | VM gone within 1 s |
| `run.sh`'s process group, Ctrl-C, offline | CLI and VM keep running | CLI and VM keep running |
| `run.sh`'s process group, Ctrl-C, network-on | VM gone | VM keeps running |
| `run.sh` alone, `SIGTERM`, either route | CLI and VM keep running | CLI and VM keep running |

`cleanup.sh --cancel --purge` cleared every survivor with `result=clean`. The wrapper rows are
`run.sh`'s own doing: it starts the CLI with `&`, and a non-interactive shell starts a background
command with `SIGINT` ignored. On macOS the same cached run backgrounded by `bash -c '... & wait'`
kept its CLI and VM after `SIGINT`, and with `SIGINT` reset to the default before the exec both were
gone.

**Before v1.20.2, on the offline route the CLI itself is no better, and this is the reason the
packet has a cancel script.**
`machine run` with `--oci-cache` or `--init` takes the pack-run boot path, which on Unix forks a
session leader that never execs, so the VM child is detached with no parent-death arming. Interrupt
the CLI and the VM keeps running, `machine list` reports `No machines found`, no VM cache directory
exists, and there is no CLI route to what is still running. It exits only when the untrusted
workload does, which for code that hangs or loops is unbounded. This is
[smol-machines/smolvm#1193](https://github.com/smol-machines/smolvm/issues/1193), fixed in v1.20.2
by #1467: the forked child now exits when its CLI does.

**On the plain path it does not happen**, and that is worth knowing rather than assuming the worst
everywhere. Measured on Ubuntu 24.04 aarch64 on 2026-09-08: a `machine run` with no `--oci-cache`,
one mount and a `sleep 600` workload, sent `SIGINT` on the CLI itself, left `machine list` empty
and **no VM process at all**. The plain path spawns an exec'd `_boot-vm` that dies with the CLI.

So, before v1.20.2:

| route | Ctrl-C on the CLI | cancel with |
|---|---|---|
| offline (`--oci-cache`) | VM survives, invisible to `machine list` | `scripts/cleanup.sh --cancel` |
| network-on (no `--oci-cache`) | VM dies with the CLI (verified on Linux) | either |

On v1.18.2 the network-on route was measured again with the **wrapper** killed and the CLI left
alone: the run stayed in `machine list` as `running (eph)` on macOS arm64 and on Linux aarch64, and
`scripts/cleanup.sh --cancel` killed the recorded pid on both.

**Do not rely on an interrupt to cancel a run.** `run.sh` records the VM's pid on both routes
because the difference is a boot-path detail that has changed between releases, and because
interrupting the *wrapper* rather than the CLI leaves the CLI and its VM running, on v1.20.2 as
before.

## Assert no machines left only after a wait

A successful `machine run` returns **before** its ephemeral entry retires. Asserting an empty
machine list immediately fails on a healthy host, and it is the single most likely false failure in
a scripted run. `scripts/cleanup.sh` waits before asserting.

## A network-off run that dies on the manifest means the bake was skipped

```
Error: fetching manifest docker.io/library/python:3.12-alpine: ... network is unreachable
Hint: networking is disabled. Add --net to enable image pulls
```

**An ordinary earlier pull does not make a later run offline-capable**: the runtime still resolves
the tag through the registry. Bake the image with `scripts/bake.sh` instead.

The CLI's own hint points at re-opening the network, which is the opposite of what an isolated run wants.
Adding `--net` here is how an offline run quietly becomes a networked one.

## A blocked host looks like a DNS bug, not a policy denial

With `--allow-host example.com`, reaching `pypi.org` fails as `wget: bad address 'pypi.org'`.
Nothing says "denied by policy". Do not spend time debugging the guest's resolver.

## The bake helper ignores `--mem`

The bake runs in a helper machine named `init-bake-<hash>-<pid>` which takes the **default** memory,
8192 MiB, whatever `--mem` you passed to the outer command. Confirmed on Ubuntu 24.04 aarch64 on
2026-09-08 by reading `machine ls --json` while a bake was in flight.

**On a host that cannot boot a VM that large, the bake can never succeed and the error names
neither the helper nor its memory:**

```
Error: config operation failed: init-layer bake:
  `smolvm machine start --name init-bake-f60a20a837dc1a34-68696` failed (exit status: 1):
  Error: agent operation failed: start machine: agent operation failed: wait for ready:
  agent did not become ready within 30 seconds
```

That is exactly the message a loaded host produces, so it invites the wrong diagnosis.
`scripts/bake.sh` runs a 2048 MiB control boot on failure and tells you which of the two it is.

`SMOLVM_AGENT_READY_TIMEOUT_SECS` does not help: the string is in the binary, but the failure is in
the inner `machine start`, which uses the hard-coded 30 s limit. Verified by setting it to 180 and
watching the bake fail at 30 s anyway.

## A guest that runs a VPN loses its gateway and resolver

A virtio-net guest's link is `100.96.0.0/30` by default: the guest is `.2`, and the gateway and
the resolver are both `.1`. `--allow-host` and `--allow-cidr` select virtio-net, so every run
run that grants egress gets that link. A plain `--net` run uses TSI and has no such link, which
was observed and not tested against a VPN. Tailscale and other carrier NAT VPNs claim `100.64.0.0/10`, which contains it, and route
it into their own device.

Measured on v1.18.2 on macOS arm64 and Linux aarch64, 2026-09-24, by adding in the guest what
Tailscale adds: `ip rule add to 100.64.0.0/10 lookup 52 prio 5270` and a table 52 route for
`100.64.0.0/10` into a dummy device.

| link | `ip route get 100.96.0.1` | lookup | fetch |
|---|---|---|---|
| default, `--allow-host example.com` | `dev ts0` | `bad address 'example.com'` | failed |
| `--guest-subnet 10.200.0.0/30`, same routes | not used | resolved | fetched |

With the flag the guest is `10.200.0.2/30` and the gateway and resolver are `10.200.0.1`. Three
things to know about it: **it implies `--net`**, so it does not belong on the offline route; it
requires virtio-net, and `--net-backend tsi` with it is refused with `--guest-subnet requires the
virtio-net backend`; and a range inside `100.64.0.0/10` is accepted without a warning, which
brings the clash back.

## `machine egress-events` cannot inspect an ephemeral run

It takes `--name` and defaults to a machine called `default`, so it applies to named machines. An
ephemeral run's machine is gone before you can name it, so egress denials from a `machine run` are
not retrievable this way.

## Counting orphans: why `pgrep -f`, `readlink` and `_boot-vm` alone all fail

Three reapers that look right. Each misses a different thing, and the third is the one that
matters here.

`pgrep -f _boot-vm` matches any process whose command line contains that string, including the
script doing the counting, so it reports orphans that do not exist.

`readlink /proc/<pid>/exe` is unreliable in the other direction. For the **exec'd** VM child it
returns `Permission denied` to the user who started it, so a reaper built on it reports nothing.
On v1.14.6 it is readable for the **forked** child, which makes it useful for scoping but not for
finding.

**Matching `argv[1] == "_boot-vm"` is exact, and still blind to the route this packet uses by
default.** There are two VM process shapes:

| route | child | argv[1] | carries its boot config |
|---|---|---|---|
| plain `machine run` | exec'd | `_boot-vm` | yes, in argv[2] |
| pack-run (`--oci-cache`, or any `init`) | **forked, never exec'd** | inherited, so `machine` | **no** |

The forked child inherits the parent's whole command line, so nothing in its argv says it is a VM.
Measured on v1.14.6 on Ubuntu 24.04 aarch64: with two orphaned pack-run VMs alive at 234 MB each,
`cleanup.sh` reported `vm_processes=none` and `result=clean`, and `run.sh` had recorded
`vm_pid=not_observed`. **The reaper was blind to exactly the path that survives an interrupt**,
which is the pack-run path, and sighted only on the path that does not.

**What works.** On Linux both shapes rename themselves to `libkrun VM`, or to `VM:<hostname>` when
`HOSTNAME` is exported, which no shell can hold, so `scripts/cleanup.sh` matches either in
`/proc/<pid>/comm` and then scopes by argv[2] when it is there and by the executable's path when it
is not. macOS exposes no rename, so there the search is scoped by
the executable path under this `HOME` and the parent chain separates a VM from the CLI that
started it. Verified against a live orphan on both hosts: the same sequence now reports
`vm_process=... forked-under ...` and `result=vms_still_running`, and `--cancel` clears it.

On v1.20.2 a forked VM exits with its CLI, so an orphan of that shape comes from an older release
or from a CLI that is still running, as after an interrupted `run.sh`. The scan still catches it,
observed 2026-09-29 on both hosts. On macOS it also lists that CLI, reparented to launchd, as
`orphaned-under`; `--cancel` kills only the recorded VM, and the CLI then exits with it.

## What is cache and what is residue

`ls ~/.cache/smolvm/vms/ | wc -l` is not a leak check. A bake fills two separate caches and
neither is residue:

- `init-layers/`, beside `vms/` in the smolvm cache, where a bake writes its layers.
- **the pack cache**, `~/Library/Caches/smolvm-pack` on macOS and `~/.cache/smolvm-pack` on Linux,
  where a cached run extracts them. On v1.14.2 on macOS a bake of one alpine image landed **here**:
  114 MB in the pack cache, `vms/_shared` absent. Observed 2026-09-08.

`scripts/cleanup.sh` reports both and keeps both. Deleting them costs you the offline route, and
the next bake pays for it again. `vms/_shared` is a third store, the shared pack store (Linux,
after `machine create --from` or a checkpoint restore); it is cache too, and the leak count
excludes it.

Leftover VM directories are also not necessarily a leak: `smolvm serve start` prints
`Reclaimed N dangling VM data dir(es)` on startup and clears them.

## There is no way to list what has been baked

`smolvm machine images` requires `--name` and reports one machine's images, so cache state is not
observable. If a run unexpectedly pulls, you cannot inspect the cache to find out why. The
`used_host_cache` line from `scripts/run.sh` is the only signal you get, which is why it is asserted
rather than printed.
