# Sandbox traps

## Contents

- Ctrl-C does not stop the machine, and which route that applies to
- Assert no machines left only after a wait
- A network-off run that dies on the manifest means the bake was skipped
- A blocked host looks like a DNS bug, not a policy denial
- The bake helper ignores `--mem`
- `machine egress-events` cannot inspect an ephemeral run
- Counting orphans: why `pgrep -f`, `readlink` and `_boot-vm` alone all fail
- What is cache and what is residue
- There is no way to list what has been baked

## Ctrl-C does not stop the machine, and which route that applies to

**On the offline route this is the whole reason the packet has a cancel script.**
`machine run` with `--oci-cache` or `--init` takes the pack-run boot path, which on Unix forks a
session leader that never execs, so the VM child is detached with no parent-death arming. Interrupt
the CLI and the VM keeps running, `machine list` reports `No machines found`, no VM cache directory
exists, and there is no CLI route to what is still running. It exits only when the untrusted
workload does, which for code that hangs or loops is unbounded. This is
[smol-machines/smolvm#1193](https://github.com/smol-machines/smolvm/issues/1193).

**On the plain path it does not happen**, and that is worth knowing rather than assuming the worst
everywhere. Measured on Ubuntu 24.04 aarch64 on 2026-09-08: a `machine run` with no `--oci-cache`,
one mount and a `sleep 600` workload, sent `SIGINT` on the CLI itself, left `machine list` empty
and **no VM process at all**. The plain path spawns an exec'd `_boot-vm` that dies with the CLI.

So:

| route | Ctrl-C on the CLI | cancel with |
|---|---|---|
| offline (`--oci-cache`) | VM survives, invisible to `machine list` | `scripts/cleanup.sh --cancel` |
| network-on (no `--oci-cache`) | VM dies with the CLI (verified on Linux) | either |

**Do not rely on the second row to cancel a sandbox.** `run.sh` records the VM's pid on both
routes because the difference is a boot-path detail that can change between releases, and because
interrupting the *wrapper* rather than the CLI leaves the CLI and its VM running on either route,
which was observed on both hosts here.

## Assert no machines left only after a wait

A successful `machine run` returns **before** its ephemeral entry retires. Asserting an empty
machine list immediately fails on a healthy host, and it is the single most likely false failure in
a scripted sandbox. `scripts/cleanup.sh` waits before asserting.

## A network-off run that dies on the manifest means the bake was skipped

```
Error: fetching manifest docker.io/library/python:3.12-alpine: ... network is unreachable
Hint: networking is disabled. Add --net to enable image pulls
```

**An ordinary earlier pull does not make a later run offline-capable**: the runtime still resolves
the tag through the registry. Bake the image with `scripts/bake.sh` instead.

The CLI's own hint points at re-opening the network, which is the opposite of what a sandbox wants.
Adding `--net` here is how an offline sandbox quietly becomes a networked one.

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

**What works.** On Linux both shapes rename themselves to `libkrun VM`, which no shell can hold,
so `scripts/cleanup.sh` matches `/proc/<pid>/comm` and then scopes by argv[2] when it is there and
by the executable's path when it is not. macOS exposes no rename, so there the search is scoped by
the executable path under this `HOME` and the parent chain separates a VM from the CLI that
started it. Verified against a live orphan on both hosts: the same sequence now reports
`vm_process=... forked-under ...` and `result=vms_still_running`, and `--cancel` clears it.

## What is cache and what is residue

`ls ~/.cache/smolvm/vms/ | wc -l` is not a leak check. Two separate caches exist and neither is
residue:

- `vms/_shared`, the image store the runbooks describe.
- **the pack cache**, `~/Library/Caches/smolvm-pack` on macOS and `~/.cache/smolvm-pack` on Linux.
  On v1.14.2 on macOS a bake of one alpine image landed **here** and produced no `_shared` at all:
  114 MB in the pack cache, `vms/_shared` absent. Observed 2026-09-08.

`scripts/cleanup.sh` reports both and keeps both. Deleting them costs you the offline route, and
the next bake pays for it again.

Leftover VM directories are also not necessarily a leak: `smolvm serve start` prints
`Reclaimed N dangling VM data dir(es)` on startup and clears them.

## There is no way to list what has been baked

`smolvm machine images` requires `--name` and reports one machine's images, so cache state is not
observable. If a run unexpectedly pulls, you cannot inspect the cache to find out why. The
`used_host_cache` line from `scripts/run.sh` is the only signal you get, which is why it is asserted
rather than printed.
