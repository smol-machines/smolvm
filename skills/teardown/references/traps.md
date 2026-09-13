# Teardown traps

Almost every cleanup fact in smolvm is counterintuitive: the obvious assertion gives a false
failure, the obvious reaper matches the wrong process, and the command a user reaches for when a
run misbehaves does not stop the machine. Each entry below was hit on a real host.

## `Ctrl-C` does not stop the machine

**And there is no CLI route to the machine it leaves behind.** From a clean zero-process
baseline, the VM's two processes were still alive at t+10 s, t+30 s and t+60 s after `SIGINT` to
the CLI, and `SIGKILL` to the CLI left one. Throughout, `smolvm machine list` says
`No machines found` and no VM cache directory exists.

The VM exits only when its own **workload** finishes: a run whose command was `sleep 45` was gone
30 s after the interrupt; one running `sleep 300` was still alive at 60 s. For a sandbox running
untrusted code that loops or hangs, the exposure is unbounded.

`scripts/cleanup.sh` is the only way to find it.

## Three reapers that look right, and what each one misses

**`pgrep -f _boot-vm` is too wide.** Any process whose command line contains that string matches,
including the cleanup script itself. That produced a phantom "1 orphan survived" result and a
confounded baseline that briefly made `Ctrl-C` look clean.

**`readlink /proc/<pid>/exe` is unreliable in both directions.** For the exec'd VM child the
process is not dumpable, so `/proc/<pid>/exe` is root-owned and `readlink` returns
`Permission denied` to the user who started it:

```
$ ls -l /proc/51706/exe
ls: cannot read symbolic link '/proc/51706/exe': Permission denied
```

On v1.14.6 it is readable for the forked child, which makes it useful for scoping and still no
good for finding.

**Matching `argv[1] == "_boot-vm"` is exact, and blind to half the VMs.** There are two shapes:

| route | child | argv[1] | carries its boot config |
|---|---|---|---|
| plain `machine run` | exec'd | `_boot-vm` | yes, in argv[2] |
| pack-run (`--oci-cache`, or any `init`) | **forked, never exec'd** | inherited, so `machine` | **no** |

The forked child inherits the parent's whole command line, so nothing in its argv marks it as a
VM. Measured on v1.14.6 on Ubuntu 24.04 aarch64 with two such orphans alive at 234 MB each, the
argv-only scanner reported `vm_processes=none` and `result=clean`. **That is the worst of the
outcomes: a false clean.**

**What works.** On Linux both shapes rename themselves to `libkrun VM`, which no shell can hold,
so `scripts/cleanup.sh` matches `/proc/<pid>/comm`, then scopes by argv[2] where it exists and by
the executable's path where it does not. macOS exposes no rename, so the search is scoped by the
executable path under this `HOME` and the parent chain separates a VM from the CLI that started
it. Verified against a live orphan on both hosts.

## Asserting "no machines" immediately after `machine run` fails on a healthy system

A successful `machine run` returns **before** its entry retires. It was observed still listed as
`vm-... unreachable (eph)` immediately after the command returned, and gone by 20 s. This is the
single most likely false failure in a scripted teardown, and it is why `cleanup.sh` waits.

## `machine delete` prompts and defaults to No

Without `--force` a scripted cleanup prints `Delete machine '<name>'? [y/N] Cancelled` and
**leaves the machine in place**, while the surrounding script carries on believing it cleaned up.
A machine that has been branched additionally needs `--cascade`, which removes the children first.

## `ls ~/.cache/smolvm/vms/ | wc -l` is not a leak check

Once `--oci-cache` has been used, a `_shared` directory lives there holding the baked images
(379 MB after one Python image). It is the cache, not residue. `cleanup.sh` and
`verify-clean.sh` both exclude it.

## Small leftover VM directories are not necessarily a leak either

`smolvm serve start` prints `Reclaimed 2 dangling VM data dir(es)` on startup and clears them, so
a directory left by a force-killed run is tidied the next time the API server runs.

## On macOS, do not `rm -rf` the pack cache by hand

`smolvm-pack` can contain `layers-cs` directories that are live `hdiutil` mount points, and `rm`
fails on them with `Resource busy`. The uninstaller detaches them first
(`find ... -name layers-cs -type d -exec hdiutil detach {} -force \;`); do the same if you are
cleaning up manually.

## Pre-existing residue is not yours

Check timestamps and paths before reporting a leak. During the runs behind this packet a second
VM belonging to another session was live on the same host, under a different `HOME`;
`cleanup.sh` listed only the one under its own state tree and left the other running, which is
the behaviour you want from anything you let run unattended.

## Nothing in the docs describes cancellation or teardown

`guides/agent-sandboxes-ci.md` is the page a sandbox author would read and it never mentions how
to stop a run, which matters given the `Ctrl-C` behaviour above.
