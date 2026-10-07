# Teardown traps

The obvious cleanup steps fail here: the obvious assertion gives a false failure, the obvious
reaper matches the wrong process, and killing a wrapper around a run does not stop its machine. Each entry below was hit on a real host.

## `Ctrl-C` on the CLI stops the machine from v1.20.2, and did not before

**On v1.22.2 it does**, measured on macOS arm64 against a clean baseline: `SIGINT` and `SIGKILL`
to the CLI's process group each left neither the CLI nor its `_boot-vm` alive at t+1 s, and
`machine list` said `No machines found`. A killed **wrapper** is the case that still leaves a VM:
the CLI is reparented to PID 1, both processes keep running, and the run is listed as
`running (eph)`. `machine stop --name <id>` ends both and leaves the entry as `stopped (eph)`, still
there 20 s later, until `machine delete --name <id> --force` removes it.

**Before v1.20.2 there was no CLI route to the machine it left behind.** From a clean zero-process
baseline, the VM's two processes were still alive at t+10 s, t+30 s and t+60 s after `SIGINT` to
the CLI, and `SIGKILL` to the CLI left one. Throughout, `smolvm machine list` says
`No machines found` and no VM cache directory exists.

The VM exits only when its own **workload** finishes: a run whose command was `sleep 45` was gone
30 s after the interrupt; one running `sleep 300` was still alive at 60 s. For a throwaway machine running
untrusted code that loops or hangs, the exposure is unbounded.

`scripts/cleanup.sh` is the only way to find it.

**Measured again on v1.18.2, 2026-09-24**, with the wrapper killed and the CLI left alone: on macOS
arm64 the run stayed in `machine list` as `running (eph)` and `machine stop --name` cleared it; on
Linux aarch64 the VM went with the wrapper. Killing the CLI as well took the VM on both.

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

**What works.** On Linux both shapes rename themselves to `libkrun VM`, or to `VM:<hostname>` when
`HOSTNAME` is exported, which no shell can hold, so `scripts/cleanup.sh` matches either in
`/proc/<pid>/comm`, then scopes by argv[2] where it exists and by the executable's path where it
does not. macOS exposes no rename, so the search is scoped by the
executable path under this `HOME` and the parent chain separates a VM from the CLI that started
it. Verified against a live orphan on both hosts.

## Asserting "no machines" immediately after `machine run` fails on a healthy system

A successful `machine run` returns **before** its entry retires. It was observed still listed as
`vm-... unreachable (eph)` immediately after the command returned, and gone by 20 s. This is the
single most likely false failure in a scripted teardown, and it is why `cleanup.sh` waits.

## `machine delete` needs `--force` in a script

**Through v1.16.x**, without `--force` a scripted cleanup printed `Delete machine '<name>'? [y/N]
Cancelled`, exited 0 and **left the machine in place**, while the surrounding script carried on
believing it cleaned up. **On v1.17.0 and later** (#1333) the same call with stdin not a terminal
exits 1:

```
Error: agent operation failed: delete: machine 'smolskill-del' needs confirmation but stdin is not
a terminal; pass --force to delete it, or --cascade to remove it together with any machines
branched from it
```

Measured on v1.18.2 on macOS arm64 and Linux aarch64, 2026-09-24. Pass `--force` either way. A
machine that has been branched additionally needs `--cascade`, which removes the children first.

## A paused machine refuses `stop`

`machine pause` saves the machine's RAM, disks and execution state and stops it, and `machine
list` then shows it as `paused`. **`machine stop` refuses it** with `machine has saved execution;
use resume or delete`, exit 1, because stopping would discard the saved execution, and `machine
start` refuses it with `machine has saved execution; use resume`. `machine delete --force` removes the machine and the saved state. On
v1.18.2 the saved state of a 1024 MiB alpine guest was 70 MB on macOS and 73 MB on Linux, in the
machine's own directory, so it goes with the delete.

## `ls ~/.cache/smolvm/vms/ | wc -l` is not a leak check

On Linux, after `machine create --from` or a checkpoint restore, a `_shared` directory lives
there: the shared pack store. It is cache, not residue. `cleanup.sh` and `verify-clean.sh` both
exclude it. An `--oci-cache` bake writes to `init-layers/` beside `vms/` and to the pack cache,
not here.

## Small leftover VM directories are not necessarily a leak either

`smolvm serve start` prints `Reclaimed 2 dangling VM data dir(es)` on startup and clears them, so
a directory left by a force-killed run is tidied the next time the API server runs.

**A boot that timed out leaves one too.** On v1.18.2 on Linux aarch64, 2026-09-24, seven ephemeral
runs that failed with `agent did not become ready within 30 seconds` left seven directories, each
holding `agent-startup-error.log`, and `verify-clean.sh` reported `vm_dirs=FAIL expected=0
actual=7`. Starting `smolvm serve start` once and stopping it printed `Reclaimed 7 dangling VM data
dir(es)`, and the check then passed. Read `agent-startup-error.log` first if you want to know why
the boot failed.

**`machine stop` on a name that does not exist leaves an empty directory** there on v1.18.2, so a
cleanup that stops every recorded name after `--cascade` removed the children leaves one per child.
They hold nothing; `verify-clean.sh` reports them as `empty_vm_dirs=` and does not fail on them.
**A second stop of the same missing name writes a 12-byte `name` file into it** on v1.22.2, and the
directory then counts as a leak (`vm_dirs=FAIL`). `scripts/cleanup.sh` acts only on names still in
`machine list` for that reason, and one `smolvm serve start` reclaims what an older script left.

## Restored checkpoints stay in the cache

On macOS, `vms/_restore-base` is a clone of the most recently restored checkpoint, kept so the next
restore writes only what differs. It holds that checkpoint's memory and disks, 243 MB after
several restores on v1.18.2, and it stays after every machine and every `.smolcheckpoint` is
deleted; `serve start` does not reclaim it. `checkpoint-unpack`, beside it, is an empty scratch
directory. `verify-clean.sh` excludes both from the leak count and prints `restore_base=present`
with the size. Remove it with `rm -rf` when no restore is running, and treat it like the
checkpoints themselves. Linux aarch64 did not create one.

From v1.22.0 the cache is `vms/_restore-checkpoints`, which keeps the three most recently restored
checkpoints, up to 16 GiB, so jumping back to one clones it instead of rebuilding its RAM. After
several restores on macOS on v1.23.0 it held 258 MB with no machine and no checkpoint left, and
no `_restore-base` was created. `verify-clean.sh` reports it as `restore_cache=present` and does not
count it. `machine create --from` takes `--restore-cache-entries` and `--restore-cache-gib`, and
`--restore-cache-entries 0` turns the cache off.

## A machine whose guest disk failed refuses `delete --force`

A machine restored and started while the host disk was full came up with its guest overlay
failing. With space back, its delete:

```
Error: agent operation failed: stop agent: guest did not confirm filesystem synchronization; left
the VM alive for retry: agent operation failed: shutdown ack: freeze /oldroot/mnt/overlay: I/O error
(os error 5)
```

exit 1, still `running`. `scripts/cleanup.sh --reap` killed its VM process, and `delete --force`
then removed the machine and its directory. `--reap` kills every VM process under this `HOME`.

Zero-byte files named `.<name>.fork-operation.lock` or `.<name>.fork-operation.pause-operation.lock`
stay in the same directory after a machine that was paused or checkpointed is deleted. They are
not directories and the leak check does not count them. On Linux every delete also prints
`WARN unable to lock UID registry; retaining assignment` and still deletes.

## On macOS, do not `rm -rf` the pack cache by hand

`smolvm-pack` can contain `layers-cs` directories that are live `hdiutil` mount points, and `rm`
fails on them with `Resource busy`. The uninstaller detaches them first
(`find ... -name layers-cs -type d -exec hdiutil detach {} -force \;`); do the same if you are
cleaning up manually.

## Pre-existing residue is not yours

Check timestamps and paths before reporting a leak. During the runs recorded here a second VM
belonging to another session was live on the same host, under a different `HOME`;
`cleanup.sh` listed only the one under its own state tree and left the other running, which is
the behaviour you want from anything you let run unattended.
