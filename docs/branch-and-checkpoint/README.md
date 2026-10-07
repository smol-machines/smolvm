# Branching and checkpointing

Two ways to reuse a machine's state. A **branch** is a child started from a running machine's
memory and disk, tied to that source; a **checkpoint** is a file you restore later, here or on
another host. [Branching](../branching.md), [incremental checkpoints](../incremental-checkpoints.md)
and [pause and resume](../pause-resume.md) are the reference for each operation. This packet runs
them together and records what they did on a release.
[Moving a running machine from a Mac to Linux](../mac-to-linux.md) has its own page.

`SKILL.md` is the agent procedure: scheduled captures with retention, restores of any generation,
pause and resume, and branch points kept as checkpoints, with the scripts that run them.
`references/scheduling.md` puts a capture under cron, systemd or launchd, and
`references/platforms.md` says what each host did.

## smolvm has no scheduler and no retention

Periodic checkpoints are an external timer running one capture at a time per machine, each to a
new output name, with old directories deleted only after the new one is published and
`machine checkpoint-prune --store <dir>` run afterwards. `--keep` on directories frees nothing that
a kept checkpoint still retains, so bound `--history` too: with two directories kept and
`--history 2`, a store grew 59, 76, 95 and 114 MB over four captures.

## Restores are copy-on-write, and smolvm keeps copies

A restored machine's disks are layered over the checkpoint's rather than copied: on macOS three
restores of one checkpoint cost about 29 MB of disk each while `du` reported five times that, and
on Linux each restored machine holds small `qcow2` layers over the checkpoint's disks.

smolvm also keeps restored checkpoints in its VM cache so the next restore writes only what
differs: `vms/_restore-base` on macOS before v1.22.0, and from v1.22.0 `vms/_restore-checkpoints`,
the last three restored, 258 MB after this packet's procedure on macOS on v1.23.0. Both hold the
checkpoint's memory and outlive every machine and checkpoint file, so remove them when you remove
the checkpoints.

## Branchability is decided at start

```bash
smolvm machine start  --name source --branchable
smolvm machine branch --from source --name child
```

A machine started without `--branchable` refuses to branch, and the message says branchability is
decided at start time and cannot be turned on for a machine that is already running. There is no
`machine create --branchable`: it is a `start` flag. On macOS a stored checkpoint, `--store`, needs
the same thing, and the error when the source was not started that way, `deferred durable save
requires file-backed guest RAM` on v1.22.2, names neither the flag nor the precondition. Before
v1.20.0 macOS also refused a checkpoint file and a pause, with `guest RAM has no file-backed
regions`. Linux checkpoints and pauses without it.

## Keeping the branch point

A branch's captured state stays on the host that made it and cannot be exported, so take a
checkpoint at the same point when the starting state has to outlive the children. For a batch,
that point is the source parked in `smolvm-branch-ready`, as [branching](../branching.md)
describes: a checkpoint taken there holds exactly what every child starts from. Restoring it does
not give back a parked source, though: the helper releases on start and runs the child program
with an empty `SMOLVM_BRANCH_NAME`, so branch a restored branch point with single `--name`
branches.

## Restoring a checkpoint

The restore path is `machine create --from`. **There is no `machine restore` subcommand.** A
restored machine packs like any other, and carries its rootfs.

## Packing a branch

A branched machine packs from v1.16.1 on, and the artifact carries both the state it inherited and
the state written after the branch. It has to be stopped first. See [pack](../pack/README.md).
