---
name: branch-and-checkpoint
description: Saves a running smolvm machine as checkpoints on a schedule, keeps a bounded history, restores any generation in it, pauses and resumes machines without losing running processes, and branches a warm machine into children with a checkpoint of the exact point they started from. Use when a machine's state has to survive the machine; when an agent or a job needs to roll back; when checkpoints must be taken periodically, since smolvm has no scheduler or retention of its own; when fanning a prepared machine out into workers; or when a checkpoint, a pause or a branch fails with an error that names none of its preconditions. Do not use it to ship an environment to another host as a file, which is the pack packet, or for state that only has to survive a stop and start, which is the dev-env packet.
---

# Checkpoints, restores, pauses and branches

Verified on **smolvm v1.23.0** on macOS arm64, 2026-10-04, and on **v1.18.2** on Linux aarch64, 2026-09-24. Done means a restore
brings back both the disk and the memory you left, the schedule keeps exactly the checkpoints you
asked for and no fewer, and every child of a branch starts from a state you still hold as a
checkpoint after the children are gone.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

`README.md` says what each of these operations is. This file is how to run them, and the traps.

**Three facts shape everything here.**

- **smolvm has no scheduler and no retention.** `scripts/checkpoint.sh` is the one capture a timer
  runs, with the rules the engine asks a scheduler to follow built in; `references/scheduling.md`
  puts it under cron, systemd or launchd.
- **A branch's captured state stays on this host and cannot be exported.** So a branch point is
  paired with a checkpoint taken at the same moment, which is the copy you keep.
- **`--branchable` at `start` decides what a machine can do later.** A branch source needs it on
  every host. On macOS a stored capture, which is what the scripts here take, needs it too, and the
  error when it was not, `deferred durable save requires file-backed guest RAM` on v1.22.2, names
  neither the flag nor the operation. Before v1.20.0 macOS also refused a checkpoint file and a
  pause without it, with `guest RAM has no file-backed regions`. Linux checkpoints and pauses
  without it. The scripts always start with it.

## Procedure

```
- [ ] 1. preflight.sh               read result= and store_space_ok=
- [ ] 2. create-source.sh           a machine with state in RAM and on disk
- [ ] 3. checkpoint.sh / schedule.sh   captures, with retention
- [ ] 4. restore.sh                 any generation, into a new machine
- [ ] 5. pause and resume           the restored machine, or any branchable one
- [ ] 6. branch-point.sh            children plus a checkpoint of where they started
- [ ] 7. cleanup.sh                 machines, checkpoints, and smolvm's restore cache
```

**1. Preflight.** Read-only.

```bash
scripts/preflight.sh --store ./store
```

It checks that this binary has `--store`, `--history`, `checkpoint-log`, `pause` and restore
`--at`, says whether this host needs `--branchable`, and reports `scheduler=builtin_none` and
`retention=builtin_none` so nobody goes looking for them. `store_space_ok=no` blocks: a capture
into a full disk publishes nothing, and a machine restored while the disk was full was left with
guest I/O errors that stopped it being deleted normally.

**2. A source with state you can check.**

```bash
scripts/create-source.sh smolskill-src                 # for checkpoints and restores
scripts/create-source.sh smolskill-bp --branch-ready   # for a batch branch
```

The workload writes a counter into `/tmp` every second, which is tmpfs and so RAM, and a marker to
`/root/setup.txt` on disk. A restore that brings the counter back proves memory came back, not only
the disk. `--branch-ready` makes the workload park in `smolvm-branch-ready` after its setup, which a
batch branch waits for.

**Or the user's own machine.** Name it with `--name` in the steps below. On macOS, if it was
started without `--branchable`, the first capture fails with `deferred durable save requires
file-backed guest RAM` on v1.22.2 or `guest RAM has no file-backed regions` before v1.20.0, and the
only fix is a restart with the flag:

```bash
smolvm machine stop  --name worker
smolvm machine start --name worker --branchable
```

That restart is a normal stop and start: disk state survives, and anything in RAM or `/tmp` is
lost, once. Say so to the user before doing it. Every start of that machine needs the flag from
then on for it to stay checkpointable.

A capture also refuses a machine with resources bound to this host: a host mount (`-v`), a
published socket, a remote volume, a host secret reference, custom DNS, a named network, a GPU,
CUDA, Rosetta, `--ssh-agent` or a Docker socket. The error, `the initial portable checkpoint
profile does not support ...; stop or detach these resources before capture`, names which.

**3. Capture, once or on a schedule.**

```bash
scripts/checkpoint.sh --name smolskill-src --store ./store --keep 6 --history 2
scripts/schedule.sh   --name smolskill-src --store ./store --every 10 --times 4 --keep 2 --history 2
```

Each capture goes to a new directory named `<machine>-<label>-<UTC time>.smolcheckpoint` beside the
store, or in the directory `--out <dir>` names, which has to be on the same filesystem as the
store. It is judged published only when `checkpoint-log` lists it as `(this checkpoint)`, and only
then are the oldest beyond `--keep` deleted and the store pruned. A capture started while another
of the same machine runs exits 3 with `result=skipped`. `schedule.sh` is for a session you are
watching; a schedule that outlives it is `checkpoint.sh` under a system timer,
`references/scheduling.md`.

```
run=1 rc=0 took_s=2 ... kept=1 store_size= 59M result=captured
run=2 rc=0 took_s=5 ... kept=2 store_size= 76M result=captured
run=3 rc=0 took_s=2 ... kept=2 store_size= 95M result=captured
run=4 rc=0 took_s=1 ... kept=2 store_size=114M result=captured
captures_ok=4
captures_failed=0
longest_capture_s=5
result=schedule_ok
```

That is the v1.18.2 run. Ten seconds is for watching it work; a schedule uses minutes,
`references/scheduling.md`.

**Set the interval from `longest_capture_s`, not from the pause.** The source pauses for a few
hundredths of a second; the command takes seconds, because retained RAM is hashed and compressed
after the source resumes. **`--keep` alone does not bound the disk**: every kept checkpoint also
retains `--history` earlier generations, 32 by default, so the store above kept growing with two
directories kept. Bound both.

**4. Restore, any generation.**

```bash
smolvm machine checkpoint-log ./smolskill-src-ckpt-<time>.smolcheckpoint
scripts/restore.sh --from <checkpoint> --name smolskill-old --at '~2'
scripts/restore.sh --from <checkpoint> --name smolskill-new
```

`~0` is the checkpoint itself and `~N` is N generations back along its history. `restore.sh`
takes only a name starting with `smolskill-`, so cleanup can find it, and refuses any other with
`name must start with smolskill- so cleanup.sh will delete it`; to restore under a name the user
chooses, run `smolvm machine create --name <name> --from <checkpoint> --at '~N'` and then
`smolvm machine start --name <name> --branchable` yourself. The restore path is
`machine create --from`; **there is no `machine restore`**. A restored machine takes its own name as
its hostname, and its disks are copy-on-write over what the checkpoint holds, so a restore costs
about 29 MB of real disk on macOS for a 243 MiB checkpoint while `du` reports five times that.

**5. Pause and resume.**

```bash
smolvm machine pause  --name smolskill-new
smolvm machine resume --name smolskill-new
```

Pause saves RAM, disks and the running execution and stops the machine; resume brings the same
execution back under the same name. Check a value the workload holds in memory: on both hosts the
counter read 31 before the pause and 34 and 33 after the resume, so it continued where it stopped
and did not run while paused. A paused machine refuses `stop` and `start`; resume it or delete it.
A resume that fails keeps the saved state, and a later resume of the same machine succeeded.

**6. Branch, and keep the branch point.**

```bash
scripts/branch-point.sh --from smolskill-bp --store ./store --count 2 --name-prefix smolskill-w
scripts/branch-point.sh --from smolskill-src --store ./store --name smolskill-one
```

For a batch it waits until the source's PID 1 is `smolvm-branch-ready`, takes the checkpoint while
the source is parked there, then branches. Every child and that checkpoint then hold the same
state: a random value the source wrote to RAM before parking came back identical in both children
and in a restore of the checkpoint.

```
source_parked_after_s=1
checkpoint=.../smolskill-bp-branchpoint-<time>.smolcheckpoint
child=smolskill-w-0
child=smolskill-w-1
source_state=running
result=branched
```

For one child with `--name` the checkpoint is taken first and the branch a second or two later, so
the two points differ by whatever the source did in between.

**A restored branch point is not a parked source.** On start the helper releases and the workload
runs the child program with an empty `SMOLVM_BRANCH_NAME`, so a batch branch from it waits for a
branch point that never comes. Branch it with `--name`, one child at a time, or restore it once per
worker; either way the child gets the state the original children started from.

**7. Clean up.**

```bash
scripts/cleanup.sh --purge --restore-base --checkpoints ./store ./*.smolcheckpoint
```

It deletes the machines the scripts recorded, children first by `--cascade`, removes the named
checkpoint directories and stores, and with `--restore-base` removes smolvm's copies of restored
checkpoints, which otherwise stay after every machine and checkpoint is gone, printing a
`removed=` or `absent` line for each. It waits up to 20 seconds, polling the machine list, and
says so, because an ephemeral entry retires after its run returns.

## Traps

Full detail in `references/traps.md`. The ones that cost the most:

- **`--branchable` is decided at `start` and cannot be added later.** Branching needs it
  everywhere; on macOS a stored capture needs it as well.
- **`--output` must end in `.checkpoint` or `.smolcheckpoint`**, with `--store` too, where it names
  a directory. `.checkpoint` is the name from v1.19.1, and the scripts use `.smolcheckpoint`, which
  every release accepts.
- **`pgrep -f smolvm-branch-ready` inside the guest always matches**, because the `sh -c` running it
  contains the string. Read `/proc/1/cmdline`.
- **`smolvm machine list | grep -q` under `pipefail` can report a machine missing that exists**:
  `grep -q` closes the pipe early and the failed write fails the pipeline. Read the list into a
  variable first.
- **`machine stop --name` on a name that does not exist leaves an empty directory** under the VM
  cache on v1.18.2, and a second stop of it on v1.22.2 leaves the name inside, which reads as a
  leak. `cleanup.sh` stops only names still listed.
- **smolvm keeps restored checkpoints** in its VM cache, memory included: `vms/_restore-base` on
  macOS, 243 MB on v1.18.2, and from v1.22.0 `vms/_restore-checkpoints`, the last three restored,
  258 MB after this procedure on macOS on v1.23.0. Deleting the checkpoint does not delete them.

## Security defaults, and why they are the defaults

- **A checkpoint is the machine's memory and disks.** Anything the workload held, secrets included,
  is in it; keep stores on a disk only you can read, and remove `_restore-base` and
  `_restore-checkpoints` when you remove the checkpoints.
- **Retention deletes only after the new checkpoint is published**, so a failed capture never
  leaves you with fewer good checkpoints than before.
- **A store is local.** It protects against a bad change, not a lost host; export a checkpoint
  with `machine checkpoint --export-from` and copy it elsewhere for that.
- **Cleanup deletes only machines the scripts recorded under the `smolskill-` prefix, and through
  `--cascade` any machine branched from one of them, whatever its name**, and removes only the
  checkpoint paths you name.
- **Nothing here escalates privilege** or edits smolvm configuration.

## Platform arms

`references/platforms.md` has each arm. In short: **macOS arm64** ran every step here on v1.23.0,
and **Linux aarch64** on v1.18.2 and once on v1.22.2, with the one difference that Linux needs no
`--branchable`. On v1.16.1 Linux aarch64 refused `--store` and froze a branch source; from v1.18.2
it does neither. **Linux x86_64**
was not re-run. **Windows** on v1.22.2 checkpoints to a file, pauses and branches with
`--freeze-source` on every branch, and refuses `--store`, so `checkpoint.sh` cannot run there.
From v1.23.0 a checkpoint from an arm64 Mac restores on arm64 Linux, run once from this Mac to Lima.

## Eval prompts, and what they produced

Run 2026-09-24 PT against v1.18.2 from the published release, under an isolated `HOME`, on macOS
26.6.2 arm64 and Lima `linux-kvm` (Ubuntu 24.04 aarch64), every machine at 1024 MiB. Output is
verbatim unless marked.

**1. "Checkpoint this machine every few minutes, keep only the last few, and show me I can go back
to any of them."**

`schedule.sh` with `--keep 2 --history 2`, four captures ten seconds apart, both hosts:
`captures_ok=4`, `kept=2`, and `checkpoint-log` on the newest listed `~0`, `~1` and `~2`. A marker
written between captures came back as `GEN1` from `--at '~2'` and `GEN3` from the newest, with the
RAM counter restored alongside. A second capture started while one ran:

```
result=skipped
note=a capture of smolskill-src is still running (pid 13935). Run one capture at a time per source: ...
```

**2. "Fan this prepared machine out into workers, and keep a copy of exactly the state they started
from."**

`branch-point.sh --count 2` on a `--branch-ready` source, macOS: the source wrote `8445` to RAM
before parking; both children read `SETUP_DONE`, their own `CHILD=` name and `8445`, and a restore of
the branch-point checkpoint read `8445`. Linux the same with `22642`. `source_state=running` on both.

**3. "Pause the machine I restored and bring it back later without losing what is running."**

The restored machine's counter: `ram before=31 after=34` on macOS and `ram before=31 after=33` on
Linux, across a 10 s pause. Separately, on macOS a restored machine paused while the host disk was
full failed its first resume with `extract paused checkpoint: failed to unpack ...`, and the same
`machine resume` succeeded once space was freed: counter 8 before the pause, 14 after, still
counting.

## Re-verified on v1.23.0

Run 2026-10-04 PT against v1.23.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.0.1 arm64, once. On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the
checks named below ran once, so the Linux stamp stays on its earlier release.

macOS: every script. Three scheduled captures (`captures_ok=3`, `longest_capture_s=1`),
`checkpoint-log` listing three generations, restores of `~2` and the newest, the counter at 20
before a pause and 24 after the resume, both children of a batch branch holding the source's token,
and `cleanup.sh --restore-base` removing 258 MB of `_restore-checkpoints`. A capture now reports
when the source resumed, `Source resumed after 0.024s; packaging continued in the background`
([#1519](https://github.com/smol-machines/smolvm/pull/1519)).

**A checkpoint taken on this Mac restored on Linux aarch64**
([#1531](https://github.com/smol-machines/smolvm/pull/1531)). `create-source.sh`, then
`machine checkpoint --name smolskill-mac --output mac.checkpoint` on the Mac with the RAM counter
at 6, which printed `40 MiB written` and `0.066s source pause`. Copied to Lima unchanged,
`machine create --from` and `machine start` there took a second each; the counter read 7 and five
seconds later 12, the RAM token and the disk marker matched the Mac's, and the guest said
`Linux 6.12.95`.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) on 2026-10-03 guests above 2048 MiB timed out, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: every script. Three scheduled captures (`captures_ok=3`, `longest_capture_s=1`),
`checkpoint-log` listing three generations, restores of `~2` and the newest, the counter at 21
before a pause and 25 after the resume, both children of a batch branch holding the source's token,
and `cleanup.sh --restore-base` removing 275 MB of `_restore-checkpoints`. The `--branchable`
facts in "Branchability is decided at start" were measured on releases v1.18.2 to v1.22.2 on
2026-10-03.

Linux aarch64: every script, with `checkpoint_needs_branchable=no`, the counter 63 then 66 and both
children holding the same token.

## What was not run

- **Linux x86_64**, and the scripts on Windows, which are bash.
- **A schedule over hours.** Four captures ten seconds apart on each host, and single captures
  within each run; the growth of a store under `--history 32` over a day was not measured.
- **Restores on another host, beyond Mac to Linux.** Through v1.22.2 a checkpoint restores only on
  a host of the same platform, and another is refused with `checkpoint host platform '...' does not
  match '...'`. From v1.23.0 one taken on an arm64 Mac restores on arm64 Linux, run once above;
  [Moving a running machine from a Mac to Linux](../mac-to-linux.md) has the requirements. Linux to
  Mac, and a stored capture rather than a file, were not run.
- **GPU and CUDA machines**, which a capture refuses, and `--share-weights`.
- **Branch pools** (`--hold`, `branch-release`), and `--freeze-source` outside Windows.
- **The API's restore route**, the `from` field on create; the `local-api` packet covers pause and
  resume over HTTP.

## Related packets

- `dev-env` for state that only has to survive a stop and start.
- `pack` for moving a machine to another host as a file, including a restored one.
- `local-api` for pause and resume over HTTP.
- `teardown` for the wider cleanup, and for what a leak check must exclude.
