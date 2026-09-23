# Incremental checkpoint storage

Use a local checkpoint store to keep repeated checkpoints without writing the
same compressed RAM and disk chunks again:

```sh
smolvm machine checkpoint --name worker --store ./checkpoints \
  --output ./before.smolcheckpoint

# Run more work, then retain another point in time.
smolvm machine checkpoint --name worker --store ./checkpoints \
  --output ./after.smolcheckpoint

smolvm machine create --name rollback --from ./before.smolcheckpoint
smolvm machine start --name rollback
smolvm machine branch --from rollback --name candidate
```

Start the source with `machine start --branchable` before capturing it. Capture
checks the runtime and guest-agent capabilities before pausing the source.
Normal portable-checkpoint restrictions still apply, including host-platform,
CPU and device compatibility. This does not make live state cross-architecture
or cross-OS portable.

## What is retained

With `--store`, each `.smolcheckpoint` is a **directory**, not a single file.
It contains a complete index and hard links to all compressed objects it needs.
It does not depend on an earlier checkpoint or on the continued existence of
the store. Deleting an older checkpoint does not break a newer one.

The store and output must be on the same filesystem. Keep outputs outside the
store's reserved `objects` and `staging` directories. The store owns temporary
staging; `--staging-dir` cannot be combined with `--store`.

The source pauses while CPU/device state and its disk boundary are captured,
then resumes while retained RAM is streamed, hashed and compressed. The command
returns only after the checkpoint has been durably published. An output is never
overwritten. A failed capture does not publish a partially usable checkpoint.

This is incremental **storage**, not dirty-page-only capture: RAM is still read
for each checkpoint, while unchanged chunks are reused instead of compressed
and written again. Savings depend on how much RAM and disk content changes.
Capture time is not guaranteed to fall in proportion to the bytes saved.

Stored-checkpoint chunk reuse does not change the live branching limits. A live
branch lineage and its QCOW2 disk backing chain are each bounded at 32 levels;
the store deduplicates their contents but does not flatten or reset them. This
is a depth limit, not a child-count limit: one batch may create many sibling
children from one captured generation. Repeated single-child branch operations
from a continuing source can add backing layers even when the resulting children are
siblings. Stop and pack the desired state into a new root before continuing
from a chain at the limit.

## History

Every checkpoint records its *lineage*: a unique id, the machine it came from,
and its **parent** — the checkpoint that machine was last captured to or
restored from. Repeated captures of one machine form a chain; restoring a
checkpoint and capturing again forms a branch. A machine remembers its current
position (`checkpoint_head`); `machine branch` children inherit it.

A stored checkpoint (`--store`) also **retains** its ancestors: it keeps each
earlier generation's index and hard-links every object those generations
reference, so any point in its history can be restored from that one directory
even after the older directories are deleted. Because unchanged chunks are
shared, the retained history costs only the differences between generations.
`--history N` sets how many generations to retain (default 32, `0` for none).

```sh
smolvm machine checkpoint-log ./after.smolcheckpoint
# ~0   9f2c1a7b3e4d  2026-09-22T10:12:03Z  worker  4096 MiB  (this checkpoint)
# ~1   51e0d8c2a9b4  2026-09-22T09:40:11Z  worker  4096 MiB
# ~2   0c7a44e1fd93  2026-09-22T09:02:56Z  worker  4096 MiB

# Restore two generations back, or by id prefix.
smolvm machine create --name rollback --from ./after.smolcheckpoint --at ~2
smolvm machine create --name rollback --from ./after.smolcheckpoint --at 0c7a44e1

# Export one generation as a single-generation portable file.
smolvm machine checkpoint --export-from ./after.smolcheckpoint --at ~1 \
  --output ./before.smolcheckpoint

# Everything ever published into a store, with parents.
smolvm machine checkpoint-log --store ./checkpoints --machine worker
```

`--export-from` produces a single file that **carries its history**: the
retained generations and their shared objects are packed together, so the one
file can be sent anywhere and restored at any point in it (`--at` works on the
file exactly as on the directory). `--history N` limits how many generations
the file carries; `--history 0`, or `--at`, exports one generation in the
classic layout. Runtimes that predate history refuse a history file with a
version message rather than misreading it.

```sh
smolvm machine checkpoint --export-from ./after.smolcheckpoint -o ./history.smolcheckpoint
smolvm machine checkpoint-log ./history.smolcheckpoint          # read from the manifest
smolvm machine create --name rollback --from ./history.smolcheckpoint --at ~2
```

Checkpoints written before lineage existed have no history; captures of a
machine restored from one start a new chain.

## Periodic checkpoints

A timer or job runner can capture the same machine repeatedly, using the same
store and a unique output name each time. SmolVM does not yet provide a built-in
checkpoint scheduler or automatic age/count-based retention.

Run one scheduled capture at a time per source machine. The engine locks the
capture boundary, but releases that lock when the source resumes, so multiple
captures can otherwise hash/compress retained generations concurrently. That
uses additional memory and I/O rather than making a backup schedule faster.
Set the interval from measured complete capture time, not just source pause time.

Keep the previous successful checkpoint until the new command succeeds. A
capture's success means its output has been durably published, not merely that
the source has resumed. Delete expired checkpoint directories according to your
retention policy, then run `checkpoint-prune`; shared objects required by other
retained checkpoints remain intact. Capture and prune failures should be logged
and alerted by the scheduler. This is a local storage mechanism, not an off-host
backup service; export or copy complete checkpoints for host-failure protection.

## Move a checkpoint

Copy the entire checkpoint directory, including its `objects` directory, or
export it as a conventional single-file artifact:

```sh
smolvm machine checkpoint --export-from ./after.smolcheckpoint \
  --output ./portable.smolcheckpoint
```

Export does not need the original store. Omitting `--store` when capturing a
machine continues to produce a standalone file directly. Treat all checkpoint
files as sensitive: they contain the machine's captured memory and disk data.

## Reclaim storage

Delete checkpoint directories you no longer need, then prune unreferenced cache
objects:

```sh
smolvm machine checkpoint-prune --store ./checkpoints
```

Pruning waits for active captures and also removes marked staging directories
left by interrupted capture clients. It does not delete retained checkpoints.
Checkpoints use immutable shared objects; restore always creates private
writable machine state. Do not edit objects or indexes manually.
