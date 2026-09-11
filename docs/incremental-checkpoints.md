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
