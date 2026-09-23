# Pause and resume

Pause saves RAM, disks and execution state before stopping the VM. Resume restores
that state under the same machine name; it does not boot a fresh guest.

```sh
smolvm machine start --name worker --branchable
smolvm machine pause --name worker
smolvm machine resume --name worker
```

You do not need to manage a checkpoint file. SmolVM keeps a private recovery
artifact until resume succeeds. A failed resume retains it for another attempt.
Keep the machine's data directory: a local pause is not an off-host backup.

Unlike `stop`/`start`, pause/resume preserves running processes and RAM-only data.
Open network connections may need to reconnect, and time continues passing while
the machine is paused. Pause waits for durable storage, so it can take longer
than a live branch. Use `checkpoint` when you want a separate retained artifact
and want the source to continue running.

The machine must support portable checkpoints. The same host, CPU and device
compatibility restrictions apply. Delete dependent live branches before pausing
their source. Ordinary start and stop refuse a paused machine rather than discard
its saved execution; use resume or explicitly delete it.

The node API exposes `POST /api/v1/machines/{name}/pause` and `/resume`.
