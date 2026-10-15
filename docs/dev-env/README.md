# A development machine you come back to

A named machine keeps its disk across stop and start, so the packages you installed in the first
session are there in the second. That is the whole use case, and it turns on one fact: **`init`
runs once, not on every start**, as [`smolfile.md`](../smolfile.md) says, and as
`machine create --help` says from v1.23.7; before that release the help said every start.

`SKILL.md` is the procedure. `assets/dev.smolfile` is a working starting point, and
[`examples/python-app/python.smolfile`](../../examples/python-app/python.smolfile) and
[`examples/node-app/node.smolfile`](../../examples/node-app/node.smolfile) are plainer ones.

## What persists, and what does not

| Mode | Persistence |
|---|---|
| `machine run` | ephemeral, every change discarded when the command exits, unless `-d` leaves it running as a named machine that `exec` and `stop` act on |
| `machine exec` | changes (package installs, config edits) persist across exec sessions, bare or image-based, in an overlay on the machine's storage disk |
| `machine stop` then `start` | changes persist; the overlay is remounted |
| `machine create --stop-on-exit` (Smolfile `stop_on_exit = true`) | the machine stops by itself when its workload exits, whatever the exit status, with storage flushed as for `machine stop`; `exec` sessions never trigger it, the restart policy then applies (the default, `never`, leaves it stopped), and the exit status is not passed on |
| `pack run` | ephemeral, each run starts fresh from the packed image |
| `pack start` then `exec` | daemon mode: package installs and file writes persist across exec sessions, and `/workspace` across a stop and start too |
| `machine create --from <artifact>.smolmachine` | a persistent named machine from a packed artifact, booting from pre-extracted layers (about 250 ms, no image pull), with full `exec` persistence |

`/tmp`, `/run` and `/dev/shm` are tmpfs whatever the mode, except that `machine run --unprivileged`
keeps only `/dev/shm`. They keep their contents while the
machine runs, including across `exec` sessions, and are empty again after a stop and start. Write
anything that must outlive a restart to `/workspace` or elsewhere on the storage disk, including
credentials and configuration, which should not sit in `/tmp` or behind a symlink into it.

The storage disk defaults to 20 GiB and the rootfs overlay to 10 GiB, as `machine list` showed on
v1.22.2 and on v1.27.3. Both are sparse, so they cost what they hold.

## `init` runs once

A Smolfile's `init` is provisioning: it runs on the first start of a machine and is skipped on
every start after that. Before v1.23.7 `smolvm machine create --help` described it as running on
every VM start; provisioning that relies on that reading is missing on the second boot. Anything
that must be true on every boot, a bind mount above all, belongs in the command the machine runs,
not in `init`.
