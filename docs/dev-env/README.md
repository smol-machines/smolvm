# A development machine you come back to

A named machine keeps its disk across stop and start, so the packages you installed in the first
session are there in the second. That is the whole use case, and it turns on one fact: **`init`
runs once, not on every start**, as [`smolfile.md`](../smolfile.md) says. `machine create --help`
describes `--init` as running on every start.

`SKILL.md` is the procedure. `assets/dev.smolfile` is a working starting point, and
[`examples/python-app/python.smolfile`](../../examples/python-app/python.smolfile) and
[`examples/node-app/node.smolfile`](../../examples/node-app/node.smolfile) are plainer ones.

## What persists, and what does not

| Mode | Persistence |
|---|---|
| `machine run` | ephemeral, every change discarded when the command exits |
| `machine exec` | changes persist across exec sessions, in an overlay on the machine's storage disk |
| `machine stop` then `start` | changes persist; the overlay is remounted |
| `machine create --from <artifact>.smolmachine` | a persistent machine from a packed artifact, boots from pre-extracted layers with no image pull |

`/tmp`, `/run` and `/dev/shm` are tmpfs whatever the mode. They keep their contents while the
machine runs, including across `exec` sessions, and are empty again after a stop and start. Write
anything that must outlive a restart to `/workspace` or elsewhere on the storage disk, including
credentials and configuration, which should not sit in `/tmp` or behind a symlink into it.

On v1.22.2 the storage disk defaulted to 20 GiB and the rootfs overlay to 10 GiB, as `machine list`
showed; `AGENTS.md` gives 2 GiB for the overlay. Both are sparse, so they cost what they hold.

## `init` runs once

A Smolfile's `init` is provisioning: it runs on the first start of a machine and is skipped on
every start after that. `smolvm machine create --help` describes it as running on every VM start;
provisioning that relies on that reading is missing on the second boot. Anything
that must be true on every boot, a bind mount above all, belongs in the command the machine runs,
not in `init`.
