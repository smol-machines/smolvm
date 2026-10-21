# A development machine you come back to

A named machine keeps its disk across stop and start, so the packages you installed in the first
session are there in the second. That is the whole use case, and it turns on one fact, below:
**`init` runs once, not on every start**.

`SKILL.md` is the procedure. `assets/dev.smolfile` is a working starting point, and
[`examples/python-app/python.smolfile`](https://github.com/smol-machines/smolvm/tree/main/examples/python-app/python.smolfile) and
[`examples/node-app/node.smolfile`](https://github.com/smol-machines/smolvm/tree/main/examples/node-app/node.smolfile) are plainer ones.

## What persists, and what does not

| Mode | Persistence |
|---|---|
| `machine run` | ephemeral, every change discarded when the command exits, unless `-d` leaves it running as a named machine that `exec` and `stop` act on |
| `machine exec` | changes (package installs, config edits) persist across exec sessions, bare or image-based, in an overlay on the machine's storage disk |
| `machine stop` then `start` | changes persist; the overlay is remounted |
| `machine create --stop-on-exit` (Smolfile `stop_on_exit = true`) | the machine stops itself when its workload exits, whatever the exit status, with storage flushed as for `machine stop`; the rest is in [smolfile.md](https://github.com/smol-machines/smolvm/blob/main/docs/smolfile.md#stopping-when-the-workload-exits) |
| `pack run` | ephemeral, each run starts fresh from the packed image |
| `pack start` then `exec` | daemon mode: package installs and file writes persist across exec sessions, and `/workspace` across a stop and start too |
| `machine create --from <artifact>.smolmachine` | a persistent named machine from a packed artifact, booting from pre-extracted layers (the agent ready in about 150 ms on v1.29.0 on macOS arm64, no image pull), with full `exec` persistence |

`/tmp`, `/run` and `/dev/shm` are tmpfs whatever the mode, except that `machine run --unprivileged`
keeps only `/dev/shm`. They keep their contents while the
machine runs, including across `exec` sessions, and are empty again after a stop and start. Write
anything that must outlive a restart to `/workspace` or elsewhere on the storage disk, including
credentials and configuration, which should not sit in `/tmp` or behind a symlink into it.

The storage disk defaults to 20 GiB and the rootfs overlay to 10 GiB, as `machine list` showed on
v1.22.2 and on v1.27.3. Both are sparse, so they cost what they hold.

## Changing ports while it runs

`machine update` adds or removes TCP ports on a running machine; the change
applies at once and is saved for the next start.

```sh
smolvm machine update --name dev -p 9090:9090
smolvm machine update --name dev --remove-port 8080:8080
```

Connections a removed port already accepted carry on. The machine must have
been started with at least one published port, since only that networking can
change live. UDP ports, and any other setting in the same command, need the
machine stopped. A host port already in use fails the command and changes
nothing. The API equivalent is `PUT /api/v1/machines/{name}/ports` with the
whole set: `{"ports":[{"host":9090,"guest":9090}]}`.

To grow a running machine's CPUs, RAM or disks, run `smolvm machine resize --help`.

## Watching a running machine

```sh
smolvm machine logs --name dev            # workload stdout and stderr
smolvm machine logs --name dev -f --tail 50
smolvm machine stats --name dev           # add --json for scripts
```

`logs` shows the output of the machine's workload (the image's entrypoint or
the Smolfile command), not of `exec` sessions. The log is kept across restarts,
rotated at 10 MiB, and readable while the machine is stopped. `-f` runs until
interrupted.

`stats` needs a running machine. CPU is the VM process on the host over half a
second, where 100% is one busy CPU; memory is the guest's own account.

## `init` runs once

A Smolfile's `init` is provisioning, as [`smolfile.md`](https://github.com/smol-machines/smolvm/blob/main/docs/smolfile.md) says: it runs on the first
start of a machine and is skipped on every start after that. Before v1.23.7 `smolvm machine create --help` described it as running on
every VM start; provisioning that relies on that reading is missing on the second boot. Anything
that must be true on every boot, a bind mount above all, belongs in the command the machine runs,
not in `init`.
