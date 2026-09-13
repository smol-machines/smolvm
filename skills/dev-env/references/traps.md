# Persistent dev machine traps

## Contents

- `init` runs once, not on every start
- `create` is not where the time goes, and not where failures appear
- `exec` right after `start` can answer with a message instead of running
- A missing host mount source lets a machine start once and never restart
- `machine shell` does not start a stopped machine
- A host `volumes` mount is not writable by a non-root `user`
- `/tmp` is tmpfs and is wiped by a stop
- `machine delete` prompts and defaults to No
- Do not run two lifecycle commands against the same machine at once
- Assert the package version, not that the import worked

## `init` runs once, not on every start

Observed on v1.14.2 on macOS arm64 and Linux aarch64: `init` runs on the **first `start`**, not
on `create`, and never again. The second start prints
`Init already completed, skipping N command(s)`.

**Anything that must be true on every boot does not belong in `init`.** The most common victim is
a bind mount: put `mount --bind ...` in `init` and the second boot comes up without it. Re-apply
it in the same command that needs it. The `docker-in-machine` packet is built around this.

**The CLI still says otherwise, and the docs no longer do.** `smolvm machine create --help` at
v1.14.6 describes `--init` as "Run command on every VM start", while `smolvm machine run --help`
has the corrected wording, so the two subcommands contradict each other in their own help output.
`introduction/concepts/smolfile.md` has since been corrected and carries a "When init runs"
heading stating that init runs once, on the first start, and that later starts skip it. Believe
the observed behaviour, which the docs now match and `machine create --help` does not.

`init` also runs **as root**, even with `user` set: `/init-ran-as.txt` contained `root` while
`exec` and `shell` ran as `app`. There is no `machine start --init` to force a re-run.

## `create` is not where the time goes, and not where failures appear

It is pure configuration and returns in milliseconds without touching the registry. The pull, the
init commands and any of their failures all land on the first `start`. Do not read a fast
`create` as evidence that anything works.

Two docs claims to ignore: `introduction/concepts/isolation-networking-credentials.md` says "a
persistent machine pulls once, when it is created". Observed: `create` pulls nothing.

## `exec` right after `start` can answer with a message instead of running

**If you see ``the container `smolvm-<hash>` is not running``**, the workload container is not up
and the exec did nothing. The hash differs between occurrences, because the container is being
relaunched.

**Why it happens.** Without a command, `machine create` launches the image's own ENTRYPOINT or CMD
as the persistent workload (`machine create --help`, `[COMMAND]`). For an interpreter image such
as `python:3.12-alpine` that command reads EOF from a stdin nobody is holding and exits at once,
so the container dies and is relaunched, and an `exec` can land in the gap.

Measured on a nested-virt aarch64 host on 2026-09-07, 20 execs each on a fresh machine and again
immediately after a restart:

| workload command | failures, fresh | failures, after restart |
|---|---|---|
| none (image CMD) | 1 in 20 | 1 in 20 |
| `sh -c 'while true; do sleep 3600; done'` | 0 in 20 | 0 in 20 |

**The fix is to give the machine a workload that stays up**, which is what
`scripts/create-dev-machine.sh` does. There is no Smolfile key for it: pass it after `--` on
`machine create`.

**And this is why the readiness probe has to assert a value.** The message goes to stdout, so a
probe that waits for empty output or a zero exit code reports ready while the container is still
flapping, and the next three checks silently read that message as their answer. Both scripts here
wait for the exact string `WORKLOAD_READY`.

## A missing host mount source lets a machine start once and never restart

**If a machine created from a Smolfile starts fine and then never starts again**, check that every
host path in `volumes` exists. A Smolfile with `volumes = ["./src:/app"]` in a directory that has
no `./src` creates and starts once, and every later `start` fails with:

```
Error: agent operation failed: start machine: agent operation failed: wait for ready:
agent did not become ready within 30 seconds
```

which names neither the mount nor the missing directory, and reads exactly like host load.

Measured on macOS 26.6.2 arm64 on v1.14.3, 2026-09-08, three create-start-stop-start cycles each
with the workload confirmed ready before the stop:

| host mount source | restarts |
|---|---|
| `./src` exists | **3 of 3** |
| `./src` absent | **0 of 3** |

`scripts/create-dev-machine.sh` runs `mkdir -p ./src` before creating, which is why the packet's
own flow does not hit this. **Anything that writes its own Smolfile has to do the same.** A
relative path in `volumes` resolves against the working directory, so the same Smolfile run from
two directories can behave differently.

This one cost real time while writing this packet: an ad-hoc restart loop that omitted the
`mkdir -p` produced 0 of 5 and looked like a release regression until the two were compared
side by side.

## `machine shell` does not start a stopped machine, despite its own help

`smolvm machine --help` describes `shell` as "Open an interactive shell in a machine (starts it if
stopped)". It does not:

```
$ smolvm machine stop --name dev
$ smolvm machine shell --name dev
Error: agent operation failed: connect: machine 'dev' is not running.
       Use 'smolvm machine start --name dev' first.
```

Verified both through a pipe and under a real pty, so it is not a TTY-detection effect. Start it
explicitly first.

## A host `volumes` mount is not writable by a non-root `user`

With `volumes = ["./src:/app"]` and `user = "app"`, writing to `/app` fails with
`Operation not permitted`. The mount carries host ownership and the guest user does not match.
Read source in through the mount, write build output somewhere else, or run that step as root.

## `/tmp` is tmpfs and is wiped by a stop

Anything a provisioning step leaves in `/tmp` is gone on the next start, while the same step's
writes to `$HOME` or `/` persist. What survives, verified by writing one file per filesystem and
restarting:

| location | survives | why |
|---|---|---|
| pip `--user` packages | yes | under `$HOME`, on the overlay |
| `$HOME/...` files | yes | overlay |
| files written at `/` | yes | overlay |
| `/tmp` | **no** | `tmpfs` |
| `/storage/...` | yes | the ext4 disk itself |

Read from inside the guest, the mechanism is an overlay whose upper layer lives on the machine's
ext4 disk:

```
none on / type overlay (... upperdir=/storage/overlays/persistent-<name>/upper ...)
/dev/vda on /workspace type ext4 (rw,noatime)
/dev/vda on /storage   type ext4 (rw,noatime)
```

## `machine delete` prompts and defaults to No

Without `--force` a scripted cleanup prints `Delete machine 'dev'? [y/N] Cancelled` and leaves the
machine in place while the script carries on. Always pass `--force` in a script.

## Do not run two lifecycle commands against the same machine at once

Two overlapping `stop` and `shell` invocations left a `machine stop` unfinished for over two
minutes, against 0.14 s for a single `stop` on the same machine. That was self-inflicted rather
than a reproduced defect, but anything that fans out lifecycle calls should serialize them per
machine.

## Assert the package version, not that the import worked

An import can be satisfied by a system copy and tells you nothing about whether your install
survived the restart. `scripts/verify-persistence.sh` records the version before the stop and
compares it after.
