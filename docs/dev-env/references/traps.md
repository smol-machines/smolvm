# Persistent dev machine traps

## Contents

- `init` runs once, not on every start
- `create` is not where the time goes, and not where most failures appear
- `exec` right after `start` can answer with a message instead of running
- A host mount source that goes missing stops every later start
- `machine shell` does not start a stopped machine
- A host `volumes` mount was not writable by the `app` user
- `/tmp` is tmpfs and is wiped by a stop
- `machine delete` prompts and defaults to No
- A VPN inside the machine takes its gateway and resolver
- Do not run two lifecycle commands against the same machine at once
- Assert the package version, not that the import worked

## `init` runs once, not on every start

Observed on v1.14.2 on macOS arm64 and Linux aarch64: `init` runs on the **first `start`**, not
on `create`, and never again. The second start prints
`Init already completed, skipping N command(s)`.

**Anything that must be true on every boot does not belong in `init`.** The most common victim is
a bind mount: put `mount --bind ...` in `init` and the second boot comes up without it. Re-apply
it in the same command that needs it. The `docker-in-machine` packet is built around this.

**The two help texts read differently.** At v1.22.2 `smolvm machine create --help` describes
`--init` as "Run command on every VM start", and `smolvm machine run --help` as "Run command before
the workload ... the same as `init` in a Smolfile". [`smolfile.md`](../../smolfile.md) says `init`
"runs once as root, like a Dockerfile `RUN`", and the docs site's `introduction/concepts/smolfile.md`
(smolmachines.com/docs) says under "When init runs" that it runs once, on the first start. Observed:
once, on the first start.

`init` also runs **as root**, even with `user` set: `/init-ran-as.txt` contained `root` while
`exec` and `shell` ran as `app`. There is no `machine start --init` to force a re-run.

## `create` is not where the time goes, and not where most failures appear

It is pure configuration and returns in milliseconds without touching the registry. The pull, the
init commands and any of their failures all land on the first `start`. Do not read a fast
`create` as evidence that anything works. It does refuse a host mount source that does not exist;
see below.

`create` pulls nothing either; the image is pulled on the first `start`.

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

**On v1.18.2**, 2026-09-24, the no-command row was 0 in 20 on macOS arm64 and 1 in 20 on Lima
aarch64, where it had been 0 in 20 on both on v1.16.1.

**The fix is to give the machine a workload that stays up**, which is what
`scripts/create-dev-machine.sh` does by passing one after `--` on `machine create`. A Smolfile can
carry it as well, as `cmd` (with `entrypoint`), and a command after `--` replaces the Smolfile's
`cmd`.

**And this is why the readiness probe has to assert a value.** The message goes to stdout, so a
probe that waits for empty output or a zero exit code reports ready while the container is still
flapping, and the next three checks silently read that message as their answer. Both scripts here
wait for the exact string `WORKLOAD_READY`.

## A host mount source that goes missing stops every later start

**If a machine created from a Smolfile has started before and now never starts again**, check that
every host path in `volumes` still exists. `create` refuses a path that is missing when it runs,
with `mount source not found: ./src`; a later `start` does not check the path again, and in the run
below every later `start` failed with:

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

How `./src` came to be missing in that run was not recorded. On v1.22.2 on macOS arm64,
2026-10-03, removing `./src` after a machine's first start reproduced it: the next `start` failed
with the same message, and `create` with `./src` already missing refused with `Error: mount source
not found: ./src`.

`scripts/create-dev-machine.sh` runs `mkdir -p ./src` before creating, which is why the packet's
own flow does not hit this. **Anything that writes its own Smolfile has to do the same.** A
relative path in `volumes` resolves against the working directory, so the same Smolfile run from
two directories can behave differently.

An ad-hoc restart loop that omitted the `mkdir -p` produced 0 of 5 and looked like a release
regression until the two were compared side by side.

## `machine shell` does not start a stopped machine

`smolvm machine --help` describes `shell` as "Open an interactive shell in a machine (starts it if
stopped)". It does not:

```
$ smolvm machine stop --name dev
$ smolvm machine shell --name dev
Error: agent operation failed: connect: machine 'dev' is not running.
       Use 'smolvm machine start --name dev' first.
```

Verified both through a pipe and under a real pty, so it is not a TTY-detection effect, and again
on v1.18.2. Start it explicitly first.

## A host `volumes` mount was not writable by the `app` user

With `volumes = ["./src:/app"]` and `user = "app"` (a user `adduser` made in the guest), writing to
`/app` failed with `Operation not permitted`: the mount carries host ownership and `app` is not its
owner. Read source in through the mount, write build output somewhere else, or run that step as
root. `user` also takes a numeric `uid[:gid]`, which `machine create --help` gives as the way to
match the owner of a mounted host directory: on v1.22.2 on macOS arm64, `machine run -v
"$PWD/src:/app" --user "$(id -u):$(id -g)"` wrote `/app/w` and the file appeared on the host.

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

Through v1.16.x a scripted delete without `--force` printed `Delete machine 'dev'? [y/N]
Cancelled`, exited 0 and left the machine in place while the script carried on. On v1.17.0 and
later it exits 1 with `needs confirmation but stdin is not a terminal; pass --force to delete it`.
Always pass `--force` in a script.

## A VPN inside the machine takes its gateway and resolver

A machine on virtio-net gets the link `100.96.0.0/30` by default, with the gateway and resolver at
`.1`. Tailscale and other carrier NAT VPNs claim `100.64.0.0/10`, which contains it, so once the
VPN is up inside the machine its gateway and resolver route into the VPN and every lookup fails.
The `throwaway-machine` packet's traps have the measurement: with the routes Tailscale adds, the default link
gave `bad address 'example.com'` and `--guest-subnet 10.200.0.0/30` with the same routes resolved
and fetched, on v1.18.2 on both hosts.

For a dev machine the flag has three constraints, each observed on v1.18.2:

- **It is set at `create` only.** `machine update` has no `--guest-subnet`, so changing it means a
  new machine. It survives stop and start.
- **A Smolfile cannot carry it.** `[network]` accepts `allow_hosts`, `allow_cidrs` and
  `credentials`; pass `--guest-subnet` on `machine create` next to `-s`.
- **It implies `--net` and virtio-net**, and `machine ls --json` then reports `"network": false`
  for a machine that does reach the network, so do not read that field as the answer.

## Do not run two lifecycle commands against the same machine at once

Two overlapping `stop` and `shell` invocations left a `machine stop` unfinished for over two
minutes, against 0.14 s for a single `stop` on the same machine. It was seen once, with the two
calls overlapping, and was not reproduced as a fault; anything that fans out lifecycle calls should
still serialize them per machine.

## Assert the package version, not that the import worked

An import can be satisfied by a system copy and tells you nothing about whether your install
survived the restart. `scripts/verify-persistence.sh` records the version before the stop and
compares it after.
