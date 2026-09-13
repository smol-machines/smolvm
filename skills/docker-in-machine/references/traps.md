# Docker in a machine traps

## The bind mounts do not survive a stop, and `init` will not re-apply them

**This is the trap that breaks the second session**, and it is the reason this packet has a
separate `start-dockerd.sh` rather than a Smolfile alone.

`init` runs **once**. On every start after the first the guest comes up with `/var/lib/docker`
back on the rootfs overlay. Observed on macOS arm64 and Linux aarch64, immediately after one stop
and start:

```
Init already completed, skipping 5 command(s)
NO_BIND_MOUNTS_AFTER_RESTART
DOCKERD_DOWN
```

**Putting the mounts in `init`, as the upstream example does, is correct for exactly one boot.**
Re-apply them in the same command that starts `dockerd`, which is what `scripts/start-dockerd.sh`
does. After it ran, the same host reported `dockerd_up` and every check passed again.

**Your images do survive**, because they are on `/storage`. After the restart and the re-mount,
`docker images` still listed `alpine:latest`. So the failure mode is "dockerd will not start" or
"dockerd starts on the wrong filesystem", not data loss.

## `/var/lib/docker` must be on `/storage`, and `docker info` will not tell you it is not

A hard requirement, not a preference. The smolvm rootfs overlay uses the initramfs (ramfs) as its
lower layer, ramfs has no file-handle support, and overlayfs then rejects it as an upper dir for
Docker's nested overlay.

**`docker info` succeeds while `/var/lib/docker` sits on the overlay**, and the failure that
follows is confusing and much later. Assert the backing device:

```bash
smolvm machine exec --name <n> -- sh -c 'df /var/lib/docker | tail -1'
# /dev/vda 20623316 412 20606520 0% /storage
```

Both readings print `/var/lib/docker` as the mount point, so the path tells you nothing. The
device is the value that matters.

## Both bind mounts are needed, not just Docker's

`/var/lib/containerd` holds the snapshotter's overlay state and fails the same way if it is left
on the rootfs overlay. The upstream Smolfile mounts both and its own comments say container start
fails without the second one, with containerd's overlay mount rejected as `invalid argument`.

`guides/docker-in-a-machine.md` gives a `dockerd` start command that bind-mounts only
`/storage/docker`. That command is incomplete.

## A `docker run` that pulls interleaves two streams

The first run of an image prints the pull's progress alongside the container's own output, and the
two arrive in a different order on different hosts: on Linux aarch64 the marker was the last line,
on macOS arm64 it was not. A check that takes the last line passes on one host and fails on the
other. `scripts/verify-docker.sh` pulls first, separately, so the run's output stands alone
without discarding the stderr that would explain a real failure.

## `machine delete` prompts and defaults to No

Pass `--force` in a script, or the cleanup reports success and leaves a 20 GiB machine behind.

## What the guide and the CLI still get wrong for this use case, at v1.14.6

- `guides/docker-in-a-machine.md` bind-mounts only one path in its `dockerd` command, while the
  upstream Smolfile mounts two.
- The same guide shows `machine create ... -s examples/docker-in-vm/docker.smolfile` after a
  `git clone` of the smolvm repo. **The release tarball does not contain `examples/`**, so a user
  who installed from the release has to clone the repo to follow the guide at all. This packet
  ships its own `assets/docker.smolfile` for that reason.
- The same guide says bind mounts "do not survive a stop and start, so reapply that mount before
  starting `dockerd`", which is correct and verified. But the page's own example puts them in
  `init`, where they run once, and never connects the two facts.
- `smolvm machine create --help` describes `--init` as "Run command on every VM start" at
  v1.14.6. If that were true the example would be correct, and **it is the surviving copy of the
  wrong promise**: `introduction/concepts/smolfile.md` has been corrected and now documents under
  "When init runs" that init runs once, on the first start.
- The guide carries no platform note at all, and on Windows the procedure cannot succeed. See
  `references/windows.md`.
