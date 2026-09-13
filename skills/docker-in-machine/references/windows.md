# Docker in a machine on Windows: it cannot work

**Not a Windows use case, and this is where the page stops.** The cause is in the bundled guest
kernel, not in the procedure, so there is no configuration a user can reach for.

Established on Windows 11 Home build 26200 x86_64 against smolvm v1.14.2. **A re-run was attempted
on 2026-09-11 against v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445 and **never reached
the question**: both attempts died pulling the image.

```
Error: agent operation failed: pull image: crane blob failed for layer sha256:23be5e15...:
  copying blob docker.io/library/docker@sha256:23be5e15...: unexpected EOF

Error: io operation failed: A connection attempt failed because the connected party did not
  properly respond after a period of time, or established connection failed because connected
  host has failed to respond. (os error 10060)
```

Neither is a kernel result. This is the same large-image pull failure the `gpu-cuda` packet's
Windows page records for `nvidia/cuda`, and it stops before any kernel feature is exercised, so
**nothing below was confirmed or refuted on v1.14.6.** Everything on this page remains the v1.14.2
record.

## How far it gets

```
create (Smolfile + --net-backend virtio-net)   in 0.6s   Init commands: 5
start  (init runs apk add docker)              in 10.7s
docker --version                               Docker version 25.0.5
df /var/lib/docker                             /dev/vda ... /storage
```

So the storage requirement this use case is built around is satisfied: the bind mounts land on the
ext4 disk exactly as on Linux and macOS.

## Where it stops

With the default configuration `dockerd` will not start at all:

```
failed to start daemon: Error initializing network controller:
error creating default "bridge" network: operation not supported
```

The guest kernel has no bridge support, confirmed directly:

```
ip link add name testbr0 type bridge
ip: RTNETLINK answers: Not supported
```

`dockerd --bridge=none` **does** start and reports a healthy daemon:

```
Server Version: 25.0.5
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```

but creating any container then fails on a second missing kernel feature:

```
docker run --rm --network=host alpine echo hi
docker: Error response from daemon: failed to create task for container:
  ... error mounting "mqueue" to rootfs at "/dev/mqueue":
  mount mqueue:/dev/mqueue ... : no such device: unknown.
```

**Two kernel options are missing from the Windows libkrunfw build**: bridge networking and POSIX
message queues. Confirmed against the config itself: `config-libkrunfw-windows_x86_64` carries
`# CONFIG_POSIX_MQUEUE is not set` and `# CONFIG_BRIDGE is not set`, while the Linux
`config-libkrunfw_x86_64` has both set to `y`.

The upstream example's own "Kernel requirements" comment lists `CONFIG_BRIDGE` and the netfilter
options as required; `CONFIG_POSIX_MQUEUE` is not in that list and is also needed.

**A healthy daemon is not the finish line.** `--bridge=none` gets `dockerd` up, which is exactly
the shape of a workaround that looks like it worked, and containers still cannot be created.

## Answering this without pulling a dind image

The two missing options can be probed directly from a plain `alpine` guest, which is small enough
to pull on a network that cannot carry the `docker` image. Report each by exit code rather than by
reading the message:

```
ip link add name testbr0 type bridge   ; echo bridge=$?
mount -t mqueue none /dev/mqueue       ; echo mqueue=$?
```

Two non-zero exits mean the kernel is still missing both and this page stands. Two zeroes mean the
guest kernel has changed and everything above needs re-running. This is the check to run first on
any new build: it costs one small pull and answers in seconds.

**A build newer than v1.14.6 ships a rebuilt Windows guest kernel**, so treat the two missing
options as a statement about v1.14.6 and earlier until that probe has been run on the newer build.

## What would change this

A libkrunfw Windows config change turning on `CONFIG_BRIDGE` and `CONFIG_POSIX_MQUEUE`. Nothing in
smolvm. Until then, use the `dev-env` or `local-api` packets on Windows and run containers
somewhere else.

`guides/docker-in-a-machine.md` carries no platform note and reads as applying to every host
smolvm supports.
