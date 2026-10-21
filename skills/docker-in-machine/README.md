# A Docker daemon inside a machine

smolvm boots OCI images without Docker. This packet is for software **inside** the machine that has
to call Docker itself: Testcontainers, Compose, an image build, or an agent that launches
containers of its own.

`SKILL.md` is the procedure, `assets/docker.smolfile` the machine definition its scripts use, and
`references/traps.md` the measurements behind each trap.
[`examples/docker-in-vm/docker.smolfile`](https://github.com/smol-machines/smolvm/tree/main/examples/docker-in-vm/docker.smolfile) is the
longer commented version, with the kernel requirements, a TCP
endpoint recipe, a K3d cluster and the managed-cloud variant where each exec has its own mount
namespace.

## The short version: two disk volumes

From v1.28.1, give Docker its data directories as disk volumes, a guest path with no host side:

```bash
smolvm machine create --name dind --net --image docker:dind \
  -v /var/lib/docker -v /var/lib/containerd
smolvm machine start --name dind
smolvm machine exec --name dind -- docker run --rm alpine echo ok
```

Each path is a directory on the machine's ext4 disk, bound into the workload on every start, so
there are no bind mounts to re-apply and no `start-dockerd.sh` step after a stop and start. In a
Smolfile it is `volumes = ["/var/lib/docker", "/var/lib/containerd"]`. On Linux x86_64 with a
build of that change, `df /var/lib/docker` read `/dev/vda` on the first boot and after a stop and
start, the `alpine` image survived the restart, and a nested `docker run` succeeded both times. The
same machine without the volumes had `/var/lib/docker` on the overlay root and `docker run` failed.
On macOS arm64 with v1.29.0 the commands above gave the same: `/dev/vda` and a nested `docker run`
before and after a stop and start, `alpine:latest` still listed, and `docker info` answering 4 s
after each start.

The rest of this packet is the procedure for v1.28.0 and earlier, which have no disk volumes.

## Docker's data has to live on `/storage`

The machine's root filesystem is already an overlay, and Docker's `overlay2` driver cannot put its
upper layer there: the backing filesystem does not provide the file-handle support nested
overlayfs needs. `/storage` is the machine's ext4 disk, and Docker's data root belongs on it:

```bash
dockerd --data-root=/storage/docker --storage-driver=overlay2
```

`assets/docker-bind-mounts.smolfile`, for v1.28.0 and earlier, instead bind-mounts `/storage/docker`
onto `/var/lib/docker`, which reads better to a container tool that assumes the default path. Both
work. **`docker info` will not tell you
which filesystem you ended up on**, so check the device, not the daemon.

## The bind mounts are gone on the second boot

`init` runs once, so after a stop and start the bind mounts are gone and `dockerd` is down.
`scripts/start-dockerd.sh`, the upstream example's "Start dockerd" recipe, re-applies them; run it
after every start. The images are on `/storage` and survive.

## Reaching the daemon from the host

Set `docker_socket = true` in the Smolfile, or pass `--docker-socket` at create. smolvm bridges the
guest's `/var/run/docker.sock` over vsock to `docker.sock` in the machine's data directory;
`machine run --docker-socket` also prints that path:

```bash
DOCKER_HOST=unix://$(smolvm machine data-dir --name smolskill-docker)/docker.sock docker ps
```

That exposes the daemon **inside** the guest to host clients, and containers stay inside the guest
kernel. It is not the same as mounting the host's own `/var/run/docker.sock` into the machine,
which hands guest code control of the host daemon and removes the isolation the machine is for. Do
not do the second with an untrusted guest. Prefer the vsock-backed Unix socket. If a client needs
TCP, the upstream example's recipe has `dockerd` listen on `0.0.0.0` inside the guest, which is what
a published port reaches (Networking in `AGENTS.md`), and the host client connect to
`127.0.0.1:<published port>`; the TCP API has no authentication of its own, so keep it off any
address other hosts can reach.

## Ports

Declare host-to-guest ports at create time. Dynamic ports chosen later by Compose or Testcontainers
are not published through the outer VM boundary automatically, so pin the ones the host must reach.

## Platforms

This does not work on Windows, up to and including v1.22.2: the bundled guest kernel has neither
bridge networking nor POSIX message queues, so `dockerd` will not start and, forced past that,
containers still cannot be created. `references/windows.md` has the evidence and a kernel probe to
re-check it on a newer build.
