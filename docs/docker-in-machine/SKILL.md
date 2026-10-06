---
name: docker-in-machine
description: Runs a Docker daemon inside a smolvm machine and shows it working there, which is what tools that call Docker themselves need, such as a test suite that starts containers, an image build, or a coding agent that launches containers. Use when dockerd will not start inside a machine; when Docker worked on the first boot and broke after a stop and start; when deciding where Docker's data directory has to live; or when checking whether this is possible on a given platform at all. Do not use it to run OCI images, which smolvm boots natively without Docker, and do not attempt it on Windows, where the bundled guest kernel cannot support it.
---

# A Docker daemon inside a machine

Verified on **smolvm v1.22.2** on macOS arm64, 2026-10-03, and on **v1.18.2** on Linux aarch64, 2026-09-24; the Linux runs used
the Smolfile with `memory = 1024`, for a host reason given below. Done means `docker info` succeeds inside the guest, a nested container runs, and
Docker's data sits on the ext4 storage disk rather than the rootfs overlay.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

smolvm boots OCI images without Docker. This is only for software **inside** the machine that must
call Docker itself.

**On Windows, up to and including v1.22.2, `dockerd` does not start in a machine.** The Windows
guest kernel is built without bridge networking and POSIX message queues, so `dockerd` cannot
create its default network and, forced past that, containers still cannot be created.
`references/windows.md` has the evidence and the direct kernel probe, which gave the same answer on
v1.22.2.

## The trap this packet exists for

**`init` runs once, so the bind mounts are gone on the second boot** and have to be re-applied on
every start. The upstream example says so in its comments and re-applies them in its "Start
dockerd" recipe, which `scripts/start-dockerd.sh` is. Reproduced on both hosts on v1.14.2, v1.18.2
and v1.22.2, and on macOS on v1.16.1:

```
Init already completed, skipping 5 command(s)
NO_BIND_MOUNTS_AFTER_RESTART
DOCKERD_DOWN
```

Running `scripts/start-dockerd.sh` afterwards restored everything, and `docker images` still
listed `alpine:latest`, because the images are on `/storage`. **The failure mode is a daemon that
will not start, or one running on the wrong filesystem, not lost data.**

`smolvm machine create --help` describes `--init` as "Run command on every VM start" at v1.22.2;
`init` runs on the first start only, as [`smolfile.md`](../smolfile.md) says. More in
`references/traps.md`.

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

`docker_in_machine=verified` on macOS and Linux, `unavailable` on Windows with the reason.

**2. Create and install.** `assets/docker.smolfile` is the upstream example's configuration,
shipped here because **the release tarball does not contain `examples/`**, so the `git clone` step
in the docs site's guide (smolmachines.com/docs) is not something a released install can follow.

```bash
scripts/create-docker-machine.sh              # name defaults to smolskill-docker
```

The `apk add docker` happens on the **first start**, not on create, and dominates the time.

**3. Start the daemon. Run this on every start, not only the first.**

```bash
scripts/start-dockerd.sh
```

It re-applies both bind mounts, clears a stale pid file, starts `dockerd` with the `overlay2`
driver and waits for `docker info` to answer:

```
 Server Version: 25.0.5
 Storage Driver: overlay2
 Docker Root Dir: /var/lib/docker
server_version=25.0.5
result=dockerd_up
```

**4. Prove it, on the right filesystem.**

```bash
scripts/verify-docker.sh
```

```
storage_driver=ok (overlay2)
docker_root_device=ok (/dev/vda)
pull=docker.io/library/alpine:latest
nested_container=ok (NESTED_OK)
host_network=ok (HOSTNET_OK)
host_socket=present (.../vms/<hash>/docker.sock)
result=docker_ok
```

`docker_root_device` is the check that matters. `docker info` succeeds while `/var/lib/docker`
sits on the rootfs overlay, and the failure that follows is confusing and much later.

**5. Use it, and clean up only when it is no longer wanted.** A machine someone asked for is the
deliverable: leave it running and give them its name. Their own code gets in with
`smolvm machine cp <file> smolskill-docker:/workspace/<file>` or a `-v` mount on create, and runs
with `smolvm machine exec --name smolskill-docker -- ...`; with no `docker` client on the host, code
that calls Docker runs inside the machine against this daemon. What this packet shows is the
daemon: `docker info`, a nested container and host networking.

```bash
scripts/cleanup.sh --purge
```

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

## Why Docker's data has to live on `/storage`

A hard requirement, not a preference. The smolvm rootfs overlay uses the initramfs (ramfs) as its
lower layer, ramfs has no file-handle support, and overlayfs then rejects it as an upper dir for
Docker's nested overlay. Both mounts are needed: `/var/lib/containerd` holds the snapshotter's
overlay state and fails the same way.

That is why the Smolfile declares `storage = 20`, and why every check here is against `/dev/vda`.

## The host-side socket

`docker_socket = true` bridges the guest's `/var/run/docker.sock` to a host path under the
machine's data directory:

```bash
D=$(smolvm machine data-dir --name smolskill-docker)
DOCKER_HOST=unix://$D/docker.sock docker ps      # needs a docker client on the host
```

The socket is created and `verify-docker.sh` asserts it exists. **Driving it from the host was not
verified**: neither host used here has a `docker` client.

## Security defaults, and why they are the defaults

- **`docker_socket = true` is the one line here that gives something outside the VM real
  authority.** A process on the host that can open that socket can start containers inside the
  machine, mount paths the machine can see and read anything they hold. Leave it off unless a host
  tool actually needs it, which is why nothing in this packet's own checks depends on it.
- **A Docker daemon inside the machine is root inside the machine, and that is the point.** The VM
  boundary is what makes it acceptable: treat root in the guest as untrusted, as the
  [security model](../security-model.md) says, and every forwarded mount, port and network
  permission becomes part of what the nested containers can reach.
- **`--network=host` inside the guest is the guest's network, not yours.** It is verified here
  because Testcontainers and Compose commonly need it, and it is contained by the VM rather than
  by Docker.
- **`net = true` is outbound access for the whole machine**, and it is required for this use case
  because `apk add docker` and every `docker pull` need it. Scope it with `--allow-host` where the
  set of registries is known.
- **The scripts wrap the public CLI only.** They edit no smolvm configuration and nothing under
  `~/.smolvm`, and cleanup deletes only names it recorded under the `smolskill-` prefix.

## Platform arms

- **macOS arm64**: v1.22.2 as shipped, every check passed, the restart trap and its recovery
  included.
- **Linux aarch64**: v1.18.2 and once on v1.22.2, with the Smolfile's memory at 1024 MiB: the Lima
  host could not boot larger guests inside the fixed 30 s readiness window, and the `install`
  packet's traps have the numbers. On a small or busy host, lower `memory` before suspecting
  Docker; 1024 MiB was enough for `dockerd` and a nested alpine container.
- **Linux x86_64**: not run anywhere for this use case.
- **Windows x86_64**: **does not run on v1.22.2**. A v1.14.2 run showed `dockerd` failing; on
  2026-10-03 on v1.22.2 (Windows 11 Home build 10.0.26200 UBR 9457) the direct kernel probe in a
  plain `alpine` guest gave `RTNETLINK answers: Not supported` for a bridge and `No such device` for
  `mqueue`. `references/windows.md` has both.

## Eval prompts, and what they produced

**1. "Give me a machine with a Docker daemon inside it, and show me Docker actually works in
it."**

On v1.18.2, both hosts identical:

```
docker_version=Docker version 25.0.5, build d260a54c81efcc3f00fe67dee78c94b16c2f8692
result=installed
server_version=25.0.5
result=dockerd_up
storage_driver=ok (overlay2)
docker_root_device=ok (/dev/vda)
nested_container=ok (NESTED_OK)
host_network=ok (HOSTNET_OK)
result=docker_ok
```

**2. "Docker worked yesterday and today `dockerd` will not start. Nothing changed."**

Reproduced on both hosts by stopping and starting the machine, with the lines shown under the
trap above; `scripts/start-dockerd.sh` then brought it back to `result=docker_ok` with
`alpine:latest` still listed.

**3. "Can I do this on Windows?"**

**No**, and the answer is short enough to give without running anything: the bundled guest kernel
has `CONFIG_BRIDGE` and `CONFIG_POSIX_MQUEUE` both off, so `dockerd` fails on
`error creating default "bridge" network: operation not supported`, and with `--bridge=none` the
daemon comes up healthy while every container fails on `/dev/mqueue`. That result is from an
earlier run on Windows 11 against v1.14.2, and the kernel probe on `references/windows.md` gave
the same two answers on v1.22.2.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) guests above 2048 MiB timed out on 2026-10-03, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: `result=docker_ok` with `docker_root_device=ok (/dev/vda)`, then after a stop and start
`Init already completed, skipping 5 command(s)`, `NO_BIND_MOUNTS_AFTER_RESTART`, `DOCKERD_DOWN`,
and `start-dockerd.sh` brought it back with `alpine:latest` still listed.

Linux aarch64 at `memory = 1024`: the same lines.

## What was not run

- **`dockerd` itself on Windows after v1.14.2.** The v1.22.2 answer is the kernel probe, not a
  daemon run.
- **Linux x86_64.** Not run for this use case on any host, then or now.
- **Driving the host-side `docker.sock` from a host `docker` client.** The socket is created and
  asserted; neither host here has a docker client to drive it with.
- **Compose and Testcontainers themselves.** The packet verifies `docker info`, a nested container
  and host networking, which is what those depend on, not the tools.

## Related packets

- `dev-env` for the `init`-runs-once semantics this is built on.
- `install` for the boot this assumes, `teardown` for the cleanup script.
