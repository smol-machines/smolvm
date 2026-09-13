---
name: docker-in-machine
description: Runs a Docker daemon inside a smolvm machine, for workloads that must call Docker themselves such as Testcontainers, Compose, image builds, or a coding agent that launches containers. Use when dockerd will not start inside a machine; when Docker worked on the first boot and broke after a stop and start; when deciding where Docker's data directory has to live; or when checking whether this is possible on a given platform at all. Do not use it to run OCI images, which smolvm boots natively without Docker, and do not attempt it on Windows, where the bundled guest kernel cannot support it.
---

# A Docker daemon inside a machine

Verified on **smolvm v1.14.6** on Linux aarch64 and macOS arm64, 2026-09-10. Done means `docker info` succeeds
inside the guest, a nested container runs, and Docker's data sits on the ext4 storage disk rather
than the rootfs overlay.

smolvm boots OCI images without Docker. This is only for software **inside** the machine that must
call Docker itself.

**This use case does not exist on Windows, up to and including v1.14.6.** The bundled guest kernel
there has neither bridge networking nor POSIX message queues, so `dockerd` will not start and,
forced past that, containers still cannot be created. `references/windows.md` has the evidence, and
the direct kernel probe to re-check it on a newer build.

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

`docker_in_machine=verified` on macOS and Linux, `unavailable` on Windows with the reason.

**2. Create and install.** `assets/docker.smolfile` is the upstream example's configuration,
shipped here because **the release tarball does not contain `examples/`**, so the guide's
`git clone` step is not something a released install can follow.

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

**5. Clean up.**

```bash
scripts/cleanup.sh --purge
```

## Why Docker's data has to live on `/storage`

A hard requirement, not a preference. The smolvm rootfs overlay uses the initramfs (ramfs) as its
lower layer, ramfs has no file-handle support, and overlayfs then rejects it as an upper dir for
Docker's nested overlay. Both mounts are needed: `/var/lib/containerd` holds the snapshotter's
overlay state and fails the same way.

That is why the Smolfile declares `storage = 20`, and why every check here is against `/dev/vda`.

## The trap this packet exists for

**`init` runs once, so the bind mounts are gone on the second boot.** The upstream example puts
them in `init` alone, which is correct for exactly one boot. Reproduced on both hosts:

```
Init already completed, skipping 5 command(s)
NO_BIND_MOUNTS_AFTER_RESTART
DOCKERD_DOWN
```

Running `scripts/start-dockerd.sh` afterwards restored everything, and `docker images` still
listed `alpine:latest`, because the images are on `/storage`. **The failure mode is a daemon that
will not start, or one running on the wrong filesystem, not lost data.**

`smolvm machine create --help` still describes `--init` as running "on every VM start" at
v1.14.6, which is what makes the upstream example look correct. The docs have been corrected and
now say init runs once. More in `references/traps.md`.

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
  boundary is what makes it acceptable: treat root in the guest as untrusted, and remember that
  every forwarded mount, port and network permission becomes part of what the nested containers
  can reach.
- **`--network=host` inside the guest is the guest's network, not yours.** It is verified here
  because Testcontainers and Compose commonly need it, and it is contained by the VM rather than
  by Docker.
- **`net = true` is outbound access for the whole machine**, and it is required for this use case
  because `apk add docker` and every `docker pull` need it. Scope it with `--allow-host` where the
  set of registries is known.
- **The scripts wrap the public CLI only.** They edit no smolvm configuration and nothing under
  `~/.smolvm`, and cleanup deletes only names it recorded under the `smolskill-` prefix.

## Platform arms

- **Linux aarch64**: the scripts were run here, which is the verified platform for this use case.
- **macOS arm64**: the scripts were run here too and every check passed, including the restart
  trap and its recovery. The material behind this packet had not exercised this use case on macOS.
- **Linux x86_64**: not run anywhere for this use case.
- **Windows x86_64**: **not possible**, on the evidence of one v1.14.2 run. A re-run on
  2026-09-11 against v1.14.6 **did not reach the question**: both attempts died pulling the image,
  so nothing was confirmed or refuted there. `references/windows.md` has both, and the direct
  kernel probe that answers it without a large pull.

## Eval prompts, and what they produced

Run on 2026-09-07 PT against v1.14.2 from the published release, under an isolated `HOME`, on
macOS 26.6.2 arm64 and Lima `linux-kvm` (Ubuntu 24.04 aarch64). Output is verbatim.

**1. "Give me a machine where I can run Testcontainers, and show me Docker actually works in
it."**

Both hosts, identical:

```
docker_version=Docker version 25.0.5, build d260a54c81efcc3f00fe67dee78c94b16c2f8692
result=installed
 Server Version: 25.0.5
 Storage Driver: overlay2
 Docker Root Dir: /var/lib/docker
result=dockerd_up
storage_driver=ok (overlay2)
docker_root_device=ok (/dev/vda)
nested_container=ok (NESTED_OK)
host_network=ok (HOSTNET_OK)
result=docker_ok
```

**2. "Docker worked yesterday and today `dockerd` will not start. Nothing changed."**

Reproduced on both hosts by stopping and starting the machine, then checking before running
anything:

```
Init already completed, skipping 5 command(s)
NO_BIND_MOUNTS_AFTER_RESTART
DOCKERD_DOWN
```

`scripts/start-dockerd.sh` then brought it back to `result=docker_ok` on both, and the images
were still there:

```
$ smolvm machine exec --name smolskill-docker -- docker images --format '{{.Repository}}:{{.Tag}}'
alpine:latest
```

**3. "Can I do this on Windows?"**

**No**, and the answer is short enough to give without running anything: the bundled guest kernel
has `CONFIG_BRIDGE` and `CONFIG_POSIX_MQUEUE` both off, so `dockerd` fails on
`error creating default "bridge" network: operation not supported`, and with `--bridge=none` the
daemon comes up healthy while every container fails on `/dev/mqueue`. That result is from an
earlier run on Windows 11 against v1.14.2. The 2026-09-11 attempt on v1.14.6 died pulling the
image and confirmed nothing either way, so that answer still rests on the one run.

## Re-verified on v1.14.6

Run 2026-09-10 PT against v1.14.6 on macOS 26.6.2 arm64 **and Lima `linux-kvm` (Ubuntu 24.04
aarch64)**: `Docker version 25.0.5`, `Server Version: 25.0.5`, `storage_driver=ok (overlay2)`,
`docker_root_device=ok (/dev/vda)`, `nested_container=ok (NESTED_OK)`,
`host_network=ok (HOSTNET_OK)`, `result=docker_ok` on both. The Linux arm was not re-run on
v1.14.3; it is re-run here.

## What was not run

- **Windows on v1.14.6.** The 2026-09-11 attempt never got past the image pull, so the conclusion
  in `references/windows.md` is still the v1.14.2 one. That page carries a direct kernel probe that
  answers it from a plain `alpine` guest without the large pull.
- **Linux x86_64.** Not run for this use case on any host, then or now.
- **Driving the host-side `docker.sock` from a host `docker` client.** The socket is created and
  asserted; neither host here has a docker client to drive it with.
- **Compose and Testcontainers themselves.** The packet verifies `docker info`, a nested container
  and host networking, which is what those depend on, not the tools.

## Related packets

- `dev-env` for the `init`-runs-once semantics this is built on.
- `install` for the boot this assumes, `teardown` for the cleanup script.
