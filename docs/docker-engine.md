# The Docker Engine API from smolvm

`smolvm engine` answers the Docker Engine API on a Unix socket. The docker CLI, Docker Compose,
Testcontainers and VS Code Dev Containers talk to it as they talk to a Docker daemon, and nothing
runs Docker: every container is a smol machine booted from its image.

## Use it

User installations register the Docker socket automatically on macOS and on Linux with a
systemd user session; Docker connections start the API adapter only when needed.
For a source build or an existing installation, run the setup command once:

```bash
smolvm engine
docker run --rm alpine echo hello
```

Setup registers the socket, selects the `smol` Docker context, and writes `docker.host` to
`~/.testcontainers.properties` unless that file already names another runtime. It reports
which context it replaced; `docker context use <previous>` switches back. No manual engine
startup or persistent central daemon is needed after setup.

A client that does not use Docker contexts can use the same socket:

```bash
export DOCKER_HOST=unix://$HOME/.smolvm/run/docker.sock
```

Testcontainers uses that endpoint to start containers and its Ryuk reaper in machines.
For clients fixed to `/var/run/docker.sock`, `smolvm engine link-socket` links that path to the
same OS-owned socket through `sudo`, preserving an existing endpoint unless `--force` is used.

| Command | What it does |
|---|---|
| `smolvm engine` | configure automatic activation and Docker client integration |
| `smolvm engine status [--json]` | show registration and adapter activity without waking it |
| `smolvm engine link-socket` | link `/var/run/docker.sock` to the same endpoint |

The default socket is `~/.smolvm/run/docker.sock`. Container, image, network, volume, exec,
and event records are stored under the smolvm data directory in `engine/`.

## Process lifetime

The native machine CLI operates directly on machines. Docker clients use a disposable HTTP
adapter, started by `launchd` on macOS or a user `systemd` socket on Linux. After ten seconds
without requests or streams, the adapter exits, even if machines are running. An attached
terminal, followed log, events subscription, image transfer, or build keeps it alive until
that operation ends. The OS keeps the listening socket while the adapter is absent.

Each Docker workload has a supervisor that owns its VM handle, I/O, health checks and restart
policy. Killing or restarting the adapter does not stop containers, published ports or
container networking. The next adapter reads durable records and reconnects to those
supervisors, including exec sessions created before the adapter disappeared. Supervisors
exit after their workloads and outstanding requests finish; one that owns a shared warm
base remains while running branches still need it. No SmolVM process stays resident when
nothing needs it. Native machine operations do not depend on socket activation.

`docker stop` and `docker compose down` remain explicit workload operations. Adapter shutdown is never an instruction to stop workloads. The former engine
start/stop commands are hidden compatibility commands: start performs setup and stop disconnects
only the adapter. Internal serve/supervise commands are service-manager entry points.

When upgrading from the old central engine, stop its containers before replacing its service;
that older process owns their runtime handles and cannot transfer them to the new supervisors.
Registration refuses to replace an occupied socket rather than killing those workloads.

## What a container is

`docker create` makes a machine named `docker-<first 12 characters of the id>` from the image,
with the CPUs and memory the container asks for (`--cpus`, `--memory`). `docker start` boots it and
runs the container's command in it as its main process; when the command exits, the machine stops
and the container is `exited` with the command's exit code. `docker exec` runs in the same
container. Restart policies, health checks (and so Compose's `depends_on: service_healthy`),
`docker pause`, `docker top`, `docker stats`, `docker cp`, `docker logs --follow --timestamps
--tail`, `docker attach`, `docker wait` and `docker rename` work as they do with Docker.

Images are pulled from the image's registry with the credentials in `~/.docker/config.json`,
including credential helpers, or the ones a client sends (`X-Registry-Auth`). A
`[images.registries."docker.io"] mirror` in the smolvm configuration applies to the engine too.

## Moving images

- `docker save` and `docker load` write and read `docker save` archives (and `docker load` reads
  OCI image layouts too). Saving an image pulled from a registry fetches its layers on the host,
  with the same credentials a pull uses.
- `docker commit` makes an image of a container's changes (files written and deleted) on top of
  its image, with its config and any `--change` instructions; `docker export` writes a container's
  whole filesystem as a tar, and `docker import` makes a one-layer image of one (from a file,
  stdin or a URL).
- `docker push` uploads an image to its registry with the credentials in `~/.docker/config.json`
  or the ones the client sends, never through a pull mirror.
- `docker tag` and `docker rmi` work as with Docker.

A pulled image boots from its registry: each container's guest pulls it. Every other image (a
loaded archive, an import, a commit, or a pull from a registry on this host, such as
`localhost:5000`, which a guest cannot reach) is an archive in smolvm's local image cache, booted
as `smolvm machine run --image ./image.tar` boots one.

## Storage

- **Bind mounts** (`-v /host/path:/path`, `--mount type=bind`) share the host directory into the
  machine. A single file can be bound; `:ro` is read-only.
- **Named volumes** are host directories under `engine/volumes/<name>/_data`. A new volume
  mounted over a path the image has files at starts with those files, as with Docker. On Linux,
  the owner a container sets on a volume's files (a database's `chown`) is kept as an extended
  attribute, so it holds without root on the host.
- **Anonymous volumes**: every `VOLUME` an image declares, and every `-v /path` without a
  source, gets a new volume named by a random id, as with Docker, unless something else is
  mounted there. It starts with the image's files at that path, stays with the container across
  restarts (and across a Compose recreate), and goes with `docker rm -v` or `docker volume prune`.
- **`--volumes-from`** mounts another container's volumes and binds at the same paths (`:ro`
  makes them read-only).
- **tmpfs** (`--tmpfs`, `--mount type=tmpfs`) is a tmpfs in the machine.

## Ports

`-p HOST:CONTAINER`, `-p CONTAINER` (a random host port), ranges, `/udp` and `-P` work, and each
port listens where the client asks, as with Docker: `-p 127.0.0.1:8080:80` on loopback only,
`-p 192.168.1.5:8080:80` on that address, `-p [::1]:8080:80` on IPv6 loopback, and a port given no
address on every interface, IPv4 and IPv6. `docker port` lists those addresses.

## Networks

Every machine's network traffic goes through its own user-space network stack on the host. The
engine connects those stacks with a switch:

- The default network, `bridge` (172.17.0.0/16), gives every container an address and a way out,
  and no names, as Docker's default bridge does. `--link` adds the linked names to `/etc/hosts`.
- A user-defined network (`docker network create`, every Compose project) gets its own subnet
  from Docker's pools (172.18-31.0.0/16, then 192.168.N.0/20). Containers on it reach each other by
  address, container name, service name and alias; a name resolves only on the networks the asking
  container shares with it.
- Containers on different networks cannot reach each other at all, by name or address.
- `docker network connect` and `disconnect` work on running containers.
- `--internal` networks have no way out.
- `--ipv6` (Compose's `enable_ipv6: true`) gives a network an IPv6 subnet as well, the one the
  client names or a unique-local /64: each container gets an IPv6 address on it, reachable by the
  others on the network (and only them), and its names answer AAAA queries too.
- `host.docker.internal` and `gateway.docker.internal` reach the host from every container.

`--network container:<name>` (Compose's `network_mode: service:<name>`) runs the container in the
other container's machine, so it shares its network (loopback included) and its hostname, as with
Docker, while keeping its own filesystem and mounts. The other container has to be running, and
the container stops if it does. Such a container cannot publish ports or mount a Unix socket.
`--network host` is accepted with a warning and gives the container the default network: a
container is a machine and cannot share the host's network.

## The Docker socket inside a container

A container that mounts the engine's socket, or `/var/run/docker.sock`, at any path reaches the
engine through it, so a tool in a container can start sibling containers as it would with Docker:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker:cli docker ps
```

No environment variable is needed. This works whether or not `/var/run/docker.sock` exists on
the host.

## Warm bases

When three or more containers of one image (at the same size) run at once, the engine boots one
more machine from the image with nothing running in it, the image's base, and later containers of
the image branch from it instead of booting. A branched container starts from the base's memory
and disks and shares them until it writes: on a Mac, an `alpine` container that sleeps costs
about 55 MB of its own memory branched and about 230 MB booted, while the base costs about as much
as one booted container. A branch starts no faster than a boot, so an image run one container at
a time never gets a base. A base belongs to its workload supervisor, so adapter exits do not retire it; an unused base is retired after two minutes; it is stopped once no
container branched from it runs, and deleted with the last one.

Branching is on for macOS. On Linux, a branch's disks are copy-on-write overlay images that take
writes several times slower than a booted machine's disks, which a database in a container
notices, so containers boot there. `SMOLVM_ENGINE_BRANCH=1` in the engine's environment turns
branching on, and `SMOLVM_ENGINE_BRANCH=0` turns it off.

A container branches only on its first start, and only when it mounts no host directory or
socket: mounts are devices a machine boots with.

## Building images

The engine does not embed a builder: the legacy `POST /build`, `/session` and `/grpc`
endpoints return an unsupported-operation error. Use Buildx's `docker-container` driver to
run BuildKit inside a smol machine and load the result back into the engine.

What the clients send, for whoever adds builds:

- `docker build` with buildx (the default since Docker 23) first opens `POST /grpc`, an HTTP/2
  connection upgraded from HTTP/1.1, to reach the BuildKit embedded in a Docker daemon. When that
  fails, buildx creates a builder of its own: it pulls `moby/buildkit:buildx-stable-1`, creates and
  starts a container from it, and talks BuildKit's gRPC to it through `docker exec`. Against this
  engine that container is an ordinary container, so this path needs no build endpoint at all:
  `docker buildx create --driver docker-container` then `docker buildx build --load` builds, and
  the image comes back through `docker load`, including builds with `RUN` steps.
- `DOCKER_BUILDKIT=0 docker build` uses the classic `POST /build?t=<tag>&dockerfile=<path>` with
  the build context as a tar body, and reads a JSON progress stream back.
- `docker compose build` hands the build to buildx (`bake`), with the same two paths;
  `COMPOSE_BAKE=false` makes Compose use its own BuildKit client on `POST /grpc`.
- Every client checks `GET /_ping`, whose `Builder-Version` header says which builder the daemon
  offers (`1`, classic, here).

## Not yet

- Network drivers other than `bridge`, and IPv6 on the default `bridge` network.
- Changing an internal network's egress after a container on it was created.

## Validate process lifetime

Against an isolated, registered test engine, set `DOCKER_HOST` and
`SMOLVM_ENGINE_TEST_ROOT` to its socket and state directory, then run
`python3 tests/test_engine_lifecycle.py`; it kills the adapter, checks workload survival,
and verifies that supervisors exit after cleanup. On macOS, also run
`python3 tests/test_engine_warm_lifecycle.py` to check that a warm branch outlives its
original workload owner and releases its base when the final branch is removed.
Run these tests sequentially on an engine without other workloads.
