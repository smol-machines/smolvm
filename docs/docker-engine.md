# The Docker Engine API from smolvm

`smolvm engine` answers the Docker Engine API on a Unix socket. The docker CLI, Docker Compose,
Testcontainers and VS Code Dev Containers talk to it as they talk to a Docker daemon, and nothing
runs Docker: every container is a smol machine booted from its image.

## Start it

```bash
smolvm engine start
docker run --rm alpine echo hello
```

`smolvm engine start` runs the engine in the background (its log is `engine/engine.log` in the
smolvm data directory), creates the docker context `smol` for its socket and selects it, and
writes `docker.host` to `~/.testcontainers.properties` unless that file already names another
daemon. It prints what it changed, including the context it replaced, so `docker context use
<previous>` switches back.

Without the context, point a client at the socket yourself:

```bash
export DOCKER_HOST=unix://$HOME/.smolvm/run/docker.sock
```

Testcontainers needs nothing else: with `DOCKER_HOST` set (or the properties file), the Node,
Python, Go and Java libraries start their containers and their Ryuk reaper in machines.

Some tools only look at `/var/run/docker.sock`. `smolvm engine link-socket` links that path to the
engine's socket, through `sudo`; `--print` shows the command instead, and an existing
`/var/run/docker.sock` that is not a link to the engine is left alone unless `--force` is given.

| Command | What it does |
|---|---|
| `smolvm engine start` | start in the background, select the `smol` context |
| `smolvm engine status [--json]` | whether it runs, its socket and process |
| `smolvm engine stop` | stop it; running containers stop with it, as with a daemon without live restore |
| `smolvm engine serve` | run in the foreground |
| `smolvm engine link-socket` | link `/var/run/docker.sock` to the engine's socket |

Each takes `--socket PATH` for a socket other than `~/.smolvm/run/docker.sock`. The engine keeps
its records under the smolvm data directory, in `engine/`: one JSON file per container, image,
volume and network, and each container's log in Docker's `json-file` format.

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
- `host.docker.internal` and `gateway.docker.internal` reach the host from every container.

`--network host` is accepted with a warning and gives the container the default network: a
container is a machine and cannot share the host's network. `--network container:<name>` is
refused for the same reason.

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
a time never gets a base. A base unused for two minutes is retired; it is stopped once no
container branched from it runs, and deleted with the last one.

Branching is on for macOS. On Linux, a branch's disks are copy-on-write overlay images that take
writes several times slower than a booted machine's disks, which a database in a container
notices, so containers boot there. `SMOLVM_ENGINE_BRANCH=1` in the engine's environment turns
branching on, and `SMOLVM_ENGINE_BRANCH=0` turns it off.

A container branches only on its first start, and only when it mounts no host directory or
socket: mounts are devices a machine boots with.

## Building images

The engine does not build images. `POST /build` (`DOCKER_BUILDKIT=0 docker build`, `docker
compose build` with `DOCKER_BUILDKIT=0`), `/session`, `/grpc` and `POST /images/load` answer with
an error that says so. Build the image elsewhere, push it to a registry the engine can pull from,
and refer to it by name.

What the clients send, for whoever adds builds:

- `docker build` with buildx (the default since Docker 23) first opens `POST /grpc`, an HTTP/2
  connection upgraded from HTTP/1.1, to reach the BuildKit embedded in a Docker daemon. When that
  fails, buildx creates a builder of its own: it pulls `moby/buildkit:buildx-stable-1`, creates and
  starts a container from it, and talks BuildKit's gRPC to it through `docker exec`. Against this
  engine that container is an ordinary container, so this path needs no build endpoint at all.
- `DOCKER_BUILDKIT=0 docker build` uses the classic `POST /build?t=<tag>&dockerfile=<path>` with
  the build context as a tar body, and reads a JSON progress stream back.
- `docker compose build` hands the build to buildx (`bake`), with the same two paths;
  `COMPOSE_BAKE=false` makes Compose use its own BuildKit client on `POST /grpc`.
- Every client checks `GET /_ping`, whose `Builder-Version` header says which builder the daemon
  offers (`1`, classic, here).

## Not yet

- IPv6 networks, other network drivers than `bridge`, and `--network container:<name>`.
- `docker save`, `docker load`, `docker push` and `docker commit`.
- Changing an internal network's egress after a container on it was created.
