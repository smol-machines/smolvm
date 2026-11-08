# The Docker Engine API from smolvm

`smolvm engine` answers the Docker Engine API on a Unix socket. The docker CLI talks to it as it
talks to a Docker daemon, and nothing runs Docker: every container is a smol machine booted from
its image.

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
container. Restart policies, health checks, `docker pause`, `docker top`, `docker stats`,
`docker cp`, `docker logs --follow --timestamps --tail`, `docker attach`, `docker wait` and
`docker rename` work as they do with Docker.

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
- **tmpfs** (`--tmpfs`, `--mount type=tmpfs`) is a tmpfs in the machine.

## Ports

`-p HOST:CONTAINER`, `-p CONTAINER` (a random host port), ranges, `/udp` and `-P` work. Published
ports listen on the host's loopback addresses, `127.0.0.1` and `::1`, whatever address the client
gives, as every smolvm machine's ports do; `SMOLVM_PUBLISH_ADDR=0.0.0.0` in the engine's
environment makes them listen on every interface.

## Networks

Every machine's network traffic goes through its own user-space network stack on the host. The
engine connects those stacks with a switch, and every container is on the default network,
`bridge` (172.17.0.0/16), as with Docker's default bridge:

- A container gets an address, reaches the other containers by address, and has a way out.
- Names do not resolve on it, as on Docker's default bridge; `--link` adds the linked names to
  `/etc/hosts`.
- `host.docker.internal` and `gateway.docker.internal` reach the host from every container.

`docker network ls` and `inspect` show `bridge`, `host` and `none`. `--network host` is accepted
with a warning and gives the container the default network: a container is a machine and cannot
share the host's network. `--network container:<name>` is refused for the same reason.

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

- User-defined networks (`docker network create`, `connect` and `disconnect`), and so Docker
  Compose, which creates one for every project.
- IPv6 networks, other network drivers than `bridge`, and `--network container:<name>`.
- Binding a Unix socket into a container, the Docker socket included.
- `docker save`, `docker load`, `docker push` and `docker commit`.
- A listening address per published port (`-p 0.0.0.0:8080:80`).
- A volume for each `VOLUME` an image declares: that path stays in the container's own filesystem.
