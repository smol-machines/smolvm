# smolvm — Agent Reference

A tool to build and run portable, self-contained virtual machines locally. <200ms boot time. No daemon, no Docker.

## Quick Reference

```bash
# Ephemeral (cleaned up after exit)
smolvm machine run --image alpine -- echo hello
smolvm machine run -it --image alpine                    # interactive shell
smolvm machine run --image python:3.12-alpine -- python3 script.py

# Persistent (survives stop/start)
smolvm machine create --net myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add python3
smolvm machine exec --name myvm -it -- /bin/sh
smolvm machine stop --name myvm
smolvm machine delete myvm

# Pack into portable executable
smolvm pack create --image python:3.12-alpine -o ./my-python
./my-python python3 -c "print('hello')"

# Containers inside a machine
smolvm container create --image nginx -- nginx -g "daemon off;"
smolvm container ls
smolvm container exec --container abc123 -- curl localhost
```

## When to Use What

| Goal | Command |
|------|---------|
| Run a one-off command in isolation | `smolvm machine run --image IMAGE -- CMD` |
| Interactive shell | `smolvm machine run -it --image IMAGE` |
| Persistent dev environment | `machine create` → `machine start` → `machine exec` |
| Run containers inside a VM | `machine start` → `container create` |
| Ship software as a binary | `smolvm pack create --image IMAGE -o OUTPUT` |
| Declarative VM config | Create a Smolfile, use `--smolfile`/`-s` flag |

## CLI Structure

All commands use named flags (no positional args except `machine create NAME` and `machine delete NAME`).

```
smolvm machine run --image IMAGE [-- COMMAND]     # ephemeral
smolvm machine exec --name NAME [-- COMMAND]      # run in existing VM
smolvm machine create NAME [OPTIONS]              # create persistent
smolvm machine start [--name NAME]                # start (default: "default")
smolvm machine stop [--name NAME]                 # stop
smolvm machine delete NAME [-f]                   # delete
smolvm machine status [--name NAME]               # check state
smolvm machine ls [--json]                        # list all

smolvm container create --image IMAGE [-- CMD]    # --machine defaults to "default"
smolvm container exec --container ID [-- CMD]
smolvm container stop --container ID
smolvm container rm --container ID [-f]
smolvm container ls                               # --machine defaults to "default"

smolvm pack create --image IMAGE -o PATH          # package
smolvm pack create --from-vm NAME -o PATH         # pack from VM snapshot
smolvm pack run [--sidecar PATH] [-- CMD]         # run .smolmachine

smolvm serve start [--listen ADDR:PORT]           # HTTP API
smolvm config registries edit                     # registry auth
```

## Key Flags

| Flag | Short | Used on | Description |
|------|-------|---------|-------------|
| `--image` | `-I` | run, container create, pack create | OCI image |
| `--name` | `-n` | start, stop, status, exec, resize | Machine name (default: "default") |
| `--machine` | `-m` | container commands | Target machine (default: "default") |
| `--container` | `-c` | container start/stop/rm/exec | Container ID |
| `--net` | | run, create | Enable outbound networking (off by default) |
| `--volume` | `-v` | run, create | Mount host dir: `HOST:GUEST[:ro]` |
| `--port` | `-p` | run, create | Port mapping: `HOST:GUEST` |
| `--smolfile` | `-s` | run, create, pack create | Load config from Smolfile |
| `--interactive` | `-i` | run, exec | Keep stdin open |
| `--tty` | `-t` | run, exec | Allocate pseudo-TTY |
| `--allow-cidr` | | run, create | CIDR egress filter (implies --net) |

## Smolfile Reference

A Smolfile is a TOML file declaring a VM workload. Use with `--smolfile`/`-s`.

```toml
# Top-level: workload definition
image = "python:3.12-alpine"          # OCI image (omit for bare Alpine)
entrypoint = ["/app/run"]             # overrides image ENTRYPOINT
cmd = ["serve"]                       # overrides image CMD
env = ["PORT=8080", "DEBUG=1"]        # environment variables
workdir = "/app"                      # working directory

# Resources
cpus = 2                              # vCPUs (default: 1)
memory = 1024                         # MiB (default: 512)
net = true                            # outbound networking (default: false)
storage = 40                          # storage disk GiB (default: 20)
overlay = 4                           # overlay disk GiB (default: 2)
allowed_cidrs = ["10.0.0.0/8"]        # egress CIDR filter (implies net)

# Dev profile (used by `machine run` and `machine create`)
[dev]
volumes = ["./src:/app"]              # host bind mounts
ports = ["8080:8080"]                 # port forwarding
init = ["pip install -r requirements.txt"]  # run on every VM start
env = ["APP_MODE=dev"]                # dev-only env (extends top-level)
workdir = "/app"                      # dev-only workdir

# Artifact profile (used by `pack create`)
[artifact]
cpus = 4                              # override resources for distribution
memory = 2048
entrypoint = ["/app/run"]             # override entrypoint for packed binary
oci_platform = "linux/amd64"          # target OCI platform

# Service (parsed, not yet wired)
[service]
listen = 8080
protocol = "http"

# Health check (parsed, not yet wired)
[health]
exec = ["curl", "-f", "http://127.0.0.1:8080/health"]
interval = "10s"
timeout = "2s"
retries = 3
```

### Merge Precedence

CLI flags override Smolfile values:

```
image:      --image flag > Smolfile image > None (bare Alpine)
entrypoint: Smolfile entrypoint > image metadata
cmd:        trailing args (after --) > Smolfile cmd > image metadata
env:        top-level env + [dev].env + CLI -e (all merged)
volumes:    [dev].volumes + CLI -v (all merged)
ports:      [dev].ports + CLI -p (all merged)
init:       [dev].init + CLI --init (all merged)
cpus/mem:   CLI flag > Smolfile > defaults (1 CPU, 512 MiB)
```

## Networking

- **Off by default** — VMs have no outbound access unless `--net` is specified
- `--net` enables full outbound (TCP/UDP, DNS)
- `--allow-cidr 10.0.0.0/8` enables egress only to specified ranges (implies `--net`)
- `--outbound-localhost-only` restricts to 127.0.0.0/8 and ::1 (implies `--net`)
- `-p HOST:GUEST` forwards a host port to the VM (TCP)

## Packed Binaries (.smolmachine)

`smolvm pack create` produces two files:
- `my-app` — stub binary with embedded VM runtime (platform-specific)
- `my-app.smolmachine` — VM payload: rootfs, OCI layers, storage (cross-platform)

The packed binary runs as a normal executable:
```bash
./my-app python3 -c "print('hello')"    # ephemeral, cleaned up after exit
./my-app --daemon start                  # persistent daemon mode
./my-app --daemon exec -- pip install x  # exec into daemon
./my-app --daemon stop                   # stop daemon
```

## HTTP API

Start with `smolvm serve start --listen 127.0.0.1:8080`. Key endpoints:

```
POST   /api/v1/machines                    Create machine
GET    /api/v1/machines                    List machines
GET    /api/v1/machines/:name              Get machine
POST   /api/v1/machines/:name/start        Start machine
POST   /api/v1/machines/:name/stop         Stop machine
DELETE /api/v1/machines/:name              Delete machine
POST   /api/v1/machines/:name/exec         Execute command
GET    /api/v1/machines/:name/logs         Stream logs (SSE)
POST   /api/v1/machines/:name/images/pull  Pull OCI image
```

OpenAPI spec: `smolvm serve openapi`

## Important Defaults

- Machine name defaults to `"default"` when `--name` is omitted
- Container `--machine` defaults to `"default"`
- Network is **off** by default (security-first)
- CPUs: 1, Memory: 512 MiB, Storage: 20 GiB, Overlay: 2 GiB
- Packed binary CPUs: 1, Memory: 256 MiB (lighter defaults for single-purpose workloads)
