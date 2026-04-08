# smolvm — Agent Reference

A tool to build and run portable, self-contained virtual machines locally. <200ms boot time. No daemon, no Docker.

## Quick Reference

```bash
# Ephemeral (cleaned up after exit)
smolvm machine run --net --image alpine -- echo hello
smolvm machine run --net -it --image alpine -- /bin/sh   # interactive shell
smolvm machine run --net --image python:3.12-alpine -- python3 script.py

# Persistent (survives across exec sessions and stop/start)
smolvm machine create --net myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add python3   # installs persist
smolvm machine exec --name myvm -- which python3      # still there
smolvm machine exec --name myvm -it -- /bin/sh
smolvm machine stop --name myvm
smolvm machine delete myvm

# Image-based persistent (filesystem changes persist across exec sessions)
smolvm machine create --net --image ubuntu myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apt-get update
smolvm machine exec --name myvm -- apt-get install -y python3
smolvm machine exec --name myvm -- which python3      # still there after exit+re-exec

# SSH agent forwarding (git/ssh without exposing keys)
smolvm machine run --ssh-agent --net --image alpine -- ssh-add -l
smolvm machine create myvm --ssh-agent --net

# Pack into portable executable
smolvm pack create --image python:3.12-alpine -o ./my-python
./my-python run -- python3 -c "print('hello')"
```

## When to Use What

| Goal | Command |
|------|---------|
| Run a one-off command in isolation | `smolvm machine run --net --image IMAGE -- CMD` |
| Interactive shell | `smolvm machine run --net -it --image IMAGE -- /bin/sh` |
| Persistent dev environment | `machine create` → `machine start` → `machine exec` |
| Ship software as a binary | `smolvm pack create --image IMAGE -o OUTPUT` |
| Use git/ssh with private keys safely | Add `--ssh-agent` to run or create |
| Minimal VM without image | `smolvm machine run -s Smolfile` (bare VM) |
| Declarative VM config | Create a Smolfile, use `--smolfile`/`-s` flag |

### Persistence Model

- **`machine run`** — ephemeral. All changes are discarded when the command exits.
- **`machine exec`** — persistent. Filesystem changes (package installs, config edits) persist across exec sessions for the same machine, whether bare or image-based. Changes are stored in an overlay on the machine's storage disk.
- **`machine stop` + `start`** — bare VMs persist changes across restarts. Image-based VMs remount the persistent overlay, preserving previous changes.

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
smolvm machine cp SRC DST                         # copy files (host↔VM)
smolvm machine exec --stream --name NAME -- CMD   # streaming output
smolvm machine monitor [--name NAME]              # foreground health + restart

smolvm pack create --image IMAGE -o PATH          # package
smolvm pack create --from-vm NAME -o PATH         # pack from VM snapshot
smolvm pack run [--sidecar PATH] [-- CMD]         # run .smolmachine

smolvm serve start [--listen ADDR:PORT]           # HTTP API
smolvm config registries edit                     # registry auth
```

## Key Flags

| Flag | Short | Used on | Description |
|------|-------|---------|-------------|
| `--image` | `-I` | run, create, pack create | OCI image |
| `--name` | `-n` | start, stop, status, exec, resize | Machine name (default: "default") |
| `--net` | | run, create | Enable outbound networking (off by default) |
| `--volume` | `-v` | run, create | Mount host dir: `HOST:GUEST[:ro]` |
| `--port` | `-p` | run, create | Port mapping: `HOST:GUEST` |
| `--smolfile` | `-s` | run, create, pack create | Load config from Smolfile |
| `--interactive` | `-i` | run, exec | Keep stdin open |
| `--tty` | `-t` | run, exec | Allocate pseudo-TTY |
| `--allow-cidr` | | run, create | CIDR egress filter (implies --net) |
| `--allow-host` | | run, create | Hostname egress filter, resolved at VM start (implies --net) |
| `--ssh-agent` | | run, create | Forward host SSH agent (git/ssh without exposing keys) |

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
cpus = 2                              # vCPUs (default: 4)
memory = 1024                         # MiB (default: 8192, elastic via balloon)
net = true                            # outbound networking (default: false)
storage = 40                          # storage disk GiB (default: 20)
overlay = 4                           # overlay disk GiB (default: 2)

# Network policy — egress filtering by hostname and/or CIDR
[network]
allow_hosts = ["api.stripe.com"]      # resolved at VM start (implies net)
allow_cidrs = ["10.0.0.0/8"]         # IP/CIDR ranges (implies net)

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

# Health check (used by `machine monitor`)
[health]
exec = ["curl", "-f", "http://127.0.0.1:8080/health"]
interval = "10s"
timeout = "2s"
retries = 3
startup_grace = "20s"

# Credential forwarding
[auth]
ssh_agent = true                      # forward host SSH agent into the VM
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
cpus/mem:   CLI flag > Smolfile > defaults (4 CPU, 8192 MiB)
```

## Networking

- **Off by default** — VMs have no outbound access unless `--net` is specified
- `--net` enables full outbound (TCP/UDP, DNS)
- `--allow-host api.stripe.com` enables egress only to resolved IPs of that hostname (implies `--net`). Also enables DNS filtering — only allowed hostnames can be resolved.
- `--allow-cidr 10.0.0.0/8` enables egress only to specified IP ranges (implies `--net`)
- `--allow-host` and `--allow-cidr` can be combined and used multiple times
- `--outbound-localhost-only` restricts to 127.0.0.0/8 and ::1 (implies `--net`)
- `-p HOST:GUEST` forwards a host port to the VM (TCP)
- Smolfile: use `[network] allow_hosts` and `[network] allow_cidrs`

## SSH Agent Forwarding

Forward the host's SSH agent into the VM so git, ssh, and scp work with your keys — without the private keys ever entering the VM.

```bash
# CLI flag
smolvm machine run --ssh-agent --net --image alpine -- ssh-add -l
smolvm machine create myvm --ssh-agent --net

# Smolfile
# [auth]
# ssh_agent = true
```

Inside the VM, `SSH_AUTH_SOCK` is set automatically. Any tool that uses the SSH agent protocol (git, ssh, scp) works transparently:

```bash
smolvm machine exec --name myvm -- git clone git@github.com:org/private-repo.git
smolvm machine exec --name myvm -- ssh deploy@server "systemctl restart app"
```

The host SSH agent signs challenges but never sends private keys across the boundary. Even with root inside the VM, keys cannot be extracted — this is enforced by the SSH agent protocol and the hypervisor isolation.

Requires `SSH_AUTH_SOCK` to be set on the host. If missing, smolvm exits with an error and remediation instructions.

## File Copy

Copy files between the host and a running machine using `machine:path` syntax:

```bash
# Upload a file to the VM
smolvm machine cp ./script.py myvm:/workspace/script.py

# Download a file from the VM
smolvm machine cp myvm:/workspace/output.json ./output.json
```

## Streaming Exec

Stream command output in real-time instead of buffering:

```bash
# CLI — prints output as it arrives
smolvm machine exec --stream --name myvm -- python3 train.py

# API — Server-Sent Events
POST /api/v1/machines/:name/exec/stream
Content-Type: application/json
{"command": ["python3", "train.py"]}

# Response: text/event-stream
# event: stdout
# data: Epoch 1/10...
# event: exit
# data: {"exitCode":0}
```
## Bare VM Mode

`machine run` works without `--image` when a Smolfile provides the workload config, or for direct Alpine shell access:

```bash
# Bare Alpine shell
smolvm machine run

# Smolfile with entrypoint/cmd (no container overhead)
smolvm machine run -s Smolfile

# Bare VM with init setup, detached
smolvm machine run -d -s Smolfile
```

Bare VMs run commands directly in the Alpine rootfs — no OCI image pull needed. Use this when you need a minimal Linux environment.

## Packed Binaries (.smolmachine)

`smolvm pack create` produces two files:
- `my-app` — stub binary with embedded VM runtime (platform-specific)
- `my-app.smolmachine` — VM payload: rootfs, OCI layers, storage (cross-platform)

The packed binary runs as a normal executable:
```bash
./my-app run -- python3 -c "print('hello')"  # ephemeral, cleaned up after exit
./my-app start                               # persistent daemon mode
./my-app exec -- pip install x               # exec into daemon
./my-app stop                                # stop daemon
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
POST   /api/v1/machines/:name/exec/stream  Streaming exec (SSE)
PUT    /api/v1/machines/:name/files/*path  Upload file
GET    /api/v1/machines/:name/files/*path  Download file
GET    /api/v1/machines/:name/logs         Stream logs (SSE)
POST   /api/v1/machines/:name/images/pull  Pull OCI image
```

OpenAPI spec: `smolvm serve openapi`

## Important Defaults

- Machine name defaults to `"default"` when `--name` is omitted
- Network is **off** by default (security-first)
- CPUs: 4, Memory: 8192 MiB (elastic via virtio balloon), Storage: 20 GiB, Overlay: 2 GiB
- Packed binary CPUs: 1, Memory: 256 MiB (lighter defaults for single-purpose workloads)
- Memory is elastic — the host only commits what the guest actually uses and reclaims the rest via virtio balloon
