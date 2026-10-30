# smolvm — Agent Reference

A tool to build and run portable, self-contained virtual machines locally. <200ms boot time. No daemon, no Docker.

## Platform Support

| Host | Guest | Hypervisor | Requirements |
|------|-------|------------|--------------|
| macOS Apple Silicon | arm64 Linux | Hypervisor.framework | macOS 11+ |
| Linux x86_64 / aarch64 | matching Linux | KVM | `/dev/kvm` |
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform (WHP) | WHP feature enabled |

Windows caveats (branches need `--freeze-source`, checkpoint capture rejects active virtiofs DAX mappings, no GPU acceleration, the pack templates): `docs/limitations.md`. Set `SMOLVM_LIB_DIR` (folder holding `krun.dll` + `libkrunfw.dll`) and `SMOLVM_AGENT_ROOTFS` when running from a non-standard layout.

## Documentation

Skill packets, tested procedures an agent can follow with their scripts, and the reference page
for each feature are indexed in `docs/README.md`
(https://github.com/smol-machines/smolvm/tree/main/docs).

## Quick Reference

```bash
# Ephemeral (cleaned up after exit)
smolvm machine run --net --image alpine -- echo hello
smolvm machine run --net -it --image alpine -- /bin/sh   # interactive shell
smolvm machine run --net --image python:3.12-alpine -- python3 script.py

# Persistent (survives across exec sessions and stop/start)
smolvm machine create --net --name myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apk add python3   # installs persist
smolvm machine exec --name myvm -- which python3      # still there
smolvm machine shell --name myvm               # interactive shell (machine must be running)
smolvm machine stop --name myvm
smolvm machine delete --name myvm

# Image-based persistent (filesystem changes persist across exec sessions)
smolvm machine create --net --image ubuntu --name myvm
smolvm machine start --name myvm
smolvm machine exec --name myvm -- apt-get update
smolvm machine exec --name myvm -- apt-get install -y python3
smolvm machine exec --name myvm -- which python3      # still there after exit+re-exec

# SSH agent forwarding (git/ssh without exposing keys) — see "SSH Agent Forwarding" below
smolvm machine run --ssh-agent --net --image alpine -- sh -c "apk add -q openssh-client && ssh-add -l"
smolvm machine create --name myvm --image alpine --ssh-agent --net   # persistent: then start + exec git/ssh

# Inject secrets into workload env (referenced from host env var / file)
smolvm machine run --secret-env OPENAI_API_KEY=OPENAI_API_KEY -- ./app
smolvm machine run -s Smolfile -- ./app   # Smolfile [secrets] resolves at launch

# Pack into portable executable
smolvm pack create --image python:3.12-alpine -o ./my-python
./my-python run -- python3 -c "print('hello')"

# Create machine from packed artifact (fast start, no pull)
smolvm machine create --name my-vm --from ./my-python.smolmachine
smolvm machine start --name my-vm
smolvm machine exec --name my-vm -- pip install requests

# Use local container images (CI, air-gapped, fast iteration)
docker save myapp:latest -o myapp.tar
smolvm machine run --image ./myapp.tar -- ./app           # from a docker/podman save archive
docker save myapp:latest | smolvm machine run --image - -- ./app   # from stdin
smolvm machine run --image ./rootfs/ -- ./app             # from an unpacked rootfs dir
smolvm machine create --name myvm --image ./myapp.tar     # persistent, from a local archive
```

## When to Use What

| Goal | Command |
|------|---------|
| Run a one-off command in isolation | `smolvm machine run --net --image IMAGE -- CMD` |
| Interactive shell (ephemeral) | `smolvm machine run --net -it --image IMAGE -- /bin/sh` |
| Interactive shell (persistent) | `smolvm machine shell --name NAME` |
| Persistent dev environment | `machine create` → `machine start` → `machine exec` |
| Ship software as a binary | `smolvm pack create --image IMAGE -o OUTPUT` |
| Fast persistent machine from packed artifact | `machine create --name NAME --from FILE.smolmachine` |
| Use local container images (CI / air-gapped / fast iteration) | `--image ./archive.tar`, `--image -` (stdin), or `--image ./rootfs/` |
| Use git/ssh with private keys safely | Add `--ssh-agent` to run or create |
| Inject API keys / tokens without putting them on the command line | `--secret-env`/`--secret-file` flags or Smolfile `[secrets]` |
| Minimal VM without image | `smolvm machine run -s Smolfile` (bare VM) |
| Change mounts/ports/resources on existing VM | `machine update --name NAME -v ./src:/app -p 8080:8080` |
| Mount a host dir into a running VM, no restart | `machine mount add --name NAME -v ./src:/app` (until it stops) |
| Declarative VM config | Create a Smolfile, use `--smolfile`/`-s` flag |
| Move a running machine from an arm64 Mac to arm64 Linux | `machine checkpoint --name NAME -o FILE.checkpoint` on the Mac, then `machine create --name NAME --from FILE.checkpoint` + `machine start` on Linux ([details](docs/mac-to-linux.md)) |

### Persistence Model

`machine run` is ephemeral unless `-d` keeps the machine as a named one that
`exec` and `stop` act on. `machine exec` changes persist in an overlay on the
machine's storage disk, bare or image-based, across exec sessions and a stop and
start. `pack run` starts fresh each time, while `pack start` + `exec` and
`machine create --from .smolmachine` persist. `/tmp`, `/run` and `/dev/shm` are
tmpfs and empty after a restart, so write what must survive to `/workspace`.
Every mode, `--stop-on-exit` and the tmpfs details: `docs/dev-env/README.md`.

## CLI Structure

All commands name a machine with `--name`, never a positional (`machine cp SRC DST` takes its two paths as positionals).

```
smolvm machine run --image IMAGE [-- COMMAND]     # ephemeral
smolvm machine exec --name NAME [-- COMMAND]      # run in existing VM
smolvm machine shell [--name NAME]                # interactive shell (must be running)
smolvm machine create --name NAME [OPTIONS]              # create persistent
smolvm machine create --name NAME --from FILE.smolmachine  # from packed artifact
smolvm machine start [--name NAME]                # start (default: "default")
smolvm machine stop [--name NAME] [--timeout SECS]  # stop (workload gets SIGTERM first)
smolvm machine logs [--name NAME] [-f] [--tail N] # workload stdout/stderr, even when stopped
smolvm machine delete --name NAME [-f]                   # delete
smolvm machine status [--name NAME]               # check state
smolvm machine stats [--name NAME] [--json]       # CPU % and guest memory
smolvm machine ls [--json]                        # list all
smolvm machine update --name NAME [OPTIONS]              # modify stopped machine settings
smolvm machine mount add --name NAME -v HOST:GUEST[:ro] # mount into a running machine (until it stops)
smolvm machine mount rm --name NAME -t GUEST              # unmount it, revoking open files
smolvm machine mount ls --name NAME [--json]              # list mounts added this boot
smolvm machine cp SRC DST                         # copy files (host↔VM)
smolvm machine exec --stream --name NAME -- CMD   # streaming output
smolvm machine monitor [--name NAME]              # foreground health + restart

smolvm pack create --image IMAGE -o PATH          # package
smolvm pack create --from-vm NAME -o PATH         # pack from VM snapshot
smolvm pack run [--sidecar PATH] [-- CMD]         # run .smolmachine
smolvm pack pull REF [-o PATH]                    # pull .smolmachine into the cache
smolvm pack list [--json]                         # pulled artifacts and their paths

smolvm serve start [--listen ADDR:PORT|PATH]      # HTTP API
smolvm config registries edit                     # registry auth
smolvm completion bash|zsh|fish|powershell|elvish # print a shell completion script
smolvm <any command> --error-format json        # failures as {"error":{"code":"NOT_FOUND","message":…}}
```

## Artifact References

Artifact references follow OCI conventions and support both tags and digests:

```
python-dev                                        # bare name (default registry + latest)
python-dev:v1.0                                   # name + tag
binsquare/custom:v1                               # namespace + name + tag
smolmachines.com/python-dev:latest                # registry + name + tag
smolmachines.com/binsquare/custom:v1              # registry + namespace + name + tag
python-dev@sha256:abcdef0123...                   # digest reference (immutable)
```

Default registry: `registry.smolmachines.com`. Digest references require `sha256:` followed by exactly 64 hex characters.

### Local container images

`--image` also accepts a local source — useful for CI, air-gapped hosts, and fast
local iteration. smolvm accepts Docker-save and OCI layout archives, recovers
their image configuration, and delegates filesystem flattening to `crane export`.

```
./image.tar  ./image.tar.gz  ./image.tgz   # Docker-save or OCI layout archive (gzip ok)
-                                           # the same archive streamed on stdin
./rootfs/                                   # an already-unpacked root filesystem directory
```

A source is treated as local when it starts with `/`, `./`, `../`, is `-`, or ends in
`.tar`/`.tar.gz`/`.tgz`; everything else is a registry reference (so bare `alpine`
still pulls). Archives are cached content-addressed by hash and re-resolved on
`machine start`. `--image -` cannot be combined with `-i`/`-t` (both read stdin).

smolvm boots images, it does not build them: a Dockerfile passed to `--image` is
rejected with a hint to build first (`docker build … && docker save … | … --image -`).

## Key Flags

| Flag | Short | Used on | Description |
|------|-------|---------|-------------|
| `--image` | `-I` | run, create, pack create | OCI image, or a local source: a Docker-save/OCI archive (`./img.tar`, or `-` for stdin) or unpacked rootfs dir (`./rootfs/`) |
| `--name` | `-n` | run, start, stop, status, exec, update | Machine name (default: "default"); `exec` takes only the long form |
| `--net` | | run, create, update, pack run | Enable outbound networking (off by default) |
| `--gpu` | | run, create, update, pack create | Enable GPU acceleration (Vulkan via virtio-gpu) |
| `--gpu-vram` | | run, create | GPU shared-memory region size in MiB (default: 4096). Ignored without `--gpu`. |
| `--volume` | `-v` | run, create, update, pack run | Mount host dir: `HOST:GUEST[:ro]`, or `GUEST` alone for a directory on the machine's own disk (`-v /var/lib/docker`), which starts with the image's owner and mode at that path, or the ones given as `GUEST:uid=UID,gid=GID,mode=OCTAL` (applied when created or changed, so an in-machine `chown` persists) |
| `--allow-system-mounts` | | run, create, update, pack run | Permit trusted read-only `/etc` and `/var/log` mounts below `/host` |
| `--port` | `-p` | run, create, update, pack run | Port mapping: `HOST:GUEST`, or `HOST:GUEST/udp` for UDP |
| `--smolfile` | `-s` | run, create, pack create | Load config from Smolfile |
| `--interactive` | `-i` | run, exec, pack run | Keep stdin open |
| `--tty` | `-t` | run, exec, pack run | Allocate pseudo-TTY |
| `--allow-cidr` | | run, create, update | CIDR egress filter (implies --net) |
| `--block-private` | | run, create | Block private and internal destinations, keep the public internet (implies --net) |
| `--allow-private` | | run, create | Re-open one private CIDR under `--block-private` |
| `--deny-cidr` | | run, create | Deny egress to a CIDR, checked before anything is allowed (implies --net) |
| `--allow-udp` | | run, create, update | Allow UDP to `CIDR[:PORT[-END]]`, also under an egress interceptor; a deny still wins (implies --net) |
| `--allow-host` | | run, create, update | Hostname egress filter, resolved at VM start (implies --net) |
| `--allow-host-pattern` | | run, create, update | Opt-in exact hostname or `*.domain` subdomains (implies --net) |
| `--ssh-agent` | | run, create, pack run | Forward host SSH agent (git/ssh without exposing keys) |
| `--nested` | | run, create | Let the guest run its own VMs (nested KVM). Off by default; it exposes the host kernel's nested-KVM code to the guest, so enable it only for trusted workloads. |
| `--state-dir` | | every command (Linux) | Keep all smolvm state under one directory instead of the default ones, e.g. to run a second engine version beside an installed one |
| `--stop-on-exit` | | create | Stop the machine when its workload exits, whatever the exit status |

## Smolfile

A Smolfile is a TOML file declaring a machine: image, entrypoint and cmd, env,
resources, mounts, ports, `init` (run once, on the machine's first start),
network policy, health check, restart policy, SSH agent and secrets, with a
`[dev]` profile for `machine run`/`create` and an `[artifact]` profile for
`pack create`. Use it with `--smolfile`/`-s`. Unknown keys are refused at
create. CLI flags override scalar values, and `-e`, `-v`, `-p` and `--init`
extend the Smolfile's lists. Every key and the full merge precedence:
`docs/smolfile.md`.

```toml
image = "python:3.12-alpine"
net = true
ports = ["8000:8000"]
volumes = ["./src:/app"]
init = ["pip install -r /app/requirements.txt"]

[network]
allow_hosts = ["pypi.org"]
```

## Networking

Networking is off by default. `--net` opens full outbound TCP, UDP and DNS;
`--allow-host` (a host and its subdomains), `--allow-host-pattern` (an exact
host, or `'*.domain'` for subdomains only) and `--allow-cidr` limit it, can be
combined and repeated, and imply `--net`, as do `--outbound-localhost-only`
and `--guest-subnet`. `-p HOST:GUEST` publishes a TCP port and
`-p HOST:GUEST/udp` a UDP one (each client gets its own session, answered from
the same host port; datagrams up to 1472 bytes); the server inside must listen
on `0.0.0.0`, and a published port alone gives no outbound access.
`--block-private` keeps the public internet open but blocks the LAN, cloud
metadata, CGNAT (Tailscale), unique-local IPv6 and the host's loopback;
`--allow-private CIDR` re-opens one private range, such as an internal
registry. Metadata stays blocked either way. Both imply `--net` and use the
virtio-net backend; the Smolfile form is `[network] block_private = true` and
`allow_private = ["10.20.0.0/16"]`.
`--deny-cidr CIDR` refuses a range even where an allow would admit it,
including the host's loopback reached through the gateway. It implies `--net`;
the Smolfile form is `[network] deny_cidrs`.
`--allow-udp CIDR[:PORT[-END]]` admits UDP to a range, optionally one port
or a port range (`1.1.1.1:123`, `192.0.2.0/24:3478-3480`; write an IPv6 range
with a prefix or brackets, as in `[2001:db8::1]:443`). It is the one way to
open UDP beyond DNS for a machine started with an external egress interceptor,
which otherwise denies every datagram. Every deny is checked first, the
metadata floor and `--block-private` still apply (only `--allow-private`
re-opens a private range), and DNS keeps its own path. It implies `--net`;
the Smolfile form is `[network] allow_udp`.
Every rule, the Smolfile keys and `--guest-subnet`:
`docs/throwaway-machine/README.md`.

A registry image does not need `--net`. When the guest cannot reach the
registry itself (no network, or an allow list that does not cover it), smolvm
fetches the image on the host at the machine's first start and boots that copy,
so a machine created without network never needs network to provision. That
first start still asks the registry to authorize the pull, so it fails if the
registry refuses or rate-limits the request; later starts boot the stored disk
without contacting it. `machine ls` and `machine status` keep reporting the
image the machine was created from.

### Proxy Support

Pass proxy settings into VMs with `-e` when behind a corporate proxy or VPN:

```bash
smolvm machine run --net \
  -e https_proxy=http://proxy.corp:3128 \
  -e http_proxy=http://proxy.corp:3128 \
  -e no_proxy=localhost,127.0.0.1 \
  --image alpine -- wget -q -O /dev/null https://example.com
```

Or declare them in a Smolfile:

```toml
net = true
env = [
  "https_proxy=http://proxy.corp:3128",
  "http_proxy=http://proxy.corp:3128",
  "no_proxy=localhost,127.0.0.1"
]
```

Proxy vars are NOT forwarded automatically: each VM gets exactly the env you specify, unless you ask for the host's (below). The guest uses the host's own resolver: the first `/etc/resolv.conf` nameserver, systemd-resolved's uplink when that file names only the local stub, or the Windows system resolver list; `--dns` sets a custom DNS resolver for the guest instead.

### Behind a corporate firewall

Two opt-in flags on `machine run` / `machine create` carry the host's network setup into the machine:

```bash
smolvm machine run --use-host-proxy --trust-host-certs --image python:3.12 -- pip install requests
```

- `--use-host-proxy` — the host's `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY` (or, on macOS, the system proxy when none is set) become the workload's proxy env, in both cases. A proxy on the host's `localhost` is rewritten to an address the machine can reach; the machine's own loopback is always in `NO_PROXY`. Implies `--net`. A PAC-file-only Mac gets an error asking for `HTTPS_PROXY`.
- `--trust-host-certs` — the certificates the host trusts (macOS: system roots + System keychain, where a corporate TLS-inspection root is installed; Linux: the system bundle) are mounted read-only at `/etc/smolvm-host-trust/ca-bundle.pem`, and `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `DENO_CERT` point at it. `SMOLVM_HOST_CA_BUNDLE=/path` reads a different bundle (Nix, custom stores). Not combinable with `--credential` yet. Tools with their own trust store (Java keystores, `apt` over HTTPS) still need it configured in the image.

Values passed with `-e` win over both flags, and `machine create` persists them.

## SSH Agent Forwarding

Forward the host's SSH agent into the VM so git, ssh, and scp work with your keys — without the private keys ever entering the VM.

```bash
# Quick check the agent is forwarded (alpine needs openssh-client for ssh-add):
smolvm machine run --ssh-agent --net --image alpine -- sh -c "apk add -q openssh-client && ssh-add -l"

# Persistent VM — create, start, install tooling, then use the agent:
smolvm machine create --name myvm --image alpine --ssh-agent --net
smolvm machine start  --name myvm
smolvm machine exec   --name myvm -- apk add -q git openssh-client

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

## GPU Acceleration

`--gpu` (or `gpu = true`) exposes the host GPU to the guest as a Vulkan device
over virtio-gpu/Venus, which ANGLE can use for WebGL; `--gpu-vram` sizes its
shared memory (default 4096 MiB). macOS bundles what it needs; Linux needs
virglrenderer and a Vulkan driver from the system packages. Not available on
Windows, where `--gpu` has no effect. Host packages, a one-shot check, a
headless Chromium example and when to set `VK_ICD_FILENAMES`: `docs/gpu.md`.

## CUDA (experimental)

`--cuda` (or `cuda = true`) remotes guest CUDA calls to the host NVIDIA GPU over
vsock, separate from `--gpu`. The host needs a working NVIDIA driver and no CUDA
toolkit; the guest gets no `/dev/nvidia*`, only Driver and Runtime API shims at
`/opt/smolvm-cuda` that need a glibc image. Without an NVIDIA driver the host
answers with a CPU-emulation device, so check the device name, not the exit code.
Coverage: `docs/gpu.md`; the tested procedure: `docs/gpu-cuda/`.

## Secrets

smolvm stores no secret material. A secret is a *reference* to a value that
already lives on the host — a host environment variable or a host file — and is
resolved into the workload's process environment at launch time. Bring your own
secrets manager (Vault, 1Password, AWS, sops, your shell): render the value into
an env var or file, then point a ref at it. Only the reference is ever
persisted; the resolved value never lands in the VM record, the database, or a
`.smolmachine` pack.

Attach refs on the command line:

```bash
# From a host environment variable (GUEST_VAR=HOST_VAR)
smolvm machine run    --secret-env OPENAI_API_KEY=OPENAI_API_KEY -- ./app
smolvm machine create --name web --secret-env DATABASE_URL=PROD_DB_URL   # persists the ref
smolvm machine exec --name web --secret-env TOKEN=CI_TOKEN -- ./deploy

# From a host file (GUEST_VAR=/absolute/path)
smolvm machine run --secret-file GCP_CREDS=/abs/creds.json -- ./app

# Bridge any external manager through the env/file seam, e.g. 1Password:
op run --env-file=secrets.env -- smolvm machine run -- ./app
```

Or reference them from a Smolfile. The left-hand key becomes the env var name in
the guest workload:

```toml
[secrets]
DATABASE_URL = { from_env  = "PROD_DB_URL" }    # host env var (at launch)
GCP_CREDS    = { from_file = "/abs/creds.json" } # absolute host file (at launch)
```

Exactly one of `from_env`, `from_file` must be set per entry; `from_file` paths
must be absolute. Resolved values are appended *after* top-level `env` and CLI
`-e` flags. Resolution is late-bound, so rotating the underlying env var or file
takes effect at the next launch with nothing to re-sync.

**Threat model:** this is defense-in-depth, not zero-knowledge. The target
process sees plaintext in its own environment, and root inside the guest can
read any `/proc/*/environ`. Use SSH agent forwarding instead when a secret must
never leave the host.

**Where they're resolved:** `machine run`, `machine create` + `machine start`,
and `machine exec` resolve refs against *this host* under a trusted-local scope.
Untrusted surfaces — HTTP API request bodies and portable `.smolmachine` packs —
are treated as untrusted callers and may carry **no** resolvable secret ref:
`from_env` would expose the server's env and `from_file` would be an arbitrary
host-file read, so both are rejected. Configure secrets locally instead.

## File Copy

Copy files between the host and a running machine using `machine:path` syntax:

```bash
# Upload a file to the VM
smolvm machine cp ./script.py myvm:/workspace/script.py

# Download a file from the VM
smolvm machine cp myvm:/workspace/output.json ./output.json
```

**Files and `exec` see the same filesystem.** Files copied with `cp`
(or written through the HTTP API or an SDK) are visible to `exec` at the
same path, and vice versa, for any path: `/tmp`, `/home`, `/workspace`,
etc. On an image-based VM (`--image`) that is the container's overlay
filesystem; on a bare VM it is the VM's own root, also after an SDK
`run(image, ...)` has used a container on the machine. Each image an SDK
`run`s on a machine keeps its own persistent container filesystem, so
running a second image never sees the first one's files.

**`/workspace` shared directory:** Every machine has a `/workspace`
directory — bare VMs, image-based VMs, and machines created from
`.smolmachine` artifacts. It persists across `exec` sessions and
across `stop`/`start` cycles. It's a good default location for
scripts, data, and results. Passing `-v /host/dir:/workspace` replaces
the default storage-disk workspace with your host directory for that run; a
mount at any other path (`/data`, `/app`) leaves `/workspace` alone:

```bash
# Typical agent workflow: copy code in, execute, extract results
smolvm machine create --name r-sandbox --image r-base:latest --net
smolvm machine start --name r-sandbox

smolvm machine cp analysis.R r-sandbox:/workspace/analysis.R
smolvm machine exec --name r-sandbox -- Rscript /workspace/analysis.R
smolvm machine cp r-sandbox:/workspace/results.csv ./results.csv

smolvm machine stop --name r-sandbox
```

**Behavior and limits:**

- Files up to 1 MiB transfer as a single message — no perceptible
  overhead beyond the agent round-trip.
- Larger files stream automatically: 1 MiB chunks for upload, 16 MiB
  chunks for download. The split is asymmetric because the
  host→guest direction has tighter socket-buffer headroom.
- Per-transfer cap is **4 GiB** in either direction. Files above this
  size are rejected: an upload before it starts (`total_size exceeds
  maximum`), a download once it passes the cap (`exceeding the byte
  cap`). For larger blobs, mount a host directory with `--volume`
  instead of copying.
- A throttled progress line prints to stderr while large transfers
  run, including bytes-so-far, percentage (uploads), and rate.
  Pipe captures (`> file`) only see the upload/download summary,
  not the progress noise.
- Atomic on the guest side: a partially-written file never appears
  at the target path. If the transfer fails or the connection drops
  mid-stream, the staging file is cleaned up and the original
  destination (if any) is unaffected.

Typical throughput on macOS (Apple Silicon): ~35-42 MB/s upload,
~170 MB/s download.

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

### Interactive exec over a WebSocket

`GET /api/v1/machines/:name/exec/interactive` upgrades to a WebSocket that carries a command's stdin and output in both directions.

| Query parameter | Meaning |
|---|---|
| `cmd` | Program to run (default `/bin/sh`) |
| `arg` | One argument to the program; repeat it for each, in order (an empty value is an argument) |
| `tty` | `true` (default) runs the command on a PTY; `false` runs it on pipes |
| `cols`, `rows` | Initial terminal size (`tty=true` only) |

Binary frames from the client are the command's stdin; binary frames from the server are its output. When the command exits the server sends `{"type":"exit","code":N}` and closes. Closing the socket ends the session and kills the command. On a PTY, a text frame `{"type":"resize","cols":N,"rows":N}` resizes the terminal and stderr is merged into stdout.

With `tty=false` the command sees plain pipes: stdout is the binary frames byte for byte, stderr arrives as text frames `{"type":"stderr","data":"..."}` (lossily UTF-8), and stdin is written with backpressure. The socket is read only as fast as the command takes its input, and no byte is dropped. Input the server has received wakes the session at once; it does not wait for agent output. Use `tty=false` for anything that is not a person at a terminal (a protocol relay, a filter). A PTY is not a reliable byte pipe: the guest agent writes its stdin without flow control, so a large or bursty write can be dropped, and the line discipline can rewrite bytes.
## Bare VM Mode

`machine run` works without `--image` when a Smolfile provides the workload config, or for direct Alpine shell access:

```bash
# Bare Alpine shell
smolvm machine run -it

# Smolfile with entrypoint/cmd (no container overhead)
smolvm machine run -s Smolfile

# Bare VM with init setup, detached
smolvm machine run -d -s Smolfile
```

Bare VMs run commands directly in the Alpine rootfs — no OCI image pull needed. Use this when you need a minimal Linux environment.

## Packed Binaries (.smolmachine)

`smolvm pack create` writes a platform-specific stub with the VM runtime
embedded and a cross-platform `.smolmachine` payload (rootfs, OCI layers,
storage); both travel together unless you pass `--single-file`. The stub runs
as a normal executable: `./my-app run -- CMD` is ephemeral, and `start`,
`exec` and `stop` drive a persistent daemon. `machine create --name NAME
--from my-app.smolmachine` makes it a named machine with the full lifecycle,
booting from pre-extracted layers with no image pull. Details, the manifest's
metadata and the traps: `docs/pack/`.

## HTTP API

`smolvm serve start` serves the machine lifecycle over local HTTP, on a Unix
socket by default (loopback TCP on Windows) or on `--listen 127.0.0.1:8080`.
A plain server has no authentication: whoever reaches the socket or the port
can create and run machines. Machines that ask for nested virtualization
(`nestedVirt`) are refused with 403 unless the server runs with `--allow-nested-virt`.
`smolvm serve openapi` prints the spec; the endpoints, field names and traps:
`docs/local-api/`.

## Important Defaults

- Machine name defaults to `$SMOLVM_MACHINE_NAME` when set, else `"default"`, when `--name` is omitted. An explicit `--name` always wins. Meant for per-workspace tooling (direnv); `machine run`, `machine checkpoint`, and `machine branch` deliberately ignore the variable. Without the variable, `machine create` generates a `vm-<id>` name instead of `"default"`
- Network is **off** by default (security-first)
- CPUs: 4, Memory: 8192 MiB, Storage: 20 GiB, Overlay: 10 GiB
- Packed binaries use the same defaults (CPUs: 4, Memory: 8192 MiB)
- Memory and CPU are elastic via virtio balloon — the host only commits what the guest actually uses and reclaims the rest

## Important Behaviors

- **Failures carry stable codes.** `--error-format json` prints a failure as `{"error":{"code":…,"message":…}}` on stderr (exit status unchanged). Codes match the SDKs' `SmolError.code`: `NOT_FOUND` (machine, file, image), `CONFLICT`, `INTERRUPTED` (a stop or delete cut the command off), `CONFIG_ERROR`, `INVALID_STATE`, `STORAGE_ERROR`, `MOUNT_ERROR`, `KVM_UNAVAILABLE`, `HYPERVISOR_UNAVAILABLE`, `COMMAND_FAILED`, `SMOLVM_ERROR`. Branch on the code, not the message.
- **Disks smaller than 20 GiB need no host tools.** `--storage 8` makes an 8 GiB disk without `resize2fs`, and image machines of that size get an image seed of their own, so creating the next one does not pull the image again.
- **`machine stop` stops the workload gracefully**: its stop signal (`SIGTERM` by default), then up to its stop timeout (10 s, at most 300) before a kill. `machine stop --timeout SECS` overrides the wait once (`0` kills at once); `machine delete` does not wait. Setting them: `docs/smolfile.md`.
- **`machine logs` shows the workload's output.** The workload's stdout and stderr are appended to `workload.log` in the machine's data directory, kept across restarts, rotated at 10 MiB (three old files kept), and readable while the machine is stopped. `-f` follows, `--tail N` shows the last N lines. Output of `machine exec` is not included. Over the API: `GET /api/v1/machines/{name}/logs?source=workload`.
- **Observational commands don't stop running VMs.** `machine images`, `machine status`, `machine ls` and similar read-only commands leave a running VM in its current state. If the VM was already running before the command, it stays running after.
- **`machine prune` works on a running VM.** Regular prune only removes unreferenced layers and is safe while containers are active. `prune --all` requires the VM to be stopped first since it deletes manifests for layers that may be in use.
- **`machine mount add` mounts into a running machine.** The host directory appears at the guest path at once, in the machine and in every workload container, with no restart; `:ro` is enforced by the host. It lasts until the machine stops (use `machine update -v` to keep a mount), a branch inherits it, and `mount rm` revokes the guest's access, open files included. `POST/GET/DELETE /api/v1/machines/:name/mounts` does the same over the API.
- **`machine update` modifies a stopped machine.** Add/remove mounts, ports, env vars, or change CPU/memory without recreating the VM. Changes take effect on next `machine start`. Requires the machine to be stopped, except for allow-list changes (`--allow-host`, `--allow-host-pattern`, `--allow-cidr`, `--remove-allow-host`, `--remove-allow-cidr`, `--allow-udp`, `--remove-allow-udp`) on a machine started with an allow list: those apply to its next connection, datagram or DNS lookup and persist across restarts. Lifting the allow list entirely still needs a stop.
