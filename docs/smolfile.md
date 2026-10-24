# Smolfile

A Smolfile declares a machine in TOML, the equivalent of a `Dockerfile` or a
cloud-init file, but for a whole VM: image, resources, network policy, mounts,
ports, and setup commands in one checked-in file.

```toml
image = "python:3.12-alpine"
net = true
cpus = 4
memory = 4096

ports = ["8000:8000", "5173-5180:5173-5180"]
volumes = ["./src:/app"]
init = ["pip install -r /app/requirements.txt"]

[network]
allow_hosts = ["api.stripe.com", "pypi.org"]

[auth]
ssh_agent = true
```

```bash
smolvm machine create --name myvm -s Smolfile   # or --smolfile <PATH>
smolvm machine start --name myvm
```

Port mappings accept a single port (`"8080"`), an explicit mapping (`"8080:80"`), or equal-length one-to-one ranges (`"5173-5180:5173-5180"`). A machine can publish at most 64 concrete mappings.

Unknown keys are rejected rather than ignored, so a typo fails at create time
instead of silently doing nothing.

## Reference

```toml
# Workload
image = "python:3.12-alpine"          # OCI image (omit for bare Alpine)
entrypoint = ["/app/run"]             # executable and fixed leading arguments (overrides image ENTRYPOINT)
cmd = ["serve"]                       # default arguments appended to entrypoint (overrides image CMD)
env = ["PORT=8080", "DEBUG=1"]        # environment variables
workdir = "/app"                      # working directory
user = "app"                          # who the workload runs as: a passwd name or uid[:gid]
stop_on_exit = true                   # stop the machine when the workload exits (default: false)
stop_signal = "SIGINT"                # sent to the workload when the machine stops (default: SIGTERM)
stop_timeout = 30                     # seconds it gets to exit before it is killed (default: 10, max: 300)

# Resources
cpus = 2                              # vCPUs (default: 4)
memory = 1024                         # MiB (default: 8192, elastic via balloon)
net = true                            # outbound networking (default: false)
gpu = true                            # GPU acceleration, Vulkan via virtio-gpu (default: false)
gpu_vram = 4096                       # GPU shared-memory region in MiB (default: 4096, ignored unless gpu = true)
storage = 40                          # storage disk GiB (default: 20)
overlay = 4                           # overlay disk GiB (default: 10)

# Mounts, ports and provisioning ([dev] lists below replace these when set)
volumes = ["./src:/app"]              # host bind mounts; a guest path alone ("/var/lib/docker") is a directory on the machine's disk
ports = ["8080:8080", "27015:27015/udp"]  # host:guest forwarding; /udp for UDP
init = ["pip install -r requirements.txt"]  # run once as root, on the machine's first start

# Network policy: egress filtering by hostname and/or CIDR
[network]
allow_hosts = ["api.stripe.com"]      # resolved at VM start; the host and its subdomains (implies net)
allow_host_patterns = ["api.example.com", "*.files.example.com"]  # exact name, or subdomains only
allow_cidrs = ["10.0.0.0/8"]          # IP/CIDR ranges (implies net)
block_private = true                  # public internet open; LAN, metadata, CGNAT, host loopback blocked
allow_private = ["10.20.0.0/16"]      # private ranges re-opened under block_private (implies it)
deny_cidrs = ["169.254.169.254"]      # denied before any allow (implies net)
allow_udp = ["1.1.1.1:123", "192.0.2.0/24:3478-3480"]  # UDP to CIDR[:PORT[-END]], also under an egress interceptor (implies net)

# Dev profile (used by `machine run` and `machine create`)
[dev]
volumes = ["./src:/app"]              # replaces the top-level list when set
ports = ["8080:8080"]                 # replaces the top-level list when set
init = ["npm install"]                # replaces the top-level list when set
env = ["APP_MODE=dev"]                # extends the top-level env
workdir = "/app"                      # overrides the top-level workdir
user = "app"                          # overrides the top-level user

# Artifact profile (used by `pack create`; `[pack]` is the same table)
[artifact]
cpus = 4                              # override resources for distribution
memory = 2048
entrypoint = ["/app/run"]             # override entrypoint for the packed binary
cmd = ["serve"]                       # override cmd for the packed binary
oci_platform = "linux/amd64"          # target OCI platform

# Health check (used by `machine monitor`)
[health]
exec = ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health"]  # runs in the agent, which has no curl
interval = "10s"
timeout = "2s"
retries = 3
startup_grace = "20s"

# Restart policy: never (default), always, on-failure or unless-stopped
[restart]
policy = "always"
max_retries = 5
max_backoff = "60s"

# SSH agent forwarding
[auth]
ssh_agent = true                      # forward the host SSH agent into the VM

# Secrets: references to host sources, resolved at workload launch
[secrets]
DATABASE_URL = { from_env  = "PROD_DB_URL" }      # host env var (at launch)
GCP_CREDS    = { from_file = "/abs/creds.json" }  # absolute host file (at launch)
```

Credential bindings are `[[network.credentials]]` tables, described in
[credential substitution](credential-substitution.md). The other accepted keys
are `net_backend`, `rosetta`, `cuda`, `auto_graph`, `docker_socket`,
`block_io`, `disk_durability` and the `[branch]` (or `[fork]`) and `[service]`
tables; `machine create --help` describes the flag each one mirrors.

## User names and numeric IDs

The Smolfile `user`, the image's `USER`, and `machine exec --user` resolve
names against the container image's `/etc/passwd` (and named groups against
`/etc/group`). A name that exists only on the host or in the VM's base system
does not work inside the image.

Use a numeric UID and GID when the image has no matching passwd entry:

```bash
smolvm machine exec --name myvm --user 1001:1001 -- id
```

Numeric IDs do not require passwd or group entries. Specify the GID too:
if an unknown numeric UID has no explicit GID, its default GID is `0`.

## Merge precedence

CLI flags override Smolfile values. For `machine run` and `machine create`:

```
image:      --image flag > Smolfile image > None (bare Alpine)
entrypoint: Smolfile entrypoint > image metadata
cmd:        trailing args (after --) > Smolfile cmd > image metadata
env:        top-level env + [dev].env + CLI -e (all merged)
volumes:    [dev].volumes, else top-level volumes, then + CLI -v
ports:      [dev].ports, else top-level ports, then + CLI -p
init:       [dev].init, else top-level init, then + CLI --init
workdir:    CLI -w > [dev].workdir > top-level workdir
cpus/mem:   CLI flag > Smolfile > defaults (4 CPU, 8192 MiB)
```

For `pack create`:

```
image:        --image flag > Smolfile image
entrypoint:   --entrypoint flag > [artifact].entrypoint > Smolfile entrypoint > image metadata
cmd:          [artifact].cmd > Smolfile cmd > image metadata
cpus/memory:  --cpus / --mem > [artifact] > Smolfile > defaults
oci_platform: --oci-platform > [artifact].oci_platform
env:          image env + Smolfile top-level env (a Smolfile key replaces the image's)
workdir:      Smolfile workdir > image workdir
```

### Stopping when the workload exits

By default a machine keeps running after its workload exits. With
`stop_on_exit = true` (or `machine create --stop-on-exit`) it stops by itself
instead, whatever the exit status, so a workload can shut its machine down, for
example after an idle timeout:

```toml
image = "python:3.12-alpine"
net = true
cmd = ["python3", "/app/server.py"]   # exits after 30 idle minutes
stop_on_exit = true
```

Storage is flushed exactly as for `machine stop`, so files the workload wrote
survive. `machine exec` sessions never trigger it; only the workload itself
does. The machine's restart policy then applies as for any stop: the default
`never` leaves it stopped. The workload's exit status is not passed on.

### Stopping the workload with the machine

`machine stop` sends the workload its stop signal and waits for it to exit
before the machine powers off, so a server can save its state first. The
signal is `SIGTERM` and the wait is 10 seconds unless the Smolfile says
otherwise; a workload still running when the wait ends is killed.

```toml
image = "my-game-server"
stop_signal = "SIGINT"    # the server saves the world on Ctrl-C
stop_timeout = 60         # saving a large world can take a while
```

`stop_signal` takes a name (`SIGTERM`, `SIGINT`, `SIGQUIT`, `SIGRTMIN+3`) or a
number; `stop_timeout` is whole seconds, at most 300. The same settings are
`machine create --stop-signal` and `--stop-timeout`, and `machine stop
--timeout SECS` overrides the wait for one stop (`0` kills at once).
`machine delete` does not wait.
