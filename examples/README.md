# Smolfile Examples

A Smolfile is the declarative source of truth for a microVM workload. It describes what runs, what resources it needs, and how it behaves — then smolvm uses the same spec for local execution, artifact creation, and future deployment.

## Quick Start

```bash
# Run the OpenClaw gateway from a Smolfile
smolvm machine run -d -s examples/openclaw-app/openclaw.smolfile
curl http://localhost:18789/health

# Run a Python dev environment
smolvm machine run -s examples/python-app/python.smolfile

# Run Doom in a browser
smolvm machine run -d -s examples/doom-web/doom.smolfile
open http://localhost:8080
```

### Persistent microVMs

```bash
smolvm machine create dev -s examples/python-app/python.smolfile
smolvm machine start --name dev
smolvm machine exec --name dev -- python3 --version
smolvm machine stop --name dev
```

### Pack a distributable binary

```bash
smolvm pack create -s examples/openclaw-app/openclaw.smolfile -o openclaw-packed
./openclaw-packed
```

## Smolfile Reference

```toml
# Top-level workload fields
image = "ghcr.io/acme/api:1.2.3"    # OCI image (optional — omit for bare Alpine VM)
entrypoint = ["/app/api"]            # executable and fixed leading arguments
cmd = ["serve"]                      # default arguments appended to entrypoint
env = ["PORT=8080"]                  # runtime environment variables
workdir = "/app"                     # working directory

# Resources
cpus = 2                             # vCPUs (default: 4)
memory = 1024                        # MiB (default: 8192)
net = true                           # outbound networking (default: false)
storage = 40                         # storage disk GiB (default: 20)
overlay = 4                          # overlay disk GiB (default: 2)

# Network policy — egress filtering by hostname and/or CIDR
[network]
allow_hosts = ["api.stripe.com", "db.example.com"]  # resolved at VM start
allow_cidrs = ["10.0.0.0/8"]                        # IP/CIDR ranges

# Health checks
[health]
exec = ["curl", "-f", "http://127.0.0.1:8080/health"]
interval = "10s"
timeout = "2s"
retries = 3

# Restart policy (parsed, not yet wired)
[restart]
policy = "always"

# Local development profile
[dev]
volumes = ["./src:/app"]             # host bind mounts
env = ["APP_MODE=development"]       # dev-only env (extends top-level)
init = ["npm install"]               # dev bootstrap commands
workdir = "/app"                     # dev-only workdir override
ports = ["8080:8080"]                # host:guest port forwarding

# Artifact profile (for smolvm pack create -s)
[artifact]
cpus = 4                             # override resources for distribution
memory = 2048
entrypoint = ["/app/api"]            # override entrypoint for packed binary
oci_platform = "linux/amd64"         # target OCI platform

```

### Merge precedence

CLI flags override Smolfile values. For `machine run`:

```
image:      --image flag > Smolfile image > None (bare Alpine VM)
entrypoint: --entrypoint flag > Smolfile entrypoint > image metadata
cmd:        trailing args (after --) > Smolfile cmd > image metadata
env:        top-level env + [dev].env + CLI -e
init:       [dev].init + CLI --init
volumes:    [dev].volumes + CLI -v
ports:      [dev].ports + CLI -p
```

For `pack create`:

```
image:      --image flag > Smolfile image
entrypoint: --entrypoint flag > [artifact].entrypoint > Smolfile entrypoint > image metadata
cmd:        [artifact].cmd > Smolfile cmd > image metadata
cpus:       --cpus flag > [artifact].cpus > top-level cpus
env:        image env + Smolfile env (dedup by key)
workdir:    Smolfile workdir > image workdir
```
