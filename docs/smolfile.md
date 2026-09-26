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

Common keys: `image`, `cpus`, `memory`, `net`, `ports`, `volumes`, `env`,
`init` (runs once as root, like a Dockerfile `RUN`), `workdir`, `user` (who the
workload runs as), `gpu`, `cuda`, `docker_socket`, `storage`, `overlay`, and the
`[network]`, `[dev]`, `[auth]`, `[health]`, `[restart]`, `[service]` tables.
