# Smolfile Examples

A `.smolfile` is a recipe for smolvm to build a microVM in a reproducible way across different host environments. Similar to `Dockerfile` -> Docker container.

## Quick Start

Here's a Smolfile. Run the commands below to recreate the same microVM setup on your machine:

```bash
smolvm microvm create dev -s examples/python-app/python.smolfile
smolvm microvm start dev
smolvm microvm exec --name dev -- python3 --version
```

## Smolfile Reference

```toml
cpus = 2                   # vCPUs (default: 1)
memory = 1024              # MiB (default: 512)
net = true                 # outbound networking (default: false)
ports = ["8080:80"]        # HOST:GUEST port mapping
volumes = ["./src:/app"]   # HOST:GUEST[:ro] volume mounts
env = ["KEY=VALUE"]        # environment variables
workdir = "/app"           # working directory for init commands
storage = 40               # storage disk GiB (default: 20)
overlay = 4                # overlay disk GiB (default: 2)
init = ["apk add git"]     # commands run on every VM start
```

All fields are optional. CLI flags override scalar values; array values are merged.
