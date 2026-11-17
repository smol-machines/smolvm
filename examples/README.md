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

# Headless Chromium with GPU acceleration
smolvm machine create --name browser -s examples/headless-browser/browser.smolfile
smolvm machine start --name browser
smolvm machine exec --name browser -- \
  chromium --headless=new --no-sandbox --disable-dev-shm-usage \
    --use-gl=angle --use-angle=vulkan \
    --screenshot=/tmp/out.png --window-size=1280,800 \
    https://example.com
smolvm machine exec --name browser -- base64 /tmp/out.png | base64 -d > out.png
```

### Amp orbs

[`amp-orbs/`](amp-orbs/) runs [Amp](https://ampcode.com)'s self-hosted orbs as
smol machines, on your own Linux host or on smol cloud.

### Persistent microVMs

```bash
smolvm machine create --name dev -s examples/python-app/python.smolfile
smolvm machine start --name dev
smolvm machine exec --name dev -- python3 --version
smolvm machine stop --name dev
```

### Pack a distributable binary

```bash
smolvm pack create -s examples/openclaw-app/openclaw.smolfile -o openclaw-packed
./openclaw-packed
```

## Smolfile reference

Every key, its default, and the merge precedence for `machine run`, `machine create` and
`pack create` are in [`docs/smolfile.md`](../docs/smolfile.md).
