# smolvm

OCI-native microVM runtime. Run containers in lightweight VMs using [libkrun](https://github.com/containers/libkrun).

> **Alpha** - APIs may change.

## Quick Start (macOS)

```bash
# Install dependencies
brew tap slp/krun
brew install libkrun@1.15.1 libkrunfw

# Clone and build
git clone https://github.com/smolvm/smolvm.git && cd smolvm
./scripts/build-agent-rootfs.sh
docker run --rm -v "$(pwd):/work" -w /work rust:alpine sh -c \
  "apk add musl-dev && cargo build --release -p smolvm-agent"
cp target/release/smolvm-agent ~/Library/Application\ Support/smolvm/agent-rootfs/usr/local/bin/
cargo build --release
codesign --entitlements smolvm.entitlements --force -s - ./target/release/smolvm

# Run
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libkrun@1.15.1/lib:/opt/homebrew/lib
./target/release/smolvm microvm run alpine:latest echo "Hello World"
```

## Usage

```bash
# Run container (ephemeral - microvm stops after)
smolvm microvm run alpine:latest echo "Hello"
smolvm microvm run -v /host:/guest alpine:latest cat /guest/file
smolvm microvm run -it alpine:latest /bin/sh

# Exec in VM (persistent - microvm keeps running, ~50ms warm)
smolvm microvm exec echo "Fast"
smolvm microvm exec cat /etc/os-release   # Shows Alpine (VM's rootfs)
smolvm microvm exec -it /bin/sh
smolvm microvm stop

# Named VMs
smolvm microvm create --name myvm --cpus 2 --mem 512 node:20 npm start
smolvm microvm start myvm
smolvm microvm stop myvm
smolvm microvm delete myvm
```

### Key Difference

| Command | Runs In | MicroVM |
|---------|---------|---------|
| `run` | Container (OCI image) | Stops after |
| `exec` | VM directly (Alpine) | Keeps running |

### Common Options

`-e KEY=VAL` env, `-v host:guest` mount, `-w /path` workdir, `--net` network, `-p 8080:80` ports, `--timeout 30s`, `-it` interactive

## Troubleshooting

```bash
RUST_LOG=debug smolvm microvm run alpine:latest  # Debug logging
cat ~/Library/Caches/smolvm/agent-console.log    # Agent logs
pkill -9 -f krun                                  # Kill stuck VM
```

## Limitations

- Volume mounts: directories only (virtiofs)
- No x86 emulation on ARM Macs
- Requires libkrun@1.15.1

## License

Apache-2.0
