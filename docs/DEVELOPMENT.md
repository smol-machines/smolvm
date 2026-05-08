# Development

## Prerequisites

- Rust toolchain
- [git-lfs](https://git-lfs.com) (required for library binaries)
- smolvm itself (for cross-compiling the agent — builds inside a `rust:alpine` VM)
- e2fsprogs (for storage template creation; `mkfs.ext4`; on macOS: `brew install e2fsprogs`)
- LLVM (macOS only, for building libkrun: `brew install llvm`)
- [cargo-make](https://github.com/sagiegurari/cargo-make): `cargo install cargo-make`

## Quick Start

We use [`cargo-make`](https://github.com/sagiegurari/cargo-make) to orchestrate build tasks:

```bash
# Install cargo-make (one-time)
cargo install cargo-make

# View all available tasks
cargo make --list-all-steps

# Build and codesign (macOS) - binary ready at ./target/release/smolvm
cargo make dev

# Run smolvm with environment variables set up automatically
cargo make smolvm --version
cargo make smolvm machine run --net --image alpine:latest -- echo hello
cargo make smolvm machine ls

# Or run the binary directly with environment variables:
DYLD_LIBRARY_PATH="./lib" SMOLVM_AGENT_ROOTFS="./target/agent-rootfs" ./target/release/smolvm <command>
```

**How it works:**
- `cargo make dev` builds + codesigns (macOS only), binary ready at `./target/release/smolvm`
- `cargo make smolvm <args>` runs smolvm with `DYLD_LIBRARY_PATH` and `SMOLVM_AGENT_ROOTFS` set up
- On macOS, binary is automatically signed with hypervisor entitlements

## Building Distribution Packages

```bash
# Build distribution package
cargo make dist

# Build using local libkrun changes from ../libkrun
./scripts/build-dist.sh --with-local-libkrun
```

## Running Tests

```bash
# Run all tests
cargo make test

# Run specific test suites
cargo make test-cli        # CLI tests only
cargo make test-sandbox    # Sandbox tests only
cargo make test-machine    # MicroVM tests only
cargo make test-pack       # Pack tests only
cargo make test-lib        # Unit tests (no VM required)
```

## Agent Rootfs

The agent rootfs resolution order is:
1. `SMOLVM_AGENT_ROOTFS` env var (explicit override)
2. `./target/agent-rootfs` (local development)
3. Platform data directory (`~/.local/share/smolvm/` on Linux, `~/Library/Application Support/smolvm/` on macOS)

```bash
# Build agent for Linux (size-optimized)
cargo make build-agent

# Build agent rootfs
cargo make agent-rootfs

# Rebuild agent and update rootfs
cargo make agent-rebuild
```

## Code Quality

```bash
# Run clippy and fmt checks
cargo make lint

# Auto-fix linting issues
cargo make fix-lints
```

## Other Tasks

```bash
# Install locally from dist package
cargo make install
```

The `cargo make dist` task wraps `scripts/build-dist.sh`. Other scripts:

```bash
./scripts/build-dist.sh
./scripts/build-agent-rootfs.sh
./scripts/install-local.sh
```

## Corporate Proxy / Custom CA Certificates

If you're behind a corporate TLS-intercepting proxy, you need to configure CA certificates at multiple levels for image pulls and package installs to work.

### 1. Install CA bundle into the system-level agent rootfs

The installed smolvm's agent rootfs needs your CA bundle so crane (OCI image pulls) can verify TLS:

```bash
cp /path/to/your/ca-bundle.pem "$HOME/Library/Application Support/smolvm/agent-rootfs/etc/ssl/certs/ca-certificates.crt"
```

Your CA bundle should contain both Mozilla root certificates and your corporate CA certificate(s).

### 2. Build agent rootfs with SSL_CERT_FILE

Set `SSL_CERT_FILE` so the build script injects the CA bundle into VMs it spawns (for `apk` package installs and the rust:alpine agent build):

```bash
export SSL_CERT_FILE=/path/to/your/ca-bundle.pem
cargo make agent-rootfs
```

The build script automatically mounts the cert directory into VMs and copies the bundle into the built rootfs.

### 3. Run smolvm with SSL_CERT_FILE

Set `SSL_CERT_FILE` when running smolvm so it gets forwarded into the guest VM for crane to use:

```bash
export SSL_CERT_FILE=/path/to/your/ca-bundle.pem
cargo make smolvm machine run --net --image alpine:latest -- echo hello
```

### 4. Clear stale VM cache if needed

If you see `agent process exited during startup` after rebuilding the agent rootfs, clear the cached VM disks:

```bash
rm -rf ~/Library/Caches/smolvm/vms/*
```

This removes stale storage/overlay disks that may contain an incompatible agent version.

## Troubleshooting

**Database lock errors** ("Database already open"):
```bash
pkill -f "smolvm serve"
pkill -f "smolvm-bin machine start"
```

**Hung tests**: Check for stuck VM processes:
```bash
ps aux | grep smolvm
```
