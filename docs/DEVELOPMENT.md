# Development

## Prerequisites

- Rust toolchain
- [git-lfs](https://git-lfs.com) (required for library binaries)
- smolvm itself (for cross-compiling the agent — builds inside a `rust:alpine` VM)
- e2fsprogs (for storage template creation; `mkfs.ext4`)
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
cargo make smolvm sandbox run --net --image alpine:latest -- echo hello
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
