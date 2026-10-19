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
# View all available tasks
cargo make --list-all-steps

# Build and codesign with the hypervisor entitlement (macOS) - binary ready at ./target/release/smolvm
cargo make dev

# Run smolvm with environment variables set up automatically
cargo make smolvm --version
cargo make smolvm machine run --net --image alpine:latest -- echo hello
cargo make smolvm machine ls

# Or run the binary directly with environment variables:
DYLD_LIBRARY_PATH="./lib" SMOLVM_AGENT_ROOTFS="./target/agent-rootfs" ./target/release/smolvm <command>
```

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
cargo make test-pack       # Pack tests only
cargo make test-lib        # Unit tests (no VM required)
./tests/run_tests.sh bare network   # Specific VM suites (names in tests/run_tests.sh)
```

## Agent Rootfs

The agent rootfs resolution order is:
1. `SMOLVM_AGENT_ROOTFS` env var (explicit override)
2. A rootfs tarball from an SDK bundle or `SMOLVM_AGENT_ROOTFS_TAR`, extracted once to a cache directory
3. `agent-rootfs` next to the `smolvm` executable (distribution layout)
4. Platform data directory (`~/.local/share/smolvm/` on Linux, `~/Library/Application Support/smolvm/` on macOS)

`./target/agent-rootfs` is not searched. To use the one `cargo make agent-rootfs` builds, export
`SMOLVM_AGENT_ROOTFS=$PWD/target/agent-rootfs`. `cargo make smolvm` sets it for you; `cargo make test` does not.

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

The `cargo make dist` task wraps `scripts/build-dist.sh`; the other scripts are
`scripts/build-agent-rootfs.sh` and `scripts/install-local.sh`.

## Rebuilding Libraries

The pre-built library binaries in `lib/` cover most development workflows. If you
need to rebuild them (after submodule updates, kernel config changes, or enabling
new features), see:

- Linux: [`scripts/build-libkrun-linux.sh`](../scripts/build-libkrun-linux.sh) builds `libkrunfw`
  and `libkrun` from the patched `libkrun/` and `libkrunfw/` submodules into `lib/linux-<arch>/`,
  on a native host of that architecture.
- macOS: no page covers rebuilding `lib/libkrun.dylib` or `lib/libkrunfw.5.dylib` yet.

## Troubleshooting

**Stuck machines**: each running machine is one `_boot-vm` process (`smolvm-bin _boot-vm` from an
install, `target/release/smolvm _boot-vm` from a dev build). Stop all of them:
```bash
pkill -f "_boot-vm"
```

**Hung tests**: Check for stuck VM processes:
```bash
ps aux | grep smolvm
```
