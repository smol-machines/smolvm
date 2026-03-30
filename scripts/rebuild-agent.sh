#!/bin/bash
# Rebuild the smolvm-agent binary for Linux and install it
#
# Usage: ./scripts/rebuild-agent.sh [--clean]
#
# Options:
#   --clean    Force clean rebuild (required after protocol changes)

set -ex

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOTFS_DIR="$HOME/Library/Application Support/smolvm/agent-rootfs"

cd "$PROJECT_DIR"

# Clean build artifacts if requested
CLEAN_CMD=""
if [[ "$1" == "--clean" ]]; then
    echo "Cleaning build artifacts..."
    CLEAN_CMD="rm -rf target/release/deps/smolvm_protocol* \
                      target/release/deps/smolvm_agent* \
                      target/release/.fingerprint/smolvm-protocol* \
                      target/release/.fingerprint/smolvm-agent* \
                      target/release/smolvm-agent && "
fi

echo "Building smolvm-agent for Linux..."
if command -v smolvm &> /dev/null; then
    smolvm machine run --net --mem 2048 -v "$PROJECT_DIR:/work" --image rust:alpine \
        -- sh -c ". /usr/local/cargo/env && apk add musl-dev && cd /work && ${CLEAN_CMD}cargo build --release -p smolvm-agent"
else
    echo "Error: smolvm is required to cross-compile the agent"
    echo "Install smolvm first: https://github.com/smolvm/smolvm"
    exit 1
fi

# Check if rootfs directory exists
if [[ ! -d "$ROOTFS_DIR/usr/local/bin" ]]; then
    echo "Error: Agent rootfs not found at $ROOTFS_DIR"
    echo "Run ./scripts/build-agent-rootfs.sh first"
    exit 1
fi

echo "Installing agent binary..."
cp target/release/smolvm-agent "$ROOTFS_DIR/usr/local/bin/"

# /sbin/init is the kernel's entry point — symlink to the agent binary.
# The agent handles overlayfs setup + pivot_root internally before
# starting the vsock listener.
ln -sf /usr/local/bin/smolvm-agent "$ROOTFS_DIR/sbin/init"

echo "Stopping running agent (if any)..."
export DYLD_LIBRARY_PATH="$PROJECT_DIR/lib"
"$PROJECT_DIR/target/release/smolvm" agent stop 2>/dev/null || true

echo ""
echo "Agent rebuilt and installed successfully!"
echo "Binary: $ROOTFS_DIR/usr/local/bin/smolvm-agent"
echo "Init:   $ROOTFS_DIR/sbin/init (symlink to agent)"
ls -la "$ROOTFS_DIR/usr/local/bin/smolvm-agent" "$ROOTFS_DIR/sbin/init"
