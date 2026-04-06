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
# Prefer the locally built binary over the installed one — it has the latest
# fixes (e.g., registry config path) that the installed version may lack.
SMOLVM_BIN="${PROJECT_DIR}/target/release/smolvm"
if [ ! -f "$SMOLVM_BIN" ] && command -v smolvm &> /dev/null; then
    SMOLVM_BIN="smolvm"
elif [ ! -f "$SMOLVM_BIN" ]; then
    echo "Error: smolvm is required to cross-compile the agent"
    echo "Build with: cargo build --release"
    exit 1
fi

"$SMOLVM_BIN" machine run --net --mem 2048 -v "$PROJECT_DIR:/work" --image rust:alpine \
    -- sh -c ". /usr/local/cargo/env && apk add musl-dev && cd /work && ${CLEAN_CMD}cargo build --release -p smolvm-agent"

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

# Also update target/agent-rootfs if it exists — pack create reads from
# there first, so it must stay in sync with the installed rootfs.
if [[ -d "$PROJECT_DIR/target/agent-rootfs/usr/local/bin" ]]; then
    cp target/release/smolvm-agent "$PROJECT_DIR/target/agent-rootfs/usr/local/bin/"
    echo "Updated: target/agent-rootfs (keeps pack create in sync)"
fi

echo "Stopping running agent (if any)..."
export DYLD_LIBRARY_PATH="$PROJECT_DIR/lib"
"$PROJECT_DIR/target/release/smolvm" agent stop 2>/dev/null || true

echo ""
echo "Agent rebuilt and installed successfully!"
echo "Binary: $ROOTFS_DIR/usr/local/bin/smolvm-agent"
echo "Init:   $ROOTFS_DIR/sbin/init (symlink to agent)"
ls -la "$ROOTFS_DIR/usr/local/bin/smolvm-agent" "$ROOTFS_DIR/sbin/init"
