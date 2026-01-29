#!/bin/bash
# Build a distributable smolvm package
#
# Usage: ./scripts/build-dist.sh
#
# Output: dist/smolvm-<version>-<platform>.tar.gz

set -e

# Configuration
VERSION="${VERSION:-$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)}"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
DIST_NAME="smolvm-${VERSION}-${PLATFORM}"
DIST_DIR="dist/${DIST_NAME}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building smolvm distribution: ${DIST_NAME}"

# Check for required libraries
LIB_DIR="${LIB_DIR:-./lib}"
if [[ ! -f "$LIB_DIR/libkrun.dylib" ]] && [[ ! -f "$LIB_DIR/libkrun.so" ]]; then
    echo "Error: libkrun not found in $LIB_DIR"
    echo "Set LIB_DIR to point to your libkrun library directory."
    exit 1
fi

# Check for Docker (required for cross-compiling agent)
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required to cross-compile the agent for Linux"
    exit 1
fi

# Build release binary
echo "Building release binary..."
LIBKRUN_BUNDLE="$LIB_DIR" cargo build --release --bin smolvm

# Build smolvm-agent for Linux
echo "Building smolvm-agent for Linux..."
docker run --rm -v "$PROJECT_ROOT:/work" -w /work rust:alpine sh -c \
    "apk add musl-dev && cargo build --release -p smolvm-agent"

# Sign binary (macOS only)
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "Signing binary..."
    codesign --force --sign - --entitlements smolvm.entitlements ./target/release/smolvm
fi

# Create distribution directory
echo "Creating distribution package..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/lib"

# Copy binary (renamed to smolvm-bin)
cp ./target/release/smolvm "$DIST_DIR/smolvm-bin"

# Copy wrapper script
cp ./dist/smolvm "$DIST_DIR/smolvm"
chmod +x "$DIST_DIR/smolvm"

# Copy libraries
if [[ "$(uname -s)" == "Darwin" ]]; then
    cp "$LIB_DIR/libkrun.dylib" "$DIST_DIR/lib/"
    cp "$LIB_DIR/libkrunfw.5.dylib" "$DIST_DIR/lib/"
    # Create symlink for compatibility
    ln -sf libkrunfw.5.dylib "$DIST_DIR/lib/libkrunfw.dylib"
else
    cp "$LIB_DIR/libkrun.so"* "$DIST_DIR/lib/"
    cp "$LIB_DIR/libkrunfw.so"* "$DIST_DIR/lib/"
fi

# Build agent-rootfs
echo "Building agent-rootfs..."
ROOTFS_SRC="$PROJECT_ROOT/helper-rootfs/rootfs"
if [[ ! -d "$ROOTFS_SRC" ]]; then
    echo "Error: helper-rootfs/rootfs not found"
    echo "Run ./scripts/build-agent-rootfs.sh first to create the base rootfs."
    exit 1
fi

# Copy rootfs and update agent binary
# Use cp -a to preserve symlinks (busybox creates many symlinks in /bin)
mkdir -p "$DIST_DIR/agent-rootfs"
cp -a "$ROOTFS_SRC"/* "$DIST_DIR/agent-rootfs/"

# Copy freshly built agent binary
cp ./target/release/smolvm-agent "$DIST_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
cp ./target/release/smolvm-agent "$DIST_DIR/agent-rootfs/sbin/init"
chmod +x "$DIST_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
chmod +x "$DIST_DIR/agent-rootfs/sbin/init"

echo "Agent rootfs size: $(du -sh "$DIST_DIR/agent-rootfs" | cut -f1)"

# Copy README
cat > "$DIST_DIR/README.txt" << 'EOF'
smolvm - OCI-native microVM runtime

INSTALLATION
============

1. Extract this archive to a location of your choice:
   tar -xzf smolvm-*.tar.gz
   cd smolvm-*

2. (Optional) Add to PATH:
   # Add to ~/.bashrc or ~/.zshrc:
   export PATH="/path/to/smolvm-directory:$PATH"

3. (Optional) Create a symlink:
   sudo ln -s /path/to/smolvm-directory/smolvm /usr/local/bin/smolvm

PREREQUISITES
=============

macOS:
  - macOS 11.0 (Big Sur) or later
  - e2fsprogs for disk formatting: brew install e2fsprogs

Linux:
  - KVM support (/dev/kvm must exist)
  - e2fsprogs (usually pre-installed)

USAGE
=====

Run the 'smolvm' script (not smolvm-bin directly):

  ./smolvm sandbox run alpine:latest echo "Hello World"
  ./smolvm microvm create --name myvm alpine:latest /bin/sh
  ./smolvm microvm start myvm
  ./smolvm microvm ls
  ./smolvm microvm stop myvm
  ./smolvm microvm delete myvm

TROUBLESHOOTING
===============

"library not found" errors:
  Make sure you're running the 'smolvm' wrapper script, not 'smolvm-bin'
  directly. The wrapper sets up the library path automatically.

"mkfs.ext4 not found" errors:
  Install e2fsprogs (see Prerequisites above).

For more information: https://github.com/smolvm/smolvm
EOF

# Generate checksums
echo "Generating checksums..."
(cd "$DIST_DIR" && shasum -a 256 smolvm smolvm-bin lib/* > checksums.txt)

# Create tarball
echo "Creating tarball..."
cd dist
tar -czf "${DIST_NAME}.tar.gz" "${DIST_NAME}"
cd ..

# Summary
echo ""
echo "Distribution package created:"
echo "  dist/${DIST_NAME}.tar.gz"
echo ""
echo "Contents:"
ls -la "$DIST_DIR"
echo ""
echo "To test locally:"
echo "  cd $DIST_DIR && ./smolvm --help"
echo ""
echo "To install locally:"
echo "  ./scripts/install-local.sh"
