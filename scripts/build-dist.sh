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
# On Linux, look in lib/linux-{arch}/ first
if [[ "$(uname -s)" == "Linux" ]]; then
    ARCH="$(uname -m)"
    LIB_DIR="${LIB_DIR:-./lib/linux-${ARCH}}"
else
    LIB_DIR="${LIB_DIR:-./lib}"
fi

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

# Build release binaries
echo "Building release binaries..."
LIBKRUN_BUNDLE="$LIB_DIR" cargo build --release --bin smolvm

# Build smolvm-agent for Linux (size-optimized)
echo "Building smolvm-agent for Linux (optimized for size)..."
if [[ "$(uname -s)" == "Linux" ]]; then
    # On Linux, build natively with musl for static linking
    if command -v cargo &> /dev/null; then
        # Check if musl target is available
        if rustup target list --installed 2>/dev/null | grep -q musl; then
            cargo build --profile release-small -p smolvm-agent --target x86_64-unknown-linux-musl
        else
            # Fall back to Docker build
            docker run --rm --network=host -v "$PROJECT_ROOT:/work" -w /work rust:alpine sh -c \
                "apk add musl-dev && cargo build --profile release-small -p smolvm-agent"
        fi
    else
        docker run --rm --network=host -v "$PROJECT_ROOT:/work" -w /work rust:alpine sh -c \
            "apk add musl-dev && cargo build --profile release-small -p smolvm-agent"
    fi
else
    docker run --rm -v "$PROJECT_ROOT:/work" -w /work rust:alpine sh -c \
        "apk add musl-dev && cargo build --profile release-small -p smolvm-agent"
fi

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
cp ./scripts/smolvm-wrapper.sh "$DIST_DIR/smolvm"
chmod +x "$DIST_DIR/smolvm"

# Copy libraries
if [[ "$(uname -s)" == "Darwin" ]]; then
    cp "$LIB_DIR/libkrun.dylib" "$DIST_DIR/lib/"
    cp "$LIB_DIR/libkrunfw.5.dylib" "$DIST_DIR/lib/"
    # Create symlink for compatibility
    ln -sf libkrunfw.5.dylib "$DIST_DIR/lib/libkrunfw.dylib"
else
    # Copy libraries preserving symlinks with -a, or copy files individually
    if [[ -L "$LIB_DIR/libkrun.so" ]]; then
        cp -a "$LIB_DIR"/libkrun.so* "$DIST_DIR/lib/" 2>/dev/null || \
            cp "$LIB_DIR"/libkrun.so* "$DIST_DIR/lib/"
    else
        cp "$LIB_DIR/libkrun.so" "$DIST_DIR/lib/"
        # Create versioned symlink
        ln -sf libkrun.so "$DIST_DIR/lib/libkrun.so.1"
    fi
    if [[ -L "$LIB_DIR/libkrunfw.so" ]]; then
        cp -a "$LIB_DIR"/libkrunfw.so* "$DIST_DIR/lib/" 2>/dev/null || \
            cp "$LIB_DIR"/libkrunfw.so* "$DIST_DIR/lib/"
    else
        cp "$LIB_DIR/libkrunfw.so"* "$DIST_DIR/lib/"
    fi
fi

# Copy init.krun for Linux (required by libkrunfw kernel)
if [[ "$(uname -s)" == "Linux" ]]; then
    # Look for init.krun in libkrun submodule or system locations
    INIT_KRUN=""
    if [[ -f "$PROJECT_ROOT/libkrun/init/init" ]]; then
        INIT_KRUN="$PROJECT_ROOT/libkrun/init/init"
    elif [[ -f "/usr/local/share/smolvm/init.krun" ]]; then
        INIT_KRUN="/usr/local/share/smolvm/init.krun"
    fi

    if [[ -n "$INIT_KRUN" ]]; then
        echo "Copying init.krun from $INIT_KRUN..."
        cp "$INIT_KRUN" "$DIST_DIR/init.krun"
        chmod +x "$DIST_DIR/init.krun"
    else
        echo "Warning: init.krun not found - users may need to build libkrun init"
    fi
fi

# Build agent-rootfs
echo "Building agent-rootfs..."
ROOTFS_SRC="$PROJECT_ROOT/target/agent-rootfs"
if [[ ! -d "$ROOTFS_SRC" ]]; then
    echo "Error: target/agent-rootfs not found"
    echo "Run ./scripts/build-agent-rootfs.sh first to create the base rootfs."
    exit 1
fi

# Copy rootfs and update agent binary
# Use cp -a to preserve symlinks (busybox creates many symlinks in /bin)
mkdir -p "$DIST_DIR/agent-rootfs"
cp -a "$ROOTFS_SRC"/* "$DIST_DIR/agent-rootfs/"

# Copy freshly built agent binary (from release-small profile)
# Remove existing symlinks first (busybox creates init as symlink)
rm -f "$DIST_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
rm -f "$DIST_DIR/agent-rootfs/sbin/init"
cp ./target/release-small/smolvm-agent "$DIST_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
chmod +x "$DIST_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
# Symlink /sbin/init → agent (saves ~1.8MB in initramfs vs a copy).
# The agent handles overlayfs setup + pivot_root internally.
ln -sf /usr/local/bin/smolvm-agent "$DIST_DIR/agent-rootfs/sbin/init"

echo "Agent rootfs size: $(du -sh "$DIST_DIR/agent-rootfs" | cut -f1)"

# Create pre-formatted storage template
# This eliminates the e2fsprogs dependency for end users
echo "Creating storage template..."
TEMPLATE_SIZE=$((512 * 1024 * 1024))  # 512MB
TEMPLATE_PATH="$DIST_DIR/storage-template.ext4"

# Find mkfs.ext4
MKFS_PATHS=(
    "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4"
    "/usr/local/opt/e2fsprogs/sbin/mkfs.ext4"
    "/opt/homebrew/sbin/mkfs.ext4"
    "/usr/local/sbin/mkfs.ext4"
    "/sbin/mkfs.ext4"
    "/usr/sbin/mkfs.ext4"
)

MKFS_BIN=""
for path in "${MKFS_PATHS[@]}"; do
    if [[ -x "$path" ]]; then
        MKFS_BIN="$path"
        break
    fi
done

if [[ -z "$MKFS_BIN" ]] && command -v mkfs.ext4 &> /dev/null; then
    MKFS_BIN="mkfs.ext4"
fi

if [[ -z "$MKFS_BIN" ]]; then
    echo "Warning: mkfs.ext4 not found, skipping storage template creation"
    echo "         Users will need e2fsprogs installed"
else
    # Create sparse file
    dd if=/dev/zero of="$TEMPLATE_PATH" bs=1 count=0 seek=$TEMPLATE_SIZE 2>/dev/null

    # Format with ext4
    "$MKFS_BIN" -F -q -m 0 -L smolvm "$TEMPLATE_PATH"

    echo "Storage template created: $(du -h "$TEMPLATE_PATH" | cut -f1) (sparse)"

    # Create overlay template (same format, different label)
    OVERLAY_TEMPLATE_PATH="$DIST_DIR/overlay-template.ext4"
    dd if=/dev/zero of="$OVERLAY_TEMPLATE_PATH" bs=1 count=0 seek=$TEMPLATE_SIZE 2>/dev/null
    "$MKFS_BIN" -F -q -m 0 -L smolvm-overlay "$OVERLAY_TEMPLATE_PATH"
    echo "Overlay template created: $(du -h "$OVERLAY_TEMPLATE_PATH" | cut -f1) (sparse)"
fi

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
  - Apple Silicon or Intel Mac

Linux:
  - KVM support (/dev/kvm must exist)
  - User must have access to /dev/kvm (typically via 'kvm' group)

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

"agent did not become ready within 30 seconds":
  This usually means the storage disk couldn't be formatted.
  Check that the storage-template.ext4 file exists in ~/.smolvm/
  If not, you may need to reinstall smolvm or install e2fsprogs:
    macOS: brew install e2fsprogs
    Linux: apt install e2fsprogs

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
