#!/bin/bash
# Build the agent VM rootfs
#
# This script creates an Alpine-based rootfs with:
# - crane (for OCI image operations)
# - crun (OCI container runtime)
# - smolvm-agent daemon
# - Required utilities (jq, e2fsprogs, util-linux)
#
# Usage: ./scripts/build-agent-rootfs.sh [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
INSTALL_ROOTFS=0
POSITIONAL_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL_ROOTFS=1 ;;
        *) POSITIONAL_ARGS+=("$arg") ;;
    esac
done
export INSTALL_ROOTFS

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-$PROJECT_ROOT/target/agent-rootfs}"

# Alpine version
ALPINE_VERSION="3.19"
ALPINE_ARCH="aarch64"  # Change to x86_64 for Intel

# Detect architecture
case "$(uname -m)" in
    arm64|aarch64)
        ALPINE_ARCH="aarch64"
        CRANE_ARCH="arm64"
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    x86_64|amd64)
        ALPINE_ARCH="x86_64"
        CRANE_ARCH="x86_64"
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)"
        exit 1
        ;;
esac

ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ALPINE_MINIROOTFS="alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
ALPINE_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/${ALPINE_MINIROOTFS}"

# Crane version
CRANE_VERSION="0.19.0"
CRANE_URL="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz"

echo "Building agent rootfs..."
echo "  Alpine: ${ALPINE_VERSION} (${ALPINE_ARCH})"
echo "  Crane: ${CRANE_VERSION}"
echo "  Output: ${OUTPUT_DIR}"

# Create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Download Alpine minirootfs
echo "Downloading Alpine minirootfs..."
ALPINE_TAR="/tmp/${ALPINE_MINIROOTFS}"
if [ ! -f "$ALPINE_TAR" ]; then
    curl -fsSL -o "$ALPINE_TAR" "$ALPINE_URL"
fi

# Extract Alpine
echo "Extracting Alpine..."
tar -xzf "$ALPINE_TAR" -C "$OUTPUT_DIR"

# Download crane
echo "Downloading crane..."
CRANE_TAR="/tmp/crane-${CRANE_VERSION}.tar.gz"
if [ ! -f "$CRANE_TAR" ]; then
    curl -fsSL -o "$CRANE_TAR" "$CRANE_URL"
fi

# Extract crane to rootfs
echo "Installing crane..."
mkdir -p "$OUTPUT_DIR/usr/local/bin"
tar -xzf "$CRANE_TAR" -C "$OUTPUT_DIR/usr/local/bin" crane

# Install additional packages using Docker
echo "Installing additional packages via Docker..."
if command -v docker &> /dev/null; then
    docker run --rm -v "$OUTPUT_DIR:/rootfs" "alpine:${ALPINE_VERSION}" sh -c '
        apk add --root /rootfs --initdb --no-cache \
            jq \
            e2fsprogs \
            crun \
            util-linux \
            libcap
    '
    echo "Packages installed successfully"
else
    echo "Warning: Docker not found, skipping package installation"
    echo "You may need to install packages manually: jq e2fsprogs crun util-linux"
fi

# Create necessary directories
mkdir -p "$OUTPUT_DIR/storage"
mkdir -p "$OUTPUT_DIR/etc/init.d"
mkdir -p "$OUTPUT_DIR/run"

# Remove existing init (it's a symlink to busybox) and replace with
# symlink to the agent binary. The agent handles overlayfs setup +
# pivot_root internally before starting the vsock listener.
rm -f "$OUTPUT_DIR/sbin/init"
ln -sf /usr/local/bin/smolvm-agent "$OUTPUT_DIR/sbin/init"

# Create resolv.conf
echo "nameserver 1.1.1.1" > "$OUTPUT_DIR/etc/resolv.conf"

PROFILE="release-small"

# Build smolvm-agent for Linux (statically linked with musl)
echo "Building smolvm-agent for Linux ($RUST_TARGET, profile: $PROFILE)..."

# Allow using a pre-built agent binary via AGENT_BINARY env var
if [[ -n "${AGENT_BINARY:-}" ]] && [[ -f "${AGENT_BINARY}" ]]; then
    echo "Using pre-built agent binary: $AGENT_BINARY"
else
    AGENT_BINARY=""

    # Strategy 1: Native build on Linux with musl target installed
    if [[ "$(uname -s)" == "Linux" ]] && command -v cargo &> /dev/null; then
        if rustup target list --installed 2>/dev/null | grep -q "$RUST_TARGET"; then
            echo "Building natively with musl target..."
            cargo build --profile "$PROFILE" -p smolvm-agent --target "$RUST_TARGET" \
                --manifest-path "$PROJECT_ROOT/Cargo.toml"
            AGENT_BINARY="$PROJECT_ROOT/target/$RUST_TARGET/$PROFILE/smolvm-agent"
        fi
    fi

    # Strategy 2: Docker with rust:alpine
    if [[ -z "$AGENT_BINARY" ]] || [[ ! -f "$AGENT_BINARY" ]]; then
        if command -v docker &> /dev/null; then
            echo "Building via Docker (rust:alpine)..."
            docker run --rm --network=host -v "$PROJECT_ROOT:/work" -w /work rust:alpine sh -c \
                "apk add musl-dev && cargo build --profile $PROFILE -p smolvm-agent"
            AGENT_BINARY="$PROJECT_ROOT/target/$PROFILE/smolvm-agent"
        else
            echo "Error: Cannot build smolvm-agent"
            echo "  Either install the musl target: rustup target add $RUST_TARGET"
            echo "  Or install Docker for cross-compilation"
            exit 1
        fi
    fi
fi

if [[ ! -f "$AGENT_BINARY" ]]; then
    echo "Error: smolvm-agent binary not found at $AGENT_BINARY"
    exit 1
fi

# Install the agent binary into the rootfs
echo "Installing smolvm-agent binary..."
cp "$AGENT_BINARY" "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
chmod +x "$OUTPUT_DIR/usr/local/bin/smolvm-agent"

echo ""
echo "Agent rootfs created at: $OUTPUT_DIR"
echo "Agent binary: $AGENT_BINARY"
echo "Rootfs size: $(du -sh "$OUTPUT_DIR" | cut -f1)"

# Install to runtime data directory if --install flag is passed
if [[ "${INSTALL_ROOTFS:-}" == "1" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        DATA_DIR="$HOME/Library/Application Support/smolvm"
    else
        DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi

    echo "Installing agent-rootfs to $DATA_DIR..."
    mkdir -p "$DATA_DIR"
    rm -rf "$DATA_DIR/agent-rootfs"
    cp -a "$OUTPUT_DIR" "$DATA_DIR/agent-rootfs"
    echo "Installed successfully."
fi
