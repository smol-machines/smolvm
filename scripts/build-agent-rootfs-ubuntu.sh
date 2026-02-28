#!/bin/bash
# Build an Ubuntu-based agent VM rootfs
#
# This script creates an Ubuntu-based rootfs with:
# - crane (for OCI image operations)
# - crun (OCI container runtime)
# - smolvm-agent daemon
# - Required utilities (jq, e2fsprogs, util-linux, curl, bash, ca-certificates)
#
# Use this instead of build-agent-rootfs.sh when you need glibc/Ubuntu
# compatibility (e.g., software that doesn't support Alpine/musl).
#
# Requires Docker (used to create the Ubuntu rootfs).
#
# Usage: ./scripts/build-ubuntu-rootfs.sh [output-dir]
#        ./scripts/build-ubuntu-rootfs.sh --install

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

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-$PROJECT_ROOT/target/agent-rootfs-ubuntu}"

# Ubuntu version
UBUNTU_VERSION="22.04"

# Detect architecture
case "$(uname -m)" in
    arm64|aarch64)
        DOCKER_PLATFORM="linux/arm64"
        CRANE_ARCH="arm64"
        CRUN_ARCH="arm64"
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    x86_64|amd64)
        DOCKER_PLATFORM="linux/amd64"
        CRANE_ARCH="x86_64"
        CRUN_ARCH="amd64"
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)"
        exit 1
        ;;
esac

# Crane version
CRANE_VERSION="0.19.0"
CRANE_URL="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz"

# crun version (Ubuntu 22.04 ships 0.17 which is too old)
CRUN_VERSION="1.19.1"
CRUN_URL="https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}-linux-${CRUN_ARCH}"

echo "Building Ubuntu agent rootfs..."
echo "  Ubuntu: ${UBUNTU_VERSION} (${DOCKER_PLATFORM})"
echo "  Crane: ${CRANE_VERSION}"
echo "  crun: ${CRUN_VERSION}"
echo "  Output: ${OUTPUT_DIR}"

# Docker is required for Ubuntu rootfs creation
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required to build the Ubuntu rootfs"
    exit 1
fi

# Create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Create Ubuntu rootfs via Docker: run a container with packages installed,
# then export the entire filesystem. This is necessary because apt-get
# doesn't have an --root option like apk does.
echo "Creating Ubuntu rootfs via Docker..."
CONTAINER_NAME="smolvm-ubuntu-rootfs-$$"

docker run --platform "$DOCKER_PLATFORM" --name "$CONTAINER_NAME" \
    "ubuntu:${UBUNTU_VERSION}" \
    bash -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            jq \
            e2fsprogs \
            util-linux \
            libcap2 \
            libcap2-bin \
            curl \
            ca-certificates \
            bash \
            tar
        apt-get clean
        rm -rf /var/lib/apt/lists/* /var/cache/apt/*
    '

docker export "$CONTAINER_NAME" | tar -xf - -C "$OUTPUT_DIR"
docker rm "$CONTAINER_NAME" > /dev/null

# Fix permissions that docker export on macOS doesn't preserve
chmod 1777 "$OUTPUT_DIR/tmp"

echo "Ubuntu rootfs extracted"

# Download crane
echo "Downloading crane..."
CRANE_TAR="/tmp/crane-${CRANE_VERSION}.tar.gz"
if [ ! -f "$CRANE_TAR" ]; then
    curl -fsSL -o "$CRANE_TAR" "$CRANE_URL"
fi

# Install crane
echo "Installing crane..."
mkdir -p "$OUTPUT_DIR/usr/local/bin"
tar -xzf "$CRANE_TAR" -C "$OUTPUT_DIR/usr/local/bin" crane

# Download and install crun (static binary from GitHub, replacing Ubuntu's old 0.17)
echo "Downloading crun ${CRUN_VERSION}..."
CRUN_BIN="/tmp/crun-${CRUN_VERSION}-linux-${CRUN_ARCH}"
if [ ! -f "$CRUN_BIN" ]; then
    curl -fsSL -o "$CRUN_BIN" "$CRUN_URL"
fi
echo "Installing crun..."
cp "$CRUN_BIN" "$OUTPUT_DIR/usr/bin/crun"
chmod +x "$OUTPUT_DIR/usr/bin/crun"

# Create necessary directories
mkdir -p "$OUTPUT_DIR/storage"
mkdir -p "$OUTPUT_DIR/etc/init.d"
mkdir -p "$OUTPUT_DIR/run"

# Remove existing init (systemd symlink in Ubuntu) and replace with
# symlink to the agent binary. The agent handles overlayfs setup +
# pivot_root internally before starting the vsock listener.
rm -f "$OUTPUT_DIR/sbin/init"
ln -sf /usr/local/bin/smolvm-agent "$OUTPUT_DIR/sbin/init"

# Remove systemd — the smolvm-agent IS the init process
rm -rf "$OUTPUT_DIR/lib/systemd" "$OUTPUT_DIR/usr/lib/systemd" \
       "$OUTPUT_DIR/etc/systemd"

# Trim docs and man pages to reduce rootfs size
rm -rf "$OUTPUT_DIR/usr/share/doc" "$OUTPUT_DIR/usr/share/man" \
       "$OUTPUT_DIR/usr/share/info" "$OUTPUT_DIR/usr/share/lintian"

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
echo "Ubuntu agent rootfs created at: $OUTPUT_DIR"
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
