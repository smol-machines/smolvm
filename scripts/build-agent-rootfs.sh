#!/bin/bash
# Build the agent VM rootfs
#
# This script creates an Alpine-based rootfs with:
# - crane (for OCI image operations)
# - crun (OCI container runtime)
# - smolvm-agent daemon
# - Required utilities (jq, e2fsprogs, util-linux)
#
# Usage: ./scripts/build-agent-rootfs.sh [--arch aarch64|x86_64] [--no-build-agent] [--install] [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
INSTALL_ROOTFS=0
OVERRIDE_ARCH=""
NO_BUILD_AGENT=0
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL_ROOTFS=1; shift ;;
        --arch)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --arch requires a value (aarch64 or x86_64)"
                exit 1
            fi
            OVERRIDE_ARCH="$2"; shift 2 ;;
        --no-build-agent) NO_BUILD_AGENT=1; shift ;;
        *) POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done
export INSTALL_ROOTFS

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-$PROJECT_ROOT/target/agent-rootfs}"

# Alpine version
ALPINE_VERSION="3.19"

# Detect or override architecture
DETECTED_ARCH="${OVERRIDE_ARCH:-$(uname -m)}"
case "$DETECTED_ARCH" in
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
        echo "Unsupported architecture: $DETECTED_ARCH"
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
CRANE_TAR="/tmp/crane-${CRANE_VERSION}-${CRANE_ARCH}.tar.gz"
if [ ! -f "$CRANE_TAR" ]; then
    curl -fsSL -o "$CRANE_TAR" "$CRANE_URL"
fi

# Extract crane to rootfs
echo "Installing crane..."
mkdir -p "$OUTPUT_DIR/usr/local/bin"
tar -xzf "$CRANE_TAR" -C "$OUTPUT_DIR/usr/local/bin" crane

# Install additional Alpine packages into the rootfs.
# Strategies:
#   1. apk.static (Linux only) — runs natively, supports cross-arch via --arch
#   2. smolvm (any host) — only for native-arch builds (pulls host-arch image)
echo "Installing additional packages..."
APK_PACKAGES="jq e2fsprogs e2fsprogs-extra crun util-linux libcap"

# Determine if this is a cross-arch build
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64) HOST_ALPINE_ARCH="aarch64" ;;
    amd64) HOST_ALPINE_ARCH="x86_64" ;;
    *)     HOST_ALPINE_ARCH="$HOST_ARCH" ;;
esac
CROSS_ARCH=0
if [[ "$ALPINE_ARCH" != "$HOST_ALPINE_ARCH" ]]; then
    CROSS_ARCH=1
fi

install_packages_apk_static() {
    echo "  Using apk.static..."
    # Download Alpine's static apk binary — runs natively on Linux,
    # can install packages for any target architecture via --arch.
    APK_STATIC_MIRROR="${ALPINE_MIRROR}/v${ALPINE_VERSION}/main/${HOST_ARCH}"
    APK_STATIC_PKG=$(curl -fsSL "$APK_STATIC_MIRROR/" | grep -o 'apk-tools-static-[^"]*\.apk' | head -1)
    if [[ -z "$APK_STATIC_PKG" ]]; then
        echo "Error: could not find apk-tools-static package at $APK_STATIC_MIRROR"
        exit 1
    fi
    curl -fsSL -o /tmp/apk-static.apk "${APK_STATIC_MIRROR}/${APK_STATIC_PKG}"
    mkdir -p /tmp/apk-static
    tar -xzf /tmp/apk-static.apk -C /tmp/apk-static 2>/dev/null || true

    # Set up apk repositories in the rootfs
    mkdir -p "$OUTPUT_DIR/etc/apk"
    echo "${ALPINE_MIRROR}/v${ALPINE_VERSION}/main" > "$OUTPUT_DIR/etc/apk/repositories"
    echo "${ALPINE_MIRROR}/v${ALPINE_VERSION}/community" >> "$OUTPUT_DIR/etc/apk/repositories"

    /tmp/apk-static/sbin/apk.static \
        --root "$OUTPUT_DIR" \
        --initdb \
        --no-cache \
        --allow-untrusted \
        --arch "$ALPINE_ARCH" \
        add $APK_PACKAGES
    echo "Packages installed successfully"
}

repair_executable_modes() {
    local rootfs_dir="$1"
    local dirs=(
        "$rootfs_dir/bin"
        "$rootfs_dir/sbin"
        "$rootfs_dir/usr/bin"
        "$rootfs_dir/usr/sbin"
        "$rootfs_dir/usr/local/bin"
        "$rootfs_dir/usr/local/sbin"
    )

    echo "Normalizing executable permissions..."
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi

        # On the macOS build path, apk install into the host-mounted rootfs can
        # strip execute bits from package-installed guest tools. We observed
        # this on crun, resize2fs, and e2fsck, and the failures only surfaced
        # later during packed/container execution. These directories are the
        # standard executable locations in the guest rootfs, so normalize their
        # contents before install/pack preserves the bad modes.
        find "$dir" -type d -exec chmod 755 {} +
        find "$dir" -type f -exec chmod 755 {} +
    done
}

if [[ "$(uname -s)" == "Linux" ]]; then
    # On Linux, apk.static is preferred — it handles cross-arch correctly
    install_packages_apk_static
elif [[ "$CROSS_ARCH" == "1" ]]; then
    echo "Error: cross-arch rootfs builds (--arch $ALPINE_ARCH on $HOST_ALPINE_ARCH host)"
    echo "       are only supported on Linux (uses apk.static)."
    echo "       On macOS, omit --arch or use the same architecture as your host."
    exit 1
elif command -v smolvm &> /dev/null; then
    echo "  Using smolvm..."
    smolvm machine run --net -v "$OUTPUT_DIR:/rootfs" --image "alpine:${ALPINE_VERSION}" \
        -- sh -c "apk add --root /rootfs --initdb --no-cache $APK_PACKAGES"
    echo "Packages installed successfully"
else
    echo "Error: smolvm is required to build the agent rootfs on macOS"
    echo "Install smolvm first: https://github.com/smolvm/smolvm"
    exit 1
fi

repair_executable_modes "$OUTPUT_DIR"

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

if [[ -n "${AGENT_BINARY:-}" ]] && [[ -f "${AGENT_BINARY}" ]]; then
    echo "Using pre-built agent binary: $AGENT_BINARY"
elif [[ "$NO_BUILD_AGENT" == "1" ]]; then
    echo "Skipping agent build (--no-build-agent)"
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

    # Strategy 2: smolvm with rust:alpine (dogfooding)
    if [[ -z "$AGENT_BINARY" ]] || [[ ! -f "$AGENT_BINARY" ]]; then
        if command -v smolvm &> /dev/null; then
            echo "Building via smolvm (rust:alpine)..."
            smolvm machine run --net --mem 2048 -v "$PROJECT_ROOT:/work" --image rust:alpine \
                -- sh -c ". /usr/local/cargo/env && apk add musl-dev && cd /work && cargo build --profile $PROFILE -p smolvm-agent"
            AGENT_BINARY="$PROJECT_ROOT/target/$PROFILE/smolvm-agent"
        else
            echo "Error: Cannot build smolvm-agent"
            echo "  Either install the musl target: rustup target add $RUST_TARGET"
            echo "  Or install smolvm for cross-compilation"
            exit 1
        fi
    fi
fi

# Install the agent binary into the rootfs (if we have one)
if [[ -n "${AGENT_BINARY:-}" ]] && [[ -f "${AGENT_BINARY}" ]]; then
    echo "Installing smolvm-agent binary..."
    cp "$AGENT_BINARY" "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
    chmod +x "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
elif [[ "$NO_BUILD_AGENT" != "1" ]]; then
    echo "Error: smolvm-agent binary not found at ${AGENT_BINARY:-<unset>}"
    exit 1
fi

echo ""
echo "Agent rootfs created at: $OUTPUT_DIR"
if [[ -n "${AGENT_BINARY:-}" ]]; then
    echo "Agent binary: $AGENT_BINARY"
fi
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
