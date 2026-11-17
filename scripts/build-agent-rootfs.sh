#!/usr/bin/env bash
# Build the agent VM rootfs
#
# This script creates an Alpine-based rootfs with:
# - crane (for OCI image operations)
# - crun (OCI container runtime)
# - smolvm-agent daemon
# - Required utilities (jq, e2fsprogs, util-linux)
#
# Usage: ./scripts/build-agent-rootfs.sh [--arch aarch64|x86_64] [--no-build-agent] [--no-upgrade] [--crane <path> | --crane-release] [--install] [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
INSTALL_ROOTFS=0
OVERRIDE_ARCH=""
NO_BUILD_AGENT=0
NO_UPGRADE=0
CRANE_BINARY=""
CRANE_RELEASE=0
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
        --no-upgrade) NO_UPGRADE=1; shift ;;
        --crane)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --crane requires the path of a crane binary"
                exit 1
            fi
            CRANE_BINARY="$2"; shift 2 ;;
        --crane-release) CRANE_RELEASE=1; shift ;;
        *) POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done
if [[ -n "$CRANE_BINARY" && "$CRANE_RELEASE" == "1" ]]; then
    echo "Error: --crane and --crane-release cannot be used together"
    exit 1
fi
export INSTALL_ROOTFS

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-$PROJECT_ROOT/target/agent-rootfs}"

# Alpine version, and the branch its packages come from
ALPINE_VERSION="3.24.3"
ALPINE_BRANCH="${ALPINE_VERSION%.*}"

# Detect or override architecture
DETECTED_ARCH="${OVERRIDE_ARCH:-$(uname -m)}"
case "$DETECTED_ARCH" in
    arm64|aarch64)
        ALPINE_ARCH="aarch64"
        CRANE_GOARCH="arm64"
        CRANE_RELEASE_ARCH="arm64"
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    x86_64|amd64)
        ALPINE_ARCH="x86_64"
        CRANE_GOARCH="amd64"
        CRANE_RELEASE_ARCH="x86_64"
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "Unsupported architecture: $DETECTED_ARCH"
        exit 1
        ;;
esac

ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ALPINE_MINIROOTFS="alpine-minirootfs-${ALPINE_VERSION}-${ALPINE_ARCH}.tar.gz"
ALPINE_URL="${ALPINE_MIRROR}/v${ALPINE_BRANCH}/releases/${ALPINE_ARCH}/${ALPINE_MINIROOTFS}"

# Crane, and the Go it is built with: a crane release can be built with a Go
# that is several patch releases old.
CRANE_VERSION="0.22.1"
GO_VERSION="1.26.10"
CRANE_PACKAGE="github.com/google/go-containerregistry/cmd/crane@v${CRANE_VERSION}"
CRANE_RELEASE_URL="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_RELEASE_ARCH}.tar.gz"

# crane must run in the Alpine (musl) rootfs: a static executable for the
# target architecture.
check_crane_binary() {
    local binary="$1" info file_arch
    if [[ ! -f "$binary" ]]; then
        echo "Error: crane $binary: no such file"
        return 1
    fi
    info="$(file -bL "$binary")"
    case "$ALPINE_ARCH" in
        x86_64)  file_arch="x86-64" ;;
        aarch64) file_arch="aarch64" ;;
    esac
    if [[ "$info" != ELF*"$file_arch"* ]]; then
        echo "Error: crane $binary is not an ELF executable for $ALPINE_ARCH: $info"
        return 1
    fi
    if [[ "$info" == *"dynamically linked"* || "$info" == *interpreter* ]]; then
        echo "Error: crane $binary is dynamically linked; build it with CGO_ENABLED=0"
        return 1
    fi
}

# A native go is used only if it honours GOTOOLCHAIN (Go 1.21 or later):
# an older go would build crane with its own standard library.
check_native_go() {
    command -v go &> /dev/null || return 1
    local version major minor
    version="$(go env GOVERSION 2>/dev/null)" || return 1
    version="${version#go}"
    major="${version%%.*}"
    minor="${version#*.}"
    minor="${minor%%[!0-9]*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major > 1 || (major == 1 && minor >= 21) ))
}

# Build crane into <dir>/crane. GOARCH cross-compiles for the target, so the
# build always runs at the host's architecture. A cross-compiled `go install`
# puts the binary in bin/linux_<arch>/, a native one in bin/.
build_crane() {
    local out_dir="$1" native_go=0
    if check_native_go; then
        native_go=1
    elif command -v go &> /dev/null; then
        echo "  Not using native $(go env GOVERSION 2>/dev/null || echo go): Go 1.21 or later is needed"
    fi
    if [[ "$native_go" == "1" ]]; then
        echo "  Building crane with native go (GOTOOLCHAIN=go${GO_VERSION})..."
        local gopath="$WORK_DIR/gopath"
        GOTOOLCHAIN="go${GO_VERSION}" GOPATH="$gopath" GOMODCACHE="$(go env GOMODCACHE)" GOBIN='' \
            CGO_ENABLED=0 GOOS=linux GOARCH="$CRANE_GOARCH" \
            go install -trimpath -ldflags="-s -w" "$CRANE_PACKAGE"
        if [[ -f "$gopath/bin/linux_${CRANE_GOARCH}/crane" ]]; then
            cp "$gopath/bin/linux_${CRANE_GOARCH}/crane" "$out_dir/crane"
        else
            cp "$gopath/bin/crane" "$out_dir/crane"
        fi
    elif command -v smolvm &> /dev/null; then
        echo "  Building crane via smolvm (golang:${GO_VERSION}-alpine)..."
        smolvm machine run --net --mem 2048 -v "$out_dir:/out" --image "golang:${GO_VERSION}-alpine" \
            -- sh -c "GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=$CRANE_GOARCH \
                go install -trimpath -ldflags='-s -w' $CRANE_PACKAGE \
                && { cp \"\$(go env GOPATH)/bin/linux_${CRANE_GOARCH}/crane\" /out/crane 2>/dev/null \
                     || cp \"\$(go env GOPATH)/bin/crane\" /out/crane; }"
    else
        echo "Error: building crane needs go >= 1.21 or smolvm to fetch and run the build toolchain; pass --crane-release or --crane <path> to use a prebuilt crane"
        exit 1
    fi
}

# Download the crane release binary for the target into <dir>/crane.
download_crane() {
    local out_dir="$1"
    echo "  Downloading the crane ${CRANE_VERSION} release..."
    curl -fsSL "$CRANE_RELEASE_URL" | tar -xzf - -C "$out_dir" crane
}

# Install <binary> into the rootfs as crane.
install_crane() {
    local binary="$1"
    echo "Installing crane..."
    mkdir -p "$OUTPUT_DIR/usr/local/bin"
    install -m 0755 "$binary" "$OUTPUT_DIR/usr/local/bin/crane"
    if command -v sha256sum &> /dev/null; then
        echo "  crane sha256 $(sha256sum "$binary" | cut -d' ' -f1)"
    else
        echo "  crane sha256 $(shasum -a 256 "$binary" | cut -d' ' -f1)"
    fi
}

# Remove the work directory. Go makes some of what it writes read-only.
cleanup() {
    chmod -R u+w "$WORK_DIR" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}

# Temporary files go in a private work directory, removed on any exit.
WORK_DIR="$(mktemp -d)"
trap cleanup EXIT

echo "Building agent rootfs..."
echo "  Alpine: ${ALPINE_VERSION} (${ALPINE_ARCH})"
echo "  Output: ${OUTPUT_DIR}"

# Get crane before the output directory is touched, so a crane that cannot be
# built, downloaded or used stops the build first.
if [[ -z "$CRANE_BINARY" ]]; then
    CRANE_BUILD_DIR="$WORK_DIR/crane"
    mkdir -p "$CRANE_BUILD_DIR"
    if [[ "$CRANE_RELEASE" == "1" ]]; then
        download_crane "$CRANE_BUILD_DIR"
    else
        build_crane "$CRANE_BUILD_DIR"
    fi
    CRANE_BINARY="$CRANE_BUILD_DIR/crane"
fi
check_crane_binary "$CRANE_BINARY" || exit 1
if [[ "$CRANE_RELEASE" == "1" ]]; then
    CRANE_ORIGIN="upstream release binary"
elif [[ -n "${CRANE_BUILD_DIR:-}" ]]; then
    CRANE_ORIGIN="built with Go ${GO_VERSION}"
else
    CRANE_ORIGIN="local ${CRANE_BINARY}"
    CRANE_VERSION="$("$CRANE_BINARY" version 2>/dev/null)" || CRANE_VERSION=""
    [[ "$CRANE_VERSION" =~ ^v?[0-9]+\.[0-9]+ ]] || CRANE_VERSION="unknown version"
    CRANE_VERSION="${CRANE_VERSION#v}"
fi
echo "  Crane: ${CRANE_VERSION} (${CRANE_ORIGIN})"

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

install_crane "$CRANE_BINARY"

# Install additional Alpine packages into the rootfs.
# Strategies:
#   1. apk.static (Linux only) — runs natively, supports cross-arch via --arch
#   2. smolvm (any host) — only for native-arch builds (pulls host-arch image)
echo "Installing additional packages..."
# GNU tar replaces busybox tar, which never sets a symlink's owner when it
# unpacks image layers.
APK_PACKAGES="jq e2fsprogs e2fsprogs-extra crun util-linux libcap seatd tar"

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
    APK_STATIC_MIRROR="${ALPINE_MIRROR}/v${ALPINE_BRANCH}/main/${HOST_ARCH}"
    APK_STATIC_PKG=$(curl -fsSL "$APK_STATIC_MIRROR/" | grep -o 'apk-tools-static-[^"]*\.apk' | head -1)
    if [[ -z "$APK_STATIC_PKG" ]]; then
        echo "Error: could not find apk-tools-static package at $APK_STATIC_MIRROR"
        exit 1
    fi
    curl -fsSL -o "$WORK_DIR/apk-static.apk" "${APK_STATIC_MIRROR}/${APK_STATIC_PKG}"
    mkdir -p "$WORK_DIR/apk-static"
    tar -xzf "$WORK_DIR/apk-static.apk" -C "$WORK_DIR/apk-static" 2>/dev/null || true

    # Set up apk repositories in the rootfs
    mkdir -p "$OUTPUT_DIR/etc/apk"
    echo "${ALPINE_MIRROR}/v${ALPINE_BRANCH}/main" > "$OUTPUT_DIR/etc/apk/repositories"
    echo "${ALPINE_MIRROR}/v${ALPINE_BRANCH}/community" >> "$OUTPUT_DIR/etc/apk/repositories"

    # --no-scripts: skip pre/post-install scripts and triggers.
    # When cross-building (e.g. aarch64 rootfs on x86_64 host), those scripts
    # are aarch64 ELF binaries that the host kernel can't exec, causing exit
    # code 127. The minirootfs already ships busybox symlinks, and seatd runs
    # as root in the VM so the 'seat' group creation is not required.
    local -a APK_STATIC_COMMAND=("$WORK_DIR/apk-static/sbin/apk.static")
    local -a APK_STATIC_INITDB_ARGS=()
    if [[ "$EUID" != "0" ]]; then
        # apk-tools 3 refuses to create a database as non-root unless
        # --usermode is given; files keep the invoking user's ownership, as
        # they would from any non-root build. (A user namespace mapping only
        # root cannot do better: apk then fails to chown setgid binaries to
        # their groups, and from apk-tools 3.0.9 --no-chown means --usermode,
        # which apk refuses as root.)
        APK_STATIC_INITDB_ARGS=(--usermode)
    fi
    "${APK_STATIC_COMMAND[@]}" \
        --root "$OUTPUT_DIR" \
        --initdb \
        "${APK_STATIC_INITDB_ARGS[@]}" \
        --no-cache \
        --allow-untrusted \
        --no-scripts \
        --arch "$ALPINE_ARCH" \
        add $APK_PACKAGES
    if [[ "$NO_UPGRADE" != "1" ]]; then
        # Bring the minirootfs's own packages up to the branch's current versions.
        "${APK_STATIC_COMMAND[@]}" \
            --root "$OUTPUT_DIR" \
            --no-cache \
            --allow-untrusted \
            --no-scripts \
            --arch "$ALPINE_ARCH" \
            upgrade
    fi
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

normalize_owner_only_modes() {
    local rootfs_dir="$1"

    # The stock Alpine minirootfs ships four paths only their owner can read.
    # A mode-preserving install — packaging/arch/PKGBUILD and packaging/nfpm.yaml
    # both copy the tree as-is — lands them root-owned under a system prefix such
    # as /usr/lib/smolvm/agent-rootfs, where the user running smolvm cannot read
    # them. `pack create` tars the whole rootfs and cannot skip anything, so it
    # hard-fails with "Permission denied" (collect_agent_rootfs,
    # crates/smolvm-pack/src/assets.rs). That also breaks plain `machine run`
    # whenever an init layer is baked via `pack create --from-vm` — a Smolfile
    # with [dev] init steps, or any --oci-cache run.
    #
    # Booting is unaffected either way: the guest never opens these files, and
    # since the vsock readiness doorbell the host no longer writes into this
    # directory to signal ready.
    #
    # Widening them discloses nothing. This tree is a build artifact published on
    # a public release page and byte-identical for every user: `shadow` carries no
    # hashes (root:*, every other account !), /etc/crontabs/root is the stock
    # run-parts schedule, /root is empty, and lib/apk/db/lock is zero bytes.
    # Ownership and write bits are left alone.
    echo "Normalizing owner-only permissions..."
    local owner_only_dirs=(
        # The tree root itself: created by this script under the builder's umask,
        # so a restrictive umask would otherwise produce a rootfs nobody but the
        # owner can even traverse into.
        "$rootfs_dir"
        "$rootfs_dir/root"
    )
    local owner_only_files=(
        "$rootfs_dir/etc/shadow"
        "$rootfs_dir/etc/crontabs/root"
        "$rootfs_dir/lib/apk/db/lock"
    )
    for path in "${owner_only_dirs[@]}"; do
        if [[ -d "$path" ]]; then
            chmod 0755 "$path"
        fi
    done
    for path in "${owner_only_files[@]}"; do
        if [[ -f "$path" ]]; then
            chmod 0644 "$path"
        fi
    done

    # Then verify the whole tree, and fail the build on anything still owner-only.
    #
    # Deliberately not a blanket `chmod -R a+rX`: this script also runs against
    # user-supplied trees, and SMOLVM_AGENT_ROOTFS can boot one. The rootfs is
    # shared into every VM, so a recursive widen would quietly expose a custom
    # tree's 0600 registry token or signing key to every workload. Naming the
    # known paths and hard-failing on the rest means a later Alpine bump that adds
    # a fifth one stops the build here — instead of shipping a rootfs that cannot
    # be packed, or widening something nobody looked at.
    local owner_only
    owner_only="$(find "$rootfs_dir" \
        \( -type f ! -perm -o=r \) -o \( -type d ! -perm -o=rx \) 2>/dev/null || true)"
    if [[ -n "$owner_only" ]]; then
        echo "Error: agent rootfs has paths unreadable to a non-owner:" >&2
        echo "$owner_only" | sed "s#^${rootfs_dir}#  #" >&2
        echo "" >&2
        echo "A mode-preserving install makes these unreadable to the user running" >&2
        echo "smolvm, and 'pack create' fails on them. Either widen them by name in" >&2
        echo "normalize_owner_only_modes() once you have confirmed they hold nothing" >&2
        echo "secret, or keep them out of the rootfs." >&2
        exit 1
    fi
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
    APK_UPGRADE_CMD=""
    if [[ "$NO_UPGRADE" != "1" ]]; then
        APK_UPGRADE_CMD=" && apk upgrade --root /rootfs --no-cache"
    fi
    smolvm machine run --net -v "$OUTPUT_DIR:/rootfs" --image "alpine:${ALPINE_BRANCH}" \
        -- sh -c "apk add --root /rootfs --initdb --no-cache $APK_PACKAGES${APK_UPGRADE_CMD}"
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

# Bake in the agent's /mnt mount points so the rootfs is self-sufficient.
#
# At boot, setup_persistent_rootfs() (crates/smolvm-agent/src/main.rs) mounts
# the overlay/storage disks and stages pivot_root under these paths BEFORE any
# writable overlay exists — its create_dir_all() calls run against the agent
# rootfs itself. On a read-only rootfs, or one built from scratch without the
# Alpine base's empty /mnt, those mkdirs fail, the mounts fail, and the VM
# boots without its persistent overlay. Pre-creating the dirs here makes those
# runtime create_dir_all() calls a no-op (the agent keeps them as a backstop
# and WARNs if a mount point is ever missing on a RO rootfs).
#
# Keep this list in sync with the agent's mount-point constants:
#   /mnt/overlay  OVERLAY_MOUNT       } setup_persistent_rootfs(), required at
#   /mnt/storage  STORAGE_TEMP_MOUNT  } boot before the overlay is writable
#   /mnt/newroot  NEWROOT             }
#   /run/smolvm/virtiofs paths::VIRTIOFS_MOUNT_ROOT  per-tag virtiofs staging
#   /mnt/rosetta  vm::rosetta::ROSETTA_GUEST_PATH  macOS Rosetta binfmt share
for mnt_dir in overlay storage newroot rosetta; do
    mkdir -p "$OUTPUT_DIR/mnt/$mnt_dir"
done
mkdir -p "$OUTPUT_DIR/run/smolvm/virtiofs"

# Install the pre-built Rosetta ptrace wrapper. This static binary intercepts
# Rosetta's Virtualization.framework ioctl validation, allowing x86_64
# translation to work under libkrun's Hypervisor.framework backend.
# Source: scripts/rosetta/rosetta-wrapper.c
ROSETTA_WRAPPER="$(dirname "$0")/rosetta/rosetta-wrapper"
if [ -f "$ROSETTA_WRAPPER" ]; then
    cp "$ROSETTA_WRAPPER" "$OUTPUT_DIR/usr/bin/rosetta-wrapper"
    chmod 755 "$OUTPUT_DIR/usr/bin/rosetta-wrapper"
fi

# Remove existing init (it's a symlink to busybox) and replace with
# symlink to the agent binary. The agent handles overlayfs setup +
# pivot_root internally before starting the vsock listener.
rm -f "$OUTPUT_DIR/sbin/init"
ln -sf /usr/local/bin/smolvm-agent "$OUTPUT_DIR/sbin/init"

# Create resolv.conf
echo "nameserver 1.1.1.1" > "$OUTPUT_DIR/etc/resolv.conf"

# Remove seatd socket if baked in during build (build artifact, not runtime state)
rm -f "$OUTPUT_DIR/run/seatd.sock"

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
            # Build the agent and the CUDA-over-vsock guest runner together.
            cargo build --profile "$PROFILE" -p smolvm-agent -p smolvm-cuda-guest \
                --target "$RUST_TARGET" --manifest-path "$PROJECT_ROOT/Cargo.toml"
            AGENT_BINARY="$PROJECT_ROOT/target/$RUST_TARGET/$PROFILE/smolvm-agent"
            CUDA_GUEST_BINARY="$PROJECT_ROOT/target/$RUST_TARGET/$PROFILE/smolvm-cuda-run"
        fi
    fi

    # Strategy 2: smolvm with rust:alpine (dogfooding)
    if [[ -z "$AGENT_BINARY" ]] || [[ ! -f "$AGENT_BINARY" ]]; then
        if command -v smolvm &> /dev/null; then
            echo "Building via smolvm (rust:alpine)..."
            smolvm machine run --net --mem 2048 -v "$PROJECT_ROOT:/work" --image rust:alpine \
                -- sh -c ". /usr/local/cargo/env && apk add musl-dev && cd /work && cargo build --profile $PROFILE -p smolvm-agent -p smolvm-cuda-guest"
            AGENT_BINARY="$PROJECT_ROOT/target/$PROFILE/smolvm-agent"
            CUDA_GUEST_BINARY="$PROJECT_ROOT/target/$PROFILE/smolvm-cuda-run"
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
    install -m 0755 "$AGENT_BINARY" "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
elif [[ "$NO_BUILD_AGENT" != "1" ]]; then
    echo "Error: smolvm-agent binary not found at ${AGENT_BINARY:-<unset>}"
    exit 1
fi

# Install the CUDA-over-vsock guest runner (best-effort: a missing binary just
# means the image ships without it; CUDA is opt-in via `machine create --cuda`).
if [[ -n "${CUDA_GUEST_BINARY:-}" ]] && [[ -f "${CUDA_GUEST_BINARY}" ]]; then
    echo "Installing smolvm-cuda-run binary..."
    install -m 0755 "$CUDA_GUEST_BINARY" "$OUTPUT_DIR/usr/local/bin/smolvm-cuda-run"
fi

# CUDA guest shims: glibc cdylibs the agent bind-mounts into workload
# containers on `--cuda` (see crates/smolvm-agent/src/cuda.rs). They are loaded
# by the container's glibc — not by the (musl) agent — so they build for the
# native gnu target.
#
# Two ways to supply them, in priority order:
#   1. Prebuilt paths via CUDART_SHIM_BINARY + CUDA_DRIVER_SHIM_BINARY (how the
#      release workflow ships them: built once per arch, incl. cross-compiled
#      aarch64, then installed here regardless of --no-build-agent).
#   2. Native `cargo build` fallback (local dev on a matching-arch Linux host).
# Best-effort: without them `--cuda` still works, the user just stages shims
# manually.
CUDART_SHIM_SRC="${CUDART_SHIM_BINARY:-}"
CUDA_DRIVER_SHIM_SRC="${CUDA_DRIVER_SHIM_BINARY:-}"

if { [[ -z "$CUDART_SHIM_SRC" ]] || [[ -z "$CUDA_DRIVER_SHIM_SRC" ]]; } \
    && [[ "$NO_BUILD_AGENT" != "1" && "$(uname -s)" == "Linux" && "$(uname -m)" == "$ALPINE_ARCH" ]] \
    && command -v cargo &> /dev/null; then
    echo "Building CUDA guest shims (native gnu target)..."
    if cargo build --release -p smolvm-cudart-shim -p smolvm-cuda-shim -p smolvm-nvml-shim \
        --manifest-path "$PROJECT_ROOT/Cargo.toml"; then
        CUDART_SHIM_SRC="${CUDART_SHIM_SRC:-$PROJECT_ROOT/target/release/libcudart.so}"
        CUDA_DRIVER_SHIM_SRC="${CUDA_DRIVER_SHIM_SRC:-$PROJECT_ROOT/target/release/libcuda.so}"
        NVML_SHIM_SRC="${NVML_SHIM_SRC:-$PROJECT_ROOT/target/release/libnvidia_ml.so}"
    else
        echo "CUDA guest shim build failed — rootfs ships without auto-staging"
    fi
fi

if [[ -n "$CUDART_SHIM_SRC" && -f "$CUDART_SHIM_SRC" \
      && -n "$CUDA_DRIVER_SHIM_SRC" && -f "$CUDA_DRIVER_SHIM_SRC" ]]; then
    echo "Installing CUDA guest shims..."
    mkdir -p "$OUTPUT_DIR/usr/local/lib/smolvm-cuda"
    cp "$CUDART_SHIM_SRC" "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/libcudart-shim.so"
    cp "$CUDA_DRIVER_SHIM_SRC" "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/libcuda.so.1"
    # Unversioned linker ("dev") names next to the sonames. Code that *links*
    # against CUDA at runtime — Triton's JIT compiles cuda_utils with
    # `gcc … -lcuda`, taking its -L from LD_LIBRARY_PATH, which the shim dir
    # rides — needs `libcuda.so`; ld does not accept `libcuda.so.1`. Without
    # these, torch.compile/Triton dies inside the guest with an opaque gcc
    # failure and users hand-symlink the shim to fix it.
    ln -sf libcuda.so.1 "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/libcuda.so"
    ln -sf libcudart-shim.so "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/libcudart.so"
    # Dynamic CUDA applications carry versioned DT_NEEDED entries. PyTorch's
    # wheel-local copies are covered by per-file bind mounts, but an ordinary
    # nvcc binary expects the matching soname to exist directly on
    # LD_LIBRARY_PATH. Route every runtime/library ABI the shim advertises to
    # the same implementation so those binaries start without manual links.
    for soname in \
        libcudart.so.13 libcublas.so.13 libcublasLt.so.13 \
        libcudart.so.12 libcublas.so.12 libcublasLt.so.12 libcudnn.so.9 \
        libcudart.so.11.0 libcublas.so.11 libcublasLt.so.11 libcudnn.so.8; do
        ln -sf libcudart-shim.so "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/$soname"
    done
    # NVML drop-in: frameworks (vLLM) detect the GPU through NVML, not the CUDA
    # driver — the shim dir rides LD_LIBRARY_PATH, so the plain-soname dlopen of
    # libnvidia-ml.so.1 resolves here. Best-effort: absent on non-Linux builds.
    if [[ -n "${NVML_SHIM_SRC:-}" && -f "$NVML_SHIM_SRC" ]]; then
        cp "$NVML_SHIM_SRC" "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/libnvidia-ml.so.1"
    fi
    echo "Installed CUDA guest shims"
    # Stamp the shims' wire fingerprint into the rootfs so the host can flag a
    # stale rootfs at boot (internal_boot's warn_if_stale_cuda_shim) instead of
    # leaving the user with an opaque cuInit failure. Works for both the prebuilt
    # (release) and native-build paths. Read it from the guest runner (built from
    # the same smolvm-cuda source as the shims, so the same PROTO_HASH); fall back
    # to a quick native build of that same binary when cargo is available.
    PROTO_HASH=""
    if [[ -n "${CUDA_GUEST_BINARY:-}" && -x "${CUDA_GUEST_BINARY:-}" ]]; then
        PROTO_HASH="$("$CUDA_GUEST_BINARY" --proto-hash 2>/dev/null || true)"
    fi
    if [[ -z "$PROTO_HASH" ]] && command -v cargo &> /dev/null; then
        PROTO_HASH="$(cargo run --release -q -p smolvm-cuda-guest \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" -- --proto-hash 2>/dev/null || true)"
    fi
    if [[ -n "$PROTO_HASH" ]]; then
        printf '%s\n' "$PROTO_HASH" > "$OUTPUT_DIR/usr/local/lib/smolvm-cuda/proto-hash"
        echo "Stamped CUDA shim proto-hash: $PROTO_HASH"
    else
        echo "Could not determine CUDA proto-hash — rootfs left unstamped (boot check skips)"
    fi
else
    echo "Skipping CUDA guest shims (no prebuilt paths, cross-arch, or no cargo) — auto-staging disabled in this rootfs"
fi

# Vulkan (Venus) guest driver bundle: the patched Mesa virtio ICD plus its
# shared-library closure and the Vulkan loader, pinned by URL + sha256. The
# agent bind-mounts it into --gpu workload containers so stock glibc images
# get working Vulkan with no setup (crates/smolvm-agent/src/vulkan.rs).
# Best-effort: without it, --gpu still works in the manual-setup mode.
if "$SCRIPT_DIR/fetch-vulkan-guest-driver.sh" "$ALPINE_ARCH" "$OUTPUT_DIR/usr/local/lib/smolvm-vulkan"; then
    echo "Installed Vulkan guest driver bundle"
else
    echo "Vulkan guest driver fetch failed — rootfs ships without auto-staging"
    rm -rf "$OUTPUT_DIR/usr/local/lib/smolvm-vulkan"
fi

# Last, so it covers every file the steps above installed — not just the Alpine base.
normalize_owner_only_modes "$OUTPUT_DIR"

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
