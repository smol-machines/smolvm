#!/usr/bin/env bash
# Build a distributable smolvm package for Windows (x86_64).
#
# Unlike build-dist.sh (which builds a native Unix dist), this is a CROSS build:
# it runs on a Linux host, cross-compiles smolvm.exe with the mingw-w64 toolchain,
# and assembles the layout that boots on Windows/WHP — smolvm.exe with krun.dll +
# libkrunfw.dll beside it (Windows resolves DLLs from the exe's directory), the
# Linux x86_64 agent-rootfs, and the pre-formatted ext4 disk templates. The guest
# is Linux, so the rootfs/templates are the same artifacts the linux-x86_64 dist
# ships; only the host binary + libraries are Windows-specific.
#
# Output: dist/smolvm-<version>-windows-x86_64.zip
#
# Inputs (mirrors build-dist.sh --skip-agent-build):
#   target/agent-rootfs/                  Linux x86_64 rootfs with smolvm-agent baked in
#   $LIB_DIR (default lib/windows-x86_64) krun.dll + libkrunfw.dll
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

VERSION="${VERSION:-$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)}"
PLATFORM="windows-x86_64"
DIST_NAME="smolvm-${VERSION}-${PLATFORM}"
DIST_DIR="dist/${DIST_NAME}"
LIB_DIR="${LIB_DIR:-lib/windows-x86_64}"
TARGET="x86_64-pc-windows-gnu"
ROOTFS_SRC="$PROJECT_ROOT/target/agent-rootfs"

# The Windows host dlopens libkrun at runtime (libloading), so the cross build
# has no link-time libkrun dependency — only the mingw linker is required.
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}"

echo "Building smolvm Windows distribution: ${DIST_NAME}"

# --- Preconditions ---------------------------------------------------------
for dll in krun.dll libkrunfw.dll; do
    if [[ ! -f "$LIB_DIR/$dll" ]]; then
        echo "Error: $dll not found in $LIB_DIR (set LIB_DIR to the Windows lib dir)" >&2
        exit 1
    fi
done
if [[ ! -d "$ROOTFS_SRC" ]]; then
    echo "Error: target/agent-rootfs not found." >&2
    echo "       Run ./scripts/build-agent-rootfs.sh --arch x86_64 first (CI downloads it)." >&2
    exit 1
fi
if ! command -v "$CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER" >/dev/null 2>&1; then
    echo "Error: mingw linker $CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER not found." >&2
    echo "       Install gcc-mingw-w64-x86-64 (apt) or x86_64-w64-mingw32-gcc (brew)." >&2
    exit 1
fi

# --- Cross-build smolvm.exe -------------------------------------------------
echo "Cross-compiling smolvm.exe for $TARGET..."
rustup target list --installed 2>/dev/null | grep -q "$TARGET" || rustup target add "$TARGET"
cargo build --release --target "$TARGET" --bin smolvm
EXE="target/$TARGET/release/smolvm.exe"
[[ -f "$EXE" ]] || { echo "Error: cross build did not produce $EXE" >&2; exit 1; }

# --- Assemble the dist directory -------------------------------------------
echo "Assembling distribution..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Host binary + DLLs sit together; Windows resolves krun.dll (and its
# libkrunfw.dll dependency) from the directory containing smolvm.exe.
cp "$EXE" "$DIST_DIR/smolvm.exe"
cp "$LIB_DIR/krun.dll" "$DIST_DIR/krun.dll"
cp "$LIB_DIR/libkrunfw.dll" "$DIST_DIR/libkrunfw.dll"

# Linux x86_64 guest rootfs (cp -a preserves the busybox symlinks). The caller
# must have placed the smolvm-agent binary into the rootfs already — the rootfs
# artifact itself ships agent-less (the agent is injected per-dist, like the
# Unix build-dist.sh path).
if [[ ! -f "$ROOTFS_SRC/usr/local/bin/smolvm-agent" ]]; then
    echo "Error: target/agent-rootfs is missing usr/local/bin/smolvm-agent." >&2
    echo "       Inject the Linux x86_64 agent into the rootfs before packaging." >&2
    exit 1
fi
mkdir -p "$DIST_DIR/agent-rootfs"
cp -a "$ROOTFS_SRC"/. "$DIST_DIR/agent-rootfs/"
echo "Agent rootfs size: $(du -sh "$DIST_DIR/agent-rootfs" | cut -f1)"

# --- Pre-formatted ext4 disk templates -------------------------------------
# Windows has no host mkfs.ext4, so the release ships pre-formatted templates
# next to smolvm.exe (pack/create copies them instead of formatting at runtime).
if command -v mkfs.ext4 >/dev/null 2>&1; then
    echo "Creating disk templates..."
    # Set a file's virtual (sparse) size portably — macOS lacks GNU truncate.
    extend_sparse() { # $1=path $2=bytes
        if command -v truncate >/dev/null 2>&1; then
            truncate -s "$2" "$1"
        else
            perl -e 'truncate($ARGV[0], $ARGV[1]) or die "truncate: $!"' "$1" "$2"
        fi
    }
    make_template() { # $1=path $2=label $3=virtual_bytes
        dd if=/dev/zero of="$1" bs=1 count=0 seek=$((512 * 1024 * 1024)) 2>/dev/null
        mkfs.ext4 -F -q -m 0 -L "$2" "$1"
        extend_sparse "$1" "$3"
    }
    make_template "$DIST_DIR/storage-template.ext4" smolvm        $((20 * 1024 * 1024 * 1024))
    make_template "$DIST_DIR/overlay-template.ext4" smolvm-overlay $((10 * 1024 * 1024 * 1024))
    echo "Templates: storage (20 GiB virtual), overlay (10 GiB virtual), sparse"
else
    echo "Error: mkfs.ext4 not found — install e2fsprogs to build the Windows dist." >&2
    exit 1
fi

# --- README ----------------------------------------------------------------
cat > "$DIST_DIR/README.txt" <<EOF
smolvm ${VERSION} — OCI-native microVM runtime (Windows x86_64)

REQUIREMENTS
  - Windows 10/11 x86_64 with the Windows Hypervisor Platform (WHP) feature
    enabled (Settings > Optional features, or:
      dism /online /enable-feature /featurename:HypervisorPlatform /all)

INSTALL
  Unzip this archive anywhere and keep all files together. krun.dll and
  libkrunfw.dll must stay beside smolvm.exe. Optionally add the folder to PATH.

USAGE (run smolvm.exe directly)
  smolvm.exe machine run --net --image alpine -- echo "Hello from Windows"
  smolvm.exe machine create --net --name myvm
  smolvm.exe machine start --name myvm
  smolvm.exe machine exec --name myvm -- /bin/sh
  smolvm.exe machine stats --name myvm
  smolvm.exe machine stop --name myvm

NOT YET SUPPORTED ON WINDOWS
  GPU acceleration; machine fork / snapshot.

More: https://github.com/smol-machines/smolvm
EOF

# --- Checksums + zip --------------------------------------------------------
echo "Generating checksums..."
( cd "$DIST_DIR" && sha256sum smolvm.exe krun.dll libkrunfw.dll > checksums.txt )

echo "Creating zip..."
( cd dist && rm -f "${DIST_NAME}.zip" && zip -qr "${DIST_NAME}.zip" "${DIST_NAME}" )

echo ""
echo "Distribution package created: dist/${DIST_NAME}.zip"
echo "Contents:"
ls -la "$DIST_DIR"
