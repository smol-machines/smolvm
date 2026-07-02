#!/usr/bin/env bash
# Build a distributable smolvm package for Windows (x86_64).
#
# Unlike build-dist.sh (which builds a native Unix dist), this is a CROSS build:
# it runs on a Linux host, cross-compiles smolvm.exe with the mingw-w64 toolchain,
# and assembles the layout that boots on Windows/WHP — smolvm.exe with krun.dll +
# libkrunfw.dll beside it (Windows resolves DLLs from the exe's directory), the
# Linux x86_64 agent-rootfs (as a tarball), and the pre-formatted ext4 disk templates. The guest
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

# Ship the Linux x86_64 guest rootfs as a TARBALL, not an extracted dir: a `.zip`
# can't carry the dir tree (busybox symlinks, modes, special files) — that is what
# broke the first attempt. smolvm.exe extracts `agent-rootfs.tar.gz` on first run
# via ensure_extracted_rootfs (Windows `tar.exe`; symlinks it can't make are
# skipped, tolerated by the runtime). The caller must have injected the agent
# binary into the rootfs already (the rootfs artifact ships agent-less).
if [[ ! -f "$ROOTFS_SRC/usr/local/bin/smolvm-agent" ]]; then
    echo "Error: target/agent-rootfs is missing usr/local/bin/smolvm-agent." >&2
    echo "       Inject the Linux x86_64 agent into the rootfs before packaging." >&2
    exit 1
fi
# The rootfs is extracted as root in CI; use sudo to read any restricted files,
# then hand the tarball back to the runner user so the later `zip` can read it.
TAR_SUDO=""
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then TAR_SUDO="sudo"; fi
echo "Packing agent-rootfs.tar.gz..."
$TAR_SUDO tar -czf "$DIST_DIR/agent-rootfs.tar.gz" -C "$ROOTFS_SRC" .
[[ -n "$TAR_SUDO" ]] && $TAR_SUDO chown "$(id -u):$(id -g)" "$DIST_DIR/agent-rootfs.tar.gz"
echo "Agent rootfs tarball: $(du -h "$DIST_DIR/agent-rootfs.tar.gz" | cut -f1)"

# --- Pre-formatted ext4 disk templates -------------------------------------
# Windows has no host mkfs.ext4, so the release ships pre-formatted templates
# next to smolvm.exe (pack/create copies them instead of formatting at runtime).
#
# Ship them at their REAL 512 MiB size — do NOT extend to the 20/10 GiB virtual
# sizes here. Zip has no sparse-file representation, so an extended template
# materializes as tens of GiB of zeros on extraction (and, no longer holey, gets
# dense-copied per machine start until the disk fills). The engine extends the
# per-machine copy to the requested virtual size itself (copy_disk_from_template
# marks the copy sparse and set_lens it; the guest grows the ext4 with resize2fs
# at boot), so nothing on Windows needs a pre-extended template. The Linux/macOS
# tarballs keep full-size templates via GNU tar --sparse (see build-dist.sh).
if command -v mkfs.ext4 >/dev/null 2>&1; then
    echo "Creating disk templates..."
    make_template() { # $1=path $2=label
        dd if=/dev/zero of="$1" bs=1 count=0 seek=$((512 * 1024 * 1024)) 2>/dev/null
        mkfs.ext4 -F -q -m 0 -L "$2" "$1"
    }
    make_template "$DIST_DIR/storage-template.ext4" smolvm
    make_template "$DIST_DIR/overlay-template.ext4" smolvm-overlay
    echo "Templates: storage + overlay (512 MiB each; engine extends copies to their virtual size)"
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
( cd "$DIST_DIR" && sha256sum smolvm.exe krun.dll libkrunfw.dll agent-rootfs.tar.gz > checksums.txt )

echo "Creating zip..."
( cd dist && rm -f "${DIST_NAME}.zip" && zip -qr "${DIST_NAME}.zip" "${DIST_NAME}" )

echo ""
echo "Distribution package created: dist/${DIST_NAME}.zip"
echo "Contents:"
ls -la "$DIST_DIR"
