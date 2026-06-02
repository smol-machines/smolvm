#!/usr/bin/env bash
#
# Build libkrunfw + libkrun for the HOST Linux architecture from smolvm's
# patched submodules, and assemble them into lib/linux-<arch>/ in the layout
# the release pipeline + smolvm runtime expect.
#
# Run this ON a native Linux host of the target arch — there is no cross-compile
# here. The intended use is layer 3 of Arm cloud support: SSH into a GCP
# C4A.metal (Axion arm64) worker and run this to produce lib/linux-aarch64/.
# It also works on x86_64 Linux to refresh lib/linux-x86_64/.
#
# Why a native build: libkrunfw compiles a full Linux kernel (linux-6.12.87 +
# patches) with the per-arch config (config-libkrunfw_<arch>), and libkrun
# embeds a static init ELF of the guest arch. Both are far simpler and more
# reliable built natively than cross-compiled.
#
# NOTE: smolvm's libkrun/libkrunfw are a PATCHED fork (init.c, virtiofs ioctl,
# DNS egress, etc.) — upstream prebuilt .so files will not work. Always build
# from the in-tree submodules.
#
# Usage:  ./scripts/build-libkrun-linux.sh
#   GPU=0                 skip the GPU feature (drops the virglrenderer dep)
#   SKIP_DEPS=1           assume build deps are already installed
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: this script must run on Linux (native build). For macOS use 'make smolvm' in libkrun/." >&2
    exit 1
fi

ARCH="$(uname -m)"                       # aarch64 | x86_64
LIBDIR="lib/linux-${ARCH}"
GPU="${GPU:-1}"
GPU_FLAG="GPU=${GPU}"

echo "=== building libkrun stack for linux-${ARCH} -> ${LIBDIR} ==="

# --- 1. Build dependencies (Debian/Ubuntu) -----------------------------------
if [[ "${SKIP_DEPS:-0}" != "1" ]] && command -v apt-get >/dev/null 2>&1; then
    echo "--- installing build dependencies ---"
    sudo apt-get update -q
    # kernel build (libkrunfw)        + libkrun (rust/bindgen) + git-lfs/runtime
    sudo apt-get install -y -q \
        build-essential flex bison libelf-dev libssl-dev bc cpio rsync kmod \
        python3 pkg-config clang llvm libclang-dev curl git git-lfs \
        $([[ "$GPU" == "1" ]] && echo libvirglrenderer-dev || true)
    if ! command -v cargo >/dev/null 2>&1; then
        echo "--- installing rust toolchain ---"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
fi
command -v cargo >/dev/null 2>&1 || { source "$HOME/.cargo/env" 2>/dev/null || true; }

# Ensure the submodules + LFS are present (the kernel config lives in-tree).
git submodule update --init libkrun libkrunfw
git lfs pull 2>/dev/null || true

# bindgen needs to find libclang at runtime on some distros.
if [[ -z "${LIBCLANG_PATH:-}" ]]; then
    LIBCLANG_PATH="$(dirname "$(find /usr/lib -name 'libclang.so*' 2>/dev/null | head -1)")"
    export LIBCLANG_PATH
fi

# --- 2. libkrunfw (guest kernel) ---------------------------------------------
echo "--- building libkrunfw (kernel ${ARCH}; this is the slow step) ---"
make -C libkrunfw clean 2>/dev/null || true
make -C libkrunfw GUESTARCH="${ARCH}"
KRUNFW_SO="$(ls -1 libkrunfw/libkrunfw.so.*.*.* 2>/dev/null | head -1)"
[[ -n "$KRUNFW_SO" ]] || { echo "ERROR: libkrunfw build produced no .so" >&2; exit 1; }

# --- 3. init (static guest-arch ELF, built natively) -------------------------
echo "--- building guest init (native ${ARCH} ELF) ---"
cc -O2 -static -Wall -o libkrun/init/init libkrun/init/init.c libkrun/init/dhcp.c
file libkrun/init/init | grep -q 'statically linked' \
    || { echo "ERROR: init/init is not a static ELF" >&2; exit 1; }

# --- 4. libkrun (VMM) --------------------------------------------------------
echo "--- building libkrun (BLK=1 NET=1 ${GPU_FLAG}) ---"
make -C libkrun clean 2>/dev/null || true
KRUN_INIT_BINARY_PATH="$(realpath libkrun/init/init)" \
    make -C libkrun BLK=1 NET=1 "${GPU_FLAG}"
KRUN_SO="$(ls -1 libkrun/target/release/libkrun.so.*.*.* 2>/dev/null | head -1)"
[[ -n "$KRUN_SO" ]] || { echo "ERROR: libkrun build produced no .so" >&2; exit 1; }

# --- 5. Assemble lib/linux-<arch>/ (mirror the x86_64 layout + sonames) ------
echo "--- assembling ${LIBDIR} ---"
mkdir -p "$LIBDIR"

assemble() {
    # $1 = built .so.X.Y.Z   $2 = base name (libkrun.so / libkrunfw.so)
    local built="$1" base="$2" ver fname major
    fname="$(basename "$built")"          # e.g. libkrunfw.so.5.3.0
    ver="${fname#"${base}."}"             # 5.3.0
    major="${ver%%.*}"                    # 5
    cp -f "$built" "$LIBDIR/$fname"
    ln -sf "$fname" "$LIBDIR/${base}.${major}"   # libkrunfw.so.5 -> .so.5.3.0
    ln -sf "${base}.${major}" "$LIBDIR/${base}"  # libkrunfw.so   -> .so.5
}

assemble "$KRUNFW_SO" "libkrunfw.so"
# libkrun: x86_64 keeps libkrun.so as a real file too — mirror that.
KRUN_FNAME="$(basename "$KRUN_SO")"; KRUN_VER="${KRUN_FNAME#libkrun.so.}"; KRUN_MAJOR="${KRUN_VER%%.*}"
cp -f "$KRUN_SO" "$LIBDIR/$KRUN_FNAME"
cp -f "$KRUN_SO" "$LIBDIR/libkrun.so"
ln -sf "libkrun.so" "$LIBDIR/libkrun.so.${KRUN_MAJOR}"

echo ""
echo "=== done: ${LIBDIR} ==="
ls -la "$LIBDIR"
echo ""
echo "Commit (these are git-LFS tracked via .gitattributes 'lib/linux-aarch64/*.so'):"
echo "  git add ${LIBDIR} && git commit -m 'feat: linux-${ARCH} libkrun/libkrunfw libs'"
