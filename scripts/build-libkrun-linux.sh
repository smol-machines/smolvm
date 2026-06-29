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
#   SKIP_LIBKRUNFW=1      reuse the committed lib/linux-<arch>/libkrunfw.so and
#                         rebuild ONLY libkrun. libkrunfw is host-glibc-independent
#                         (it wraps a guest-kernel blob; its floor is GLIBC_2.2),
#                         so when the goal is lowering libkrun's glibc floor there's
#                         no need to recompile the kernel — skips the slow step.
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
        python3 python3-pyelftools pkg-config clang llvm libclang-dev curl git git-lfs \
        $([[ "$GPU" == "1" ]] && echo "libvirglrenderer-dev libepoxy-dev libdrm-dev libgbm-dev" || true)
    if ! command -v cargo >/dev/null 2>&1; then
        echo "--- installing rust toolchain ---"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
fi
command -v cargo >/dev/null 2>&1 || { source "$HOME/.cargo/env" 2>/dev/null || true; }

# Ensure the submodules + LFS are present (the kernel config lives in-tree).
# Tolerate running on rsync'd working trees (no parent .git) — the libkrun /
# libkrunfw dirs just need to already contain the patched source.
if [ -d .git ]; then
    git submodule update --init libkrun libkrunfw || true
    git lfs pull 2>/dev/null || true
fi
[ -d libkrun/src ] \
    || { echo "ERROR: libkrun/ source must be present (clone or rsync it here)." >&2; exit 1; }
# Only the libkrunfw kernel source is needed when we actually rebuild it — under
# SKIP_LIBKRUNFW the committed lib/linux-<arch>/libkrunfw.so is reused, so a
# light rsync of just libkrun/ + lib/ is enough (no multi-GB kernel tree).
if [[ "${SKIP_LIBKRUNFW:-0}" != "1" ]]; then
    [ -f libkrunfw/Makefile ] \
        || { echo "ERROR: libkrunfw/ source must be present (or set SKIP_LIBKRUNFW=1 to reuse the committed lib)." >&2; exit 1; }
fi

# bindgen needs to find libclang at runtime on some distros.
if [[ -z "${LIBCLANG_PATH:-}" ]]; then
    LIBCLANG_PATH="$(dirname "$(find /usr/lib -name 'libclang.so*' 2>/dev/null | head -1)")"
    export LIBCLANG_PATH
fi

# --- 2. libkrunfw (guest kernel) ---------------------------------------------
if [[ "${SKIP_LIBKRUNFW:-0}" == "1" ]]; then
    echo "--- SKIP_LIBKRUNFW=1: reusing committed ${LIBDIR}/libkrunfw.so.* (host-glibc-independent) ---"
    KRUNFW_SO=""   # signals "do not re-assemble libkrunfw" below
else
    echo "--- building libkrunfw (kernel ${ARCH}; this is the slow step) ---"
    # Build from INSIDE the dir, NOT `make -C`: `-C` auto-enables -w (print-dir),
    # which lands in MAKEFLAGS as a bare `w`; the kernel's `$(MAKE) $(MAKEFLAGS)`
    # recipe then dies with "No rule to make target 'w'". -j scales the kernel build.
    ( cd libkrunfw && make clean >/dev/null 2>&1 || true; make -j"$(nproc)" GUESTARCH="${ARCH}" )
    KRUNFW_SO="$(ls -1 libkrunfw/libkrunfw.so.*.*.* 2>/dev/null | head -1)"
    [[ -n "$KRUNFW_SO" ]] || { echo "ERROR: libkrunfw build produced no .so" >&2; exit 1; }
fi

# --- 3. init (guest PID-1) ---------------------------------------------------
# Two libkrun layouts, auto-detected by the presence of init/init.c:
#  - old (<= libkrun 1.x): PID-1 is a static C init compiled here and handed to
#    the build via KRUN_INIT_BINARY_PATH.
#  - libkrun 2.0+: PID-1 is a Rust crate (init/) that src/init_blob/build.rs
#    cross-compiles to musl ITSELF. `init/init` is only an empty placeholder, and
#    KRUN_INIT_BINARY_PATH must be LEFT UNSET — init_blob/build.rs uses that var
#    verbatim when set, so pointing it at the empty placeholder embeds a 0-byte
#    init and bricks the guest (PID-1 dies, VM never reaches agent-ready). The
#    musl std target must be present or the init links dynamically and can't run
#    as the guest's PID 1.
INIT_ENV=()
if [[ -f libkrun/init/init.c ]]; then
    echo "--- building guest init (legacy C; native ${ARCH} ELF) ---"
    cc -O2 -static -Wall -o libkrun/init/init libkrun/init/init.c libkrun/init/dhcp.c
    file libkrun/init/init | grep -q 'statically linked' \
        || { echo "ERROR: init/init is not a static ELF" >&2; exit 1; }
    INIT_ENV=("KRUN_INIT_BINARY_PATH=$(realpath libkrun/init/init)")
else
    echo "--- guest init: Rust crate (init_blob cross-compiles to musl) ---"
    rustup target add "${ARCH}-unknown-linux-musl" >/dev/null 2>&1 \
        || echo "WARN: could not add ${ARCH}-unknown-linux-musl; init may link dynamically"
fi

# --- 4. libkrun (VMM) --------------------------------------------------------
echo "--- building libkrun (BLK=1 NET=1 ${GPU_FLAG}) ---"
# Link with partial RELRO (lazy binding), NOT full RELRO. The GPU-enabled libkrun
# carries a hard virglrenderer NEEDED that build-dist.sh strips via patchelf so
# non-GPU hosts can dlopen it (paired with RTLD_LAZY in src/agent/krun.rs). That
# strip only holds if symbols bind lazily — full RELRO's BIND_NOW would eagerly
# resolve the now-unprovided virgl symbols and fail the load. Must match the
# relro-level=partial that build-dist.sh applies on its own libkrun compiles.
( cd libkrun && make clean >/dev/null 2>&1 || true; \
  env "${INIT_ENV[@]}" \
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C relro-level=partial" \
  make --no-print-directory BLK=1 NET=1 "${GPU_FLAG}" )
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

if [[ -n "$KRUNFW_SO" ]]; then
    assemble "$KRUNFW_SO" "libkrunfw.so"
else
    echo "--- keeping committed ${LIBDIR}/libkrunfw.so (SKIP_LIBKRUNFW) ---"
fi
# libkrun: x86_64 keeps libkrun.so as a real file too — mirror that.
KRUN_FNAME="$(basename "$KRUN_SO")"; KRUN_VER="${KRUN_FNAME#libkrun.so.}"; KRUN_MAJOR="${KRUN_VER%%.*}"
cp -f "$KRUN_SO" "$LIBDIR/$KRUN_FNAME"
cp -f "$KRUN_SO" "$LIBDIR/libkrun.so"
ln -sf "libkrun.so" "$LIBDIR/libkrun.so.${KRUN_MAJOR}"

# Record which submodule commits these libs came from, so CI can detect a stale
# bundle (scripts/check-libkrun-provenance.sh). When libkrunfw was reused rather
# than rebuilt, keep its recorded commit via --skip-libkrunfw.
STAMP_ARGS=("$LIBDIR")
[[ -z "$KRUNFW_SO" ]] && STAMP_ARGS+=(--skip-libkrunfw)
"$(dirname "$0")/stamp-libkrun-provenance.sh" "${STAMP_ARGS[@]}"

echo ""
echo "=== done: ${LIBDIR} ==="
ls -la "$LIBDIR"
echo ""
echo "Commit (these are git-LFS tracked via .gitattributes 'lib/linux-aarch64/*.so'):"
echo "  git add ${LIBDIR} && git commit -m 'feat: linux-${ARCH} libkrun/libkrunfw libs'"
