#!/usr/bin/env bash
# Build the macOS virglrenderer bundled in lib/ from the krunkit fork plus the
# Venus bridge patch, and make it relocatable the way the rest of lib/ is.
#
# The stock krunkit virglrenderer only advertises what Metal can do natively,
# which leaves Venus with no external memory: no dmabuf, no modifiers, no
# swapchain, so guests get Vulkan compute at best and every compositor falls
# back to software. The patch in patches/virglrenderer/ bridges the guest's
# dmabuf and modifier requests onto VK_EXT_external_memory_host, which
# MoltenVK does support.
#
# Requirements: brew install molten-vk libepoxy meson ninja pkg-config
#   SKIP_DEPS=1   assume the brew packages are present
#   OUT=<path>    where to put the dylib (default: lib/libvirglrenderer.1.dylib)
set -euo pipefail

VIRGL_VERSION="0.10.4e-krunkit"
VIRGL_URL="https://gitlab.freedesktop.org/slp/virglrenderer/-/archive/${VIRGL_VERSION}/virglrenderer-${VIRGL_VERSION}.tar.gz"
VIRGL_SHA256="09d000623fbdb966cb604eb48c962a0815e8142383e6066d6494809335b76dbb"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/lib/libvirglrenderer.1.dylib}"
WORK="$ROOT/target/virglrenderer"
PATCH_DIR="$ROOT/patches/virglrenderer"

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }
if [[ "${SKIP_DEPS:-0}" != "1" ]]; then
    for pkg in molten-vk libepoxy meson ninja pkg-config; do
        brew list --versions "$pkg" >/dev/null 2>&1 || brew install "$pkg"
    done
fi
MVK="$(brew --prefix molten-vk)"
EPOXY="$(brew --prefix libepoxy)"

mkdir -p "$WORK"
TARBALL="$WORK/virglrenderer-${VIRGL_VERSION}.tar.gz"
if [[ ! -f "$TARBALL" ]] || ! echo "$VIRGL_SHA256  $TARBALL" | shasum -a 256 -c --status; then
    curl -fsSL "$VIRGL_URL" -o "$TARBALL"
    echo "$VIRGL_SHA256  $TARBALL" | shasum -a 256 -c --status || { echo "checksum mismatch for $TARBALL" >&2; exit 1; }
fi

SRC="$WORK/virglrenderer-${VIRGL_VERSION}"
rm -rf "$SRC"
tar -xzf "$TARBALL" -C "$WORK"
for p in "$PATCH_DIR"/*.patch; do
    patch -d "$SRC" -p1 --silent < "$p"
done

# meson caches the toolchain environment at the first setup, so the MoltenVK
# link path has to be present on this call.
export PKG_CONFIG_PATH="$MVK/lib/pkgconfig:$EPOXY/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
LDFLAGS="-L$MVK/lib" CFLAGS="-I$MVK/include" \
    meson setup "$SRC/build" "$SRC" -Dvenus=true -Drender-server=false \
        -Dbuildtype=release --prefix="$WORK/prefix" --libdir=lib >"$WORK/meson.log" 2>&1
meson compile -C "$SRC/build" >"$WORK/ninja.log" 2>&1

DYLIB="$SRC/build/src/libvirglrenderer.1.dylib"
cp "$DYLIB" "$OUT"
install_name_tool -id @loader_path/libvirglrenderer.1.dylib "$OUT"
otool -L "$OUT" | awk 'NR>1 {print $1}' | grep -E 'libMoltenVK|libepoxy' | while read -r dep; do
    install_name_tool -change "$dep" "@loader_path/$(basename "$dep")" "$OUT"
done
codesign --force --sign - "$OUT" 2>/dev/null
echo "Installed: $OUT"
otool -L "$OUT" | grep -E '@loader_path|MoltenVK|epoxy' | sed 's/^/  /'
