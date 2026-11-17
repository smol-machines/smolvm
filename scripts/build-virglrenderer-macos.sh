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
# Requirements: brew install vulkan-headers meson ninja pkg-config
# Uses the checked-in MoltenVK library (fetch Git LFS objects first).
#   SKIP_DEPS=1   assume the brew packages are present
#   OUT=<path>    where to put the dylib (default: lib/libvirglrenderer.1.dylib)
# Also rebuilds and installs libepoxy beside it for the same deployment target.
set -euo pipefail

VIRGL_VERSION="0.10.4e-krunkit"
VIRGL_URL="https://gitlab.freedesktop.org/slp/virglrenderer/-/archive/${VIRGL_VERSION}/virglrenderer-${VIRGL_VERSION}.tar.gz"
VIRGL_SHA256="09d000623fbdb966cb604eb48c962a0815e8142383e6066d6494809335b76dbb"
EPOXY_VERSION="1.5.10"
EPOXY_URL="https://download.gnome.org/sources/libepoxy/1.5/libepoxy-${EPOXY_VERSION}.tar.xz"
EPOXY_SHA256="072cda4b59dd098bba8c2363a6247299db1fa89411dc221c8b81b8ee8192e623"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/lib/libvirglrenderer.1.dylib}"
WORK="$ROOT/target/virglrenderer"
PATCH_DIR="$ROOT/patches/virglrenderer"

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }
if [[ "${SKIP_DEPS:-0}" != "1" ]]; then
    for pkg in vulkan-headers meson ninja pkg-config; do
        brew list --versions "$pkg" >/dev/null 2>&1 || brew install "$pkg"
    done
fi
MVK="$ROOT/lib"
VULKAN_HEADERS="$(brew --prefix vulkan-headers)"
EPOXY="$WORK/epoxy-prefix"
python3 "$ROOT/scripts/check-macos-deployment-target.py" "$MVK/libMoltenVK.dylib"

# Do not inherit the build machine's macOS version or a newer Homebrew bottle.
export MACOSX_DEPLOYMENT_TARGET=11.0
export CFLAGS="${CFLAGS:-} -mmacosx-version-min=11.0"
export CXXFLAGS="${CXXFLAGS:-} -mmacosx-version-min=11.0"
export LDFLAGS="${LDFLAGS:-} -mmacosx-version-min=11.0"

mkdir -p "$WORK" "$(dirname "$OUT")"
EPOXY_TARBALL="$WORK/libepoxy-${EPOXY_VERSION}.tar.xz"
if [[ ! -f "$EPOXY_TARBALL" ]] || ! echo "$EPOXY_SHA256  $EPOXY_TARBALL" | shasum -a 256 -c --status; then
    curl -fsSL "$EPOXY_URL" -o "$EPOXY_TARBALL"
    echo "$EPOXY_SHA256  $EPOXY_TARBALL" | shasum -a 256 -c --status || { echo "checksum mismatch for $EPOXY_TARBALL" >&2; exit 1; }
fi
EPOXY_SRC="$WORK/libepoxy-${EPOXY_VERSION}"
rm -rf "$EPOXY_SRC"
tar -xf "$EPOXY_TARBALL" -C "$WORK"
meson setup "$EPOXY_SRC/build" "$EPOXY_SRC" -Dbuildtype=release \
    -Dtests=false -Dglx=no -Degl=no -Dx11=false \
    --prefix="$EPOXY" --libdir=lib >"$WORK/epoxy-meson.log" 2>&1
meson compile -C "$EPOXY_SRC/build" >"$WORK/epoxy-ninja.log" 2>&1
meson install -C "$EPOXY_SRC/build" --no-rebuild >"$WORK/epoxy-install.log" 2>&1
EPOXY_OUT="$(dirname "$OUT")/libepoxy.0.dylib"
cp "$EPOXY/lib/libepoxy.0.dylib" "$EPOXY_OUT"
install_name_tool -id @loader_path/libepoxy.0.dylib "$EPOXY_OUT"
codesign --force --sign - "$EPOXY_OUT" 2>/dev/null

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
export PKG_CONFIG_PATH="$EPOXY/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
LDFLAGS="$LDFLAGS -L$MVK" CFLAGS="$CFLAGS -I$VULKAN_HEADERS/include" \
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
python3 "$ROOT/scripts/check-macos-deployment-target.py" "$OUT" "$EPOXY_OUT"
echo "Installed: $OUT"
otool -L "$OUT" | grep -E '@loader_path|MoltenVK|epoxy' | sed 's/^/  /'
