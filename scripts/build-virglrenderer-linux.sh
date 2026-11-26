#!/usr/bin/env bash
# Build the Linux host renderer bundled in lib/linux-<arch>/: libvirglrenderer,
# its virgl_render_server and libepoxy.
#
# A --gpu machine on Linux runs guest Vulkan in virgl_render_server and guest
# OpenGL in libvirglrenderer. Bundling them means a host needs only its GPU
# driver, every host runs the same renderer version (distros still package
# releases too old for NVIDIA's driver), and the fixes in
# patches/virglrenderer-linux/ reach users without waiting for a distro.
#
# Run it as root inside an AlmaLinux 8 container of the target architecture
# (.github/workflows/build-virglrenderer-linux.yml does). AlmaLinux 8 is the
# baseline on purpose: it has glibc 2.28, the oldest the Linux dist supports
# (LINUX_GLIBC in release.yml), and it is what manylinux_2_28 builds on.
#
# What stays with the host: libEGL, libgbm, libdrm and the Vulkan loader and
# driver. They belong to the GPU driver installed there. The Vulkan loader is
# opened at runtime (vulkan-dload), so the bundle loads on a host without one.
#
# Usage: build-virglrenderer-linux.sh <output-dir>
# Writes <output-dir>/libvirglrenderer.so{,.1,.1.x.y}, libepoxy.so{,.0,.0.0.0},
# virgl_render_server and virglrenderer.provenance.
set -euo pipefail

OUT="${1:?output dir}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_DIR="$HERE/../patches/virglrenderer-linux"

VIRGL_VERSION="1.3.0"
VIRGL_URL="https://gitlab.freedesktop.org/virgl/virglrenderer/-/archive/${VIRGL_VERSION}/virglrenderer-${VIRGL_VERSION}.tar.gz"
VIRGL_SHA256="065bc56e89e6f631f96101cd62eba0748e48eb888b434edc86e89d05395e76f3"
EPOXY_VERSION="1.5.10"
EPOXY_URL="https://download.gnome.org/sources/libepoxy/1.5/libepoxy-${EPOXY_VERSION}.tar.xz"
EPOXY_SHA256="072cda4b59dd098bba8c2363a6247299db1fa89411dc221c8b81b8ee8192e623"
GLIBC_FLOOR="2.28"

if ! grep -q '^ID="almalinux"' /etc/os-release 2>/dev/null \
    || ! grep -q '^VERSION_ID="8' /etc/os-release; then
    echo "build-virglrenderer-linux.sh must run on AlmaLinux 8 (glibc $GLIBC_FLOOR)" >&2
    exit 1
fi

dnf install -y -q --enablerepo=powertools gcc glibc-devel python39 python39-pip pkgconf-pkg-config \
    curl ca-certificates xz patch binutils libdrm-devel mesa-libgbm-devel \
    libglvnd-devel >/dev/null
# AlmaLinux 8 packages no meson new enough for libepoxy, and ninja and
# patchelf only in other repositories; virglrenderer's generators need PyYAML.
python3.9 -m pip install -q 'meson==1.7.0' 'PyYAML==6.0.2' 'ninja==1.11.1.4' \
    'patchelf==0.17.2.4'
export PATH="/usr/local/bin:$PATH"
# virglrenderer's meson finds `python3`, which must be the one with PyYAML.
alternatives --set python3 /usr/bin/python3.9

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PREFIX="$WORK/prefix"
cd "$WORK"

fetch() {
    curl -sfL "$1" -o "$2"
    echo "$3  $2" | sha256sum -c - >/dev/null
}
run() {
    local log="$WORK/$1.log"
    shift
    "$@" >"$log" 2>&1 || { tail -40 "$log" >&2; exit 1; }
}

# libepoxy: EGL only. virglrenderer is built for the EGL platform, so the X11
# and GLX halves would only add libraries a headless host does not have.
fetch "$EPOXY_URL" epoxy.tar.xz "$EPOXY_SHA256"
tar -xf epoxy.tar.xz
run epoxy-setup meson setup epoxy-build "libepoxy-$EPOXY_VERSION" --buildtype=release \
    --prefix="$PREFIX" --libdir=lib -Dtests=false -Dglx=no -Dx11=false -Degl=yes
run epoxy-build ninja -C epoxy-build install

fetch "$VIRGL_URL" virgl.tar.gz "$VIRGL_SHA256"
tar -xf virgl.tar.gz
for p in "$PATCH_DIR"/*.patch; do
    patch -d "virglrenderer-$VIRGL_VERSION" -p1 --silent < "$p"
done
# vulkan-preload stays off: NVIDIA's driver does not survive being loaded
# before the render server forks.
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" run virgl-setup meson setup virgl-build \
    "virglrenderer-$VIRGL_VERSION" --buildtype=release -Db_ndebug=true \
    --prefix="$PREFIX" --libdir=lib -Dplatforms=egl -Dvenus=true \
    -Dvulkan-dload=true -Dvulkan-preload=false -Dvideo=false -Dtests=false
run virgl-build ninja -C virgl-build install

mkdir -p "$OUT"
rm -f "$OUT"/libvirglrenderer.so* "$OUT"/libepoxy.so* "$OUT/virgl_render_server"
copy_lib() {
    local name="$1" real
    real="$(basename "$(readlink -f "$PREFIX/lib/$name.so")")"
    strip --strip-unneeded -o "$OUT/$real" "$PREFIX/lib/$real"
    # Each library finds the rest of the bundle next to itself.
    patchelf --set-rpath '$ORIGIN' "$OUT/$real"
    local soname
    soname="$(patchelf --print-soname "$OUT/$real")"
    ln -sf "$real" "$OUT/$soname"
    ln -sf "$soname" "$OUT/$name.so"
}
copy_lib libepoxy
copy_lib libvirglrenderer
strip --strip-unneeded -o "$OUT/virgl_render_server" "$PREFIX/libexec/virgl_render_server"
patchelf --set-rpath '$ORIGIN' "$OUT/virgl_render_server"
chmod 755 "$OUT/virgl_render_server"

# Nothing may need a glibc newer than the floor, or a library that is neither
# in the bundle nor part of the host's GPU driver stack.
for f in "$OUT"/libepoxy.so.0 "$OUT"/libvirglrenderer.so.1 "$OUT/virgl_render_server"; do
    newest="$(objdump -T "$f" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)"
    if [[ "$(printf '%s\n%s\n' "GLIBC_$GLIBC_FLOOR" "$newest" | sort -V | tail -1)" != "GLIBC_$GLIBC_FLOOR" ]]; then
        echo "$f needs $newest, above the $GLIBC_FLOOR floor" >&2
        exit 1
    fi
    for needed in $(patchelf --print-needed "$f"); do
        case "$needed" in
        libc.so.6 | libm.so.6 | libdl.so.2 | libpthread.so.0 | librt.so.1 | ld-linux-*) ;;
        libEGL.so.1 | libgbm.so.1 | libdrm.so.2) ;;
        libepoxy.so.0 | libvirglrenderer.so.1) [[ -e "$OUT/$needed" ]] ;;
        *)
            echo "$f needs $needed, which is neither bundled nor a host GPU library" >&2
            exit 1
            ;;
        esac
    done
done

{
    echo "# Written by scripts/build-virglrenderer-linux.sh — do not edit by hand."
    echo "virglrenderer=$VIRGL_VERSION"
    echo "virglrenderer_sha256=$VIRGL_SHA256"
    echo "patches=$(cat "$PATCH_DIR"/*.patch | sha256sum | cut -d' ' -f1)"
    echo "libepoxy=$EPOXY_VERSION"
    echo "libepoxy_sha256=$EPOXY_SHA256"
    echo "arch=$(uname -m)"
} > "$OUT/virglrenderer.provenance"

ls -la "$OUT"
for f in "$OUT"/libepoxy.so.0 "$OUT"/libvirglrenderer.so.1 "$OUT/virgl_render_server"; do
    echo "$(basename "$f"): $(patchelf --print-needed "$f" | tr '\n' ' ')"
done
