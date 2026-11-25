#!/usr/bin/env bash
# Build the guest Vulkan (Venus) driver that fetch-vulkan-guest-driver.sh
# stages into the agent rootfs.
#
# Run it as root inside an AlmaLinux 9 container of the target architecture
# (.github/workflows/build-vulkan-guest-driver.yml does). EL9 is the baseline
# on purpose: the driver then needs nothing newer than glibc 2.34, and links
# against the same library versions fetch-vulkan-guest-driver.sh bundles
# beside it, so it loads in old workload images as well as current ones.
#
# The source is the pinned Mesa release tarball plus the patches in
# scripts/vulkan-guest-driver/. 0001 and 0002 are the krunkit Venus patches:
# a macOS host maps guest allocations on 16 KiB pages, so every allocation
# the host maps must be 16 KiB aligned. On a 4 KiB-page Linux host the larger
# alignment is harmless. 0003 is Mesa commit 935c4ec39a30, which the pinned
# release predates: without it a thread that used Vulkan and outlives the
# program's last Vulkan instance crashes when it exits.
#
# Usage: build-vulkan-guest-driver.sh <output-dir>
# Writes <output-dir>/libvulkan_virtio.so, virtio_icd.json and
# driver.provenance.
set -euo pipefail

OUT="${1:?output dir}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MESA_VERSION="25.2.8"
MESA_SHA256="097842f3e49d996868b38688db87b006f7d4541e93ce86d2f341d8b3e7be7c93"
MESA_URL="https://archive.mesa3d.org/mesa-$MESA_VERSION.tar.xz"

if ! grep -q 'PLATFORM_ID="platform:el9"' /etc/os-release 2>/dev/null; then
    echo "build-vulkan-guest-driver.sh must run on an EL9 system (AlmaLinux 9)" >&2
    exit 1
fi

dnf install -y -q dnf-plugins-core >/dev/null
dnf config-manager --set-enabled crb >/dev/null
dnf install -y -q gcc gcc-c++ python3-pip ninja-build bison flex xz patch \
    pkgconf-pkg-config libdrm-devel libxcb-devel libX11-devel \
    libxshmfence-devel wayland-devel libzstd-devel expat-devel zlib-devel \
    >/dev/null
# EL9 packages a meson and a Mako older than this Mesa accepts.
PIP_ROOT_USER_ACTION=ignore python3 -m pip install -q 'meson==1.7.0' 'Mako==1.3.5' 'PyYAML==6.0.2' 'packaging==24.1'

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
curl -sfL "$MESA_URL" -o mesa.tar.xz
echo "$MESA_SHA256  mesa.tar.xz" | sha256sum -c - >/dev/null
tar -xf mesa.tar.xz
cd "mesa-$MESA_VERSION"
for p in "$HERE"/vulkan-guest-driver/*.patch; do
    patch -p1 --silent < "$p"
done

# Venus only, with the X11 and Wayland window-system code the bundled closure
# covers. wayland-protocols is data consumed at build time; EL9's is too old,
# so meson takes its pinned subproject.
meson setup build --buildtype=release -Db_ndebug=true \
    -Dvulkan-drivers=virtio -Dgallium-drivers= -Dvulkan-layers= \
    -Dplatforms=x11,wayland -Dxlib-lease=disabled \
    -Dopengl=false -Dglx=disabled -Degl=disabled -Dgbm=disabled \
    -Dgles1=disabled -Dgles2=disabled -Dllvm=disabled -Dvideo-codecs= \
    -Dzstd=enabled -Dexpat=enabled >"$WORK/meson.log" 2>&1 || {
        tail -40 "$WORK/meson.log" >&2
        exit 1
    }
ICD_MANIFEST="src/virtio/vulkan/virtio_icd.$(uname -m).json"
ninja -C build src/virtio/vulkan/libvulkan_virtio.so "$ICD_MANIFEST" >"$WORK/ninja.log" 2>&1 || {
    tail -40 "$WORK/ninja.log" >&2
    exit 1
}

mkdir -p "$OUT"
strip --strip-unneeded -o "$OUT/libvulkan_virtio.so" build/src/virtio/vulkan/libvulkan_virtio.so
# library_path is rewritten to the container mount path when the bundle is staged.
sed 's|"library_path" *: *"[^"]*"|"library_path": "libvulkan_virtio.so"|' \
    "build/$ICD_MANIFEST" > "$OUT/virtio_icd.json"
grep -q '"api_version"' "$OUT/virtio_icd.json"

{
    echo "# Written by scripts/build-vulkan-guest-driver.sh — do not edit by hand."
    echo "mesa=$MESA_VERSION"
    echo "mesa_sha256=$MESA_SHA256"
    echo "patches=$(cat "$HERE"/vulkan-guest-driver/*.patch | sha256sum | cut -d' ' -f1)"
    echo "arch=$(uname -m)"
} > "$OUT/driver.provenance"

echo "Built $(ls -la "$OUT/libvulkan_virtio.so" | awk '{print $5}') byte driver:"
readelf -d "$OUT/libvulkan_virtio.so" | grep NEEDED
objdump -T "$OUT/libvulkan_virtio.so" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
