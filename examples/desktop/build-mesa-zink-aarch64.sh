#!/bin/bash
# Build the Mesa stack the accelerated desktop installs on macOS hosts, inside
# an aarch64 Arch Linux machine (the one omarchy-aarch64.sh sets up will do).
#
# Why a custom Mesa at all: the macOS virglrenderer is Venus (Vulkan) only, so
# the guest gets GL through Zink. Stock Mesa fails twice on that path: its
# Venus driver dies on the host's 16 KiB pages (the two krunkit commits fix
# the allocation alignment), and Zink from 26.2 on requires
# VK_KHR_maintenance5, which the renderer's protocol predates. 26.0 is the
# newest Mesa whose Zink does not need it, and a small loader patch lets Zink
# claim a virtio-gpu that has no virgl.
#
# Usage (as root in the guest, with network):
#   bash build-mesa-zink-aarch64.sh [/out]
# Produces /out/mesa-<ver>-zink-venus16k-aarch64.tar.zst, a /usr overlay:
#   tar --zstd -xf mesa-*.tar.zst -C / && ldconfig
set -euo pipefail
MESA_TAG="${MESA_TAG:-mesa-26.0.8}"
OUT="${1:-/out}"
HERE="$(cd "$(dirname "$0")" && pwd)"
unset LD_LIBRARY_PATH VK_DRIVER_FILES VK_ICD_FILENAMES

pacman -S --noconfirm --needed base-devel git meson ninja python bison flex \
    libdrm wayland wayland-protocols libglvnd llvm zstd >/dev/null
WORK="${WORK:-/root/mesa-build}"
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"; cd "$WORK"
git clone -q --depth 1 --branch "$MESA_TAG" https://gitlab.freedesktop.org/mesa/mesa.git src
cd src
# The krunkit Venus fix: 16 KiB alignment for every allocation the host maps.
git remote add slp https://gitlab.freedesktop.org/slp/mesa.git
GIT_TERMINAL_PROMPT=0 git fetch -q --depth 400 slp mesa-libkrun-vulkan
pick=""
for h in $(git log --format=%h FETCH_HEAD -40); do
    git show -s --format=%s "$h" | grep -q "force 16k alignment" && { pick="$h"; break; }
done
[[ -n "$pick" ]] || { echo "16k alignment commit not found on slp/mesa-libkrun-vulkan" >&2; exit 1; }
git cherry-pick -n "$pick"
patch -p1 --silent < "$HERE/patches/mesa-virtio-gpu-zink-fallback.patch"

meson setup build -Dvulkan-drivers=virtio -Dgallium-drivers=zink,virgl,llvmpipe \
    -Dplatforms=wayland -Dglx=disabled -Degl=enabled -Dgbm=enabled \
    -Dvulkan-layers= -Dvideo-codecs= -Dgallium-va=disabled -Dllvm=enabled \
    -Dbuildtype=release --prefix=/usr --libdir=lib >"$WORK/meson.log" 2>&1
ninja -C build >"$WORK/ninja.log" 2>&1
rm -rf "$WORK/stage"; DESTDIR="$WORK/stage" ninja -C build install >/dev/null
ver="${MESA_TAG#mesa-}"
tar --zstd -C "$WORK/stage" -cf "$OUT/mesa-$ver-zink-venus16k-aarch64.tar.zst" usr
sha256sum "$OUT/mesa-$ver-zink-venus16k-aarch64.tar.zst"
