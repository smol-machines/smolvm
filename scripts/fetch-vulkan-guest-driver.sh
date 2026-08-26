#!/usr/bin/env bash
# Fetch and stage the guest Vulkan (Venus) driver bundle for the agent rootfs.
#
# A `--gpu` VM exposes /dev/dri into every workload container, but the
# container can only use Vulkan if its image ships a Mesa with the virtio
# (Venus) ICD — which stock images don't (and on macOS hosts the driver
# additionally needs the mesa-krunkit blob-alignment patch). This bundle is
# what crates/smolvm-agent/src/vulkan.rs bind-mounts into --gpu containers so
# Vulkan works with no user setup, mirroring the CUDA shim staging.
#
# Every artifact is pinned by URL + sha256:
#   - libvulkan_virtio.so from the slp/mesa-krunkit COPR (the patched Mesa;
#     also correct on 4 KiB-page Linux hosts — same upstream code path).
#   - Its DT_NEEDED closure (libdrm, xcb/wayland client libs, zstd, expat,
#     zlib) and the Vulkan loader from the immutable AlmaLinux 9.6 vault, so
#     the driver dlopens on images that ship none of these. glibc >= 2.34
#     (el9) is required of the workload image; older images degrade to
#     no-Vulkan exactly as they do today.
#
# Usage: fetch-vulkan-guest-driver.sh <aarch64|x86_64> <output-dir>
# The bundle lands in <output-dir>/ as flat lib*.so* files plus
# virtio_icd.json (library_path pointing at the container mount path).
# Downloads are cached in .vulkan-rpm-cache/ next to the output dir.
set -euo pipefail

ARCH="${1:?arch (aarch64|x86_64)}"
OUT="${2:?output dir}"

COPR="https://download.copr.fedorainfracloud.org/results/slp/mesa-krunkit/epel-9-$ARCH/09212593-mesa"
VAULT="https://repo.almalinux.org/vault/9.6"

# name|url|sha256 — resolved 2026-08-20 from the COPR build 09212593 and the
# AlmaLinux 9.6 vault (immutable). Update all three fields together.
case "$ARCH" in
aarch64) PINS=(
  "mesa-vulkan-drivers-24.2.8-104.el9.aarch64.rpm|$COPR/mesa-vulkan-drivers-24.2.8-104.el9.aarch64.rpm|a38e8b384c431cef84b1443252a9fdc754238133a42e07e518191aeec76097c2"
  "vulkan-loader-1.4.304.0-1.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/vulkan-loader-1.4.304.0-1.el9.aarch64.rpm|a9c4da94e48fc85c6969d5cf03c3c5446a4f68bbe962f557086a3b0fb30b09f6"
  "libdrm-2.4.123-2.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/libdrm-2.4.123-2.el9.aarch64.rpm|7070f1cbe3a269b21544238b13127334bfeb39efd85989033ba3990c9c5b674c"
  "zlib-1.2.11-40.el9.aarch64.rpm|$VAULT/BaseOS/aarch64/os/Packages/zlib-1.2.11-40.el9.aarch64.rpm|e3acb023695f3f4626f8cbef5b89caba8760954873e30e1d4ea9f2d720b37295"
  "libzstd-1.5.5-1.el9.aarch64.rpm|$VAULT/BaseOS/aarch64/os/Packages/libzstd-1.5.5-1.el9.aarch64.rpm|6f5532912915999fdf4e3b2fe7709d72a7b3813f6dc9aabd0084c73352fedf43"
  "expat-2.5.0-5.el9_6.aarch64.rpm|$VAULT/BaseOS/aarch64/os/Packages/expat-2.5.0-5.el9_6.aarch64.rpm|e566fc63983241efe489a5eb5b40ea6cc7f4fb340c327b5564a5a980597ae95c"
  "libxcb-1.13.1-9.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/libxcb-1.13.1-9.el9.aarch64.rpm|d2b2e4a348c5582bb200db666a5b1d3899a173beaa519cef4fcfe1bd4cca26f9"
  "libX11-xcb-1.7.0-11.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/libX11-xcb-1.7.0-11.el9.aarch64.rpm|f9188fc7ca1012bbcb80d932214d839539a6d7deb39f45d19887b1757aec16e4"
  "libxshmfence-1.3-10.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/libxshmfence-1.3-10.el9.aarch64.rpm|90ee9fc68c9a44090cdc4b27e2caed640832cdc0b852caa8bb3e0479b5e198ca"
  "libwayland-client-1.21.0-1.el9.aarch64.rpm|$VAULT/AppStream/aarch64/os/Packages/libwayland-client-1.21.0-1.el9.aarch64.rpm|9cee7c9f55019668dbf6dd8e2031e23a6e16f773bf308ed126ba5e4acfccbd57"
) ;;
x86_64) PINS=(
  "mesa-vulkan-drivers-24.2.8-104.el9.x86_64.rpm|$COPR/mesa-vulkan-drivers-24.2.8-104.el9.x86_64.rpm|d447cd1562646d704bff677776c6222f6d4734d0d780983533ba5d90366e2309"
  "vulkan-loader-1.4.304.0-1.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/vulkan-loader-1.4.304.0-1.el9.x86_64.rpm|34b090c246b2443d7ffcc4bc103a8d647f7090712d3a4e6ddce08860fda0f30b"
  "libdrm-2.4.123-2.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/libdrm-2.4.123-2.el9.x86_64.rpm|a4abf6bf087c6992d385e5a8a3bec2d2821536d6c2fcfc8242b635076e423739"
  "zlib-1.2.11-40.el9.x86_64.rpm|$VAULT/BaseOS/x86_64/os/Packages/zlib-1.2.11-40.el9.x86_64.rpm|90d7d5d145c6d397645ffefdff40e3d2783e3bf3bfa7b6c1f089c2cad81a3191"
  "libzstd-1.5.5-1.el9.x86_64.rpm|$VAULT/BaseOS/x86_64/os/Packages/libzstd-1.5.5-1.el9.x86_64.rpm|33006cb9736d17f74c7a30cf9375438a9228023639239bf69c84b2530ad97462"
  "expat-2.5.0-5.el9_6.x86_64.rpm|$VAULT/BaseOS/x86_64/os/Packages/expat-2.5.0-5.el9_6.x86_64.rpm|5613b077e20fab964955224fc3b0caa9ecd8b97c1adb30ae85439c1639920567"
  "libxcb-1.13.1-9.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/libxcb-1.13.1-9.el9.x86_64.rpm|840ea71fb8beb52093e9f6d23dd0bc7de86f9d6da8c48888d766b0915cf1e1bc"
  "libX11-xcb-1.7.0-11.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/libX11-xcb-1.7.0-11.el9.x86_64.rpm|1f26334e50951a561defc9163cdbdaa7f8229fa7dc893b8198ff58e87b654ff8"
  "libxshmfence-1.3-10.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/libxshmfence-1.3-10.el9.x86_64.rpm|c13f4ee9d273bdac9977f1dd6ae9a31303a3ee0aa96996a17db997ff7162f74b"
  "libwayland-client-1.21.0-1.el9.x86_64.rpm|$VAULT/AppStream/x86_64/os/Packages/libwayland-client-1.21.0-1.el9.x86_64.rpm|8c08d9da5462a30a506a8d6714eddab540300edcec63017cd41920fb40ded06a"
) ;;
*) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# Cache outside the output tree (the output dir lives inside the rootfs).
CACHE="${VULKAN_RPM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/smolvm-vulkan-rpms}"
mkdir -p "$CACHE" "$OUT"

sha() {
    if command -v sha256sum &>/dev/null; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

extract_rpm() {
    # Portable rpm payload extraction: bsdtar reads rpm directly (macOS,
    # most CI images); rpm2cpio+cpio is the Linux fallback.
    local rpm="$1" dest="$2"
    if tar -xf "$rpm" -C "$dest" 2>/dev/null; then return 0; fi
    if command -v bsdtar &>/dev/null && bsdtar -xf "$rpm" -C "$dest"; then return 0; fi
    if command -v rpm2cpio &>/dev/null; then
        (cd "$dest" && rpm2cpio "$rpm" | cpio -idm --quiet); return 0
    fi
    echo "no rpm extractor available (need bsdtar or rpm2cpio)" >&2
    return 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for pin in "${PINS[@]}"; do
    name="${pin%%|*}"; rest="${pin#*|}"; url="${rest%%|*}"; want="${rest##*|}"
    f="$CACHE/$name"
    if [[ ! -f "$f" ]] || [[ "$(sha "$f")" != "$want" ]]; then
        echo "  fetching $name"
        curl -sfL "$url" -o "$f"
    fi
    got="$(sha "$f")"
    if [[ "$got" != "$want" ]]; then
        echo "sha256 mismatch for $name: got $got want $want" >&2
        exit 1
    fi
    extract_rpm "$f" "$WORK"
done

# Flatten the shared libraries (preserving soname symlinks) into the bundle.
# Only usr/lib64 matters; the rpms ship nothing else we need.
rm -f "$OUT"/lib*.so* "$OUT"/virtio_icd.json
cp -a "$WORK"/usr/lib64/lib*.so* "$OUT"/
# Drop the other mesa vulkan drivers and layers — Venus only, smaller bundle,
# and no chance of the loader probing an ICD we didn't intend to ship.
find "$OUT" -name 'libvulkan_*.so' ! -name 'libvulkan_virtio.so' -delete
find "$OUT" -name 'libVkLayer_*.so' -delete
find "$OUT" -name 'libpowervr_rogue.so' -delete

# The ICD manifest is the rpm's own (correct api_version) with library_path
# rewritten to the CONTAINER path the agent bind-mounts the bundle to
# (crates/smolvm-agent/src/vulkan.rs CONTAINER_DIR).
sed 's|"library_path" *: *"[^"]*"|"library_path": "/opt/smolvm-vulkan/libvulkan_virtio.so"|' \
    "$WORK/usr/share/vulkan/icd.d/virtio_icd.$ARCH.json" > "$OUT/virtio_icd.json"
grep -q "/opt/smolvm-vulkan/libvulkan_virtio.so" "$OUT/virtio_icd.json"

echo "Vulkan guest driver bundle staged in $OUT ($(du -sh "$OUT" | cut -f1))"
