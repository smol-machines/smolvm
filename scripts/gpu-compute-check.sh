#!/usr/bin/env bash
# Verify that a --gpu machine can actually RUN a GPU workload, not merely
# enumerate a device.
#
# 🔴 Enumeration is not function. `vulkaninfo` listed a Venus device for a long
# time while no workload could run, so this dispatches a compute shader and
# checks every value it wrote. It is what caught the capset regression that made
# --gpu silently fall back to software.
#
# Usage: scripts/gpu-compute-check.sh [machine-name]
#
# The machine must be started WITHOUT KRUN_GPU_BACKEND=2d: that selects
# rutabaga's CPU 2D component, which has no 3D contexts and therefore no Venus.
set -euo pipefail
MACHINE="${1:-omarchy}"
SMOLVM="${SMOLVM:-smolvm}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

C_SRC=$(base64 < "$HERE/tests/gpu/vk_compute_check.c" | tr -d '\n')
SHADER=$(base64 < "$HERE/tests/gpu/vk_compute_check.comp" | tr -d '\n')

# The bundled Venus driver is injected at /opt/smolvm-vulkan. LD_LIBRARY_PATH is
# unset deliberately: the bundle shadows the image's own libdrm/libexpat and
# breaks both OpenGL and Python inside the container.
"$SMOLVM" machine exec --name "$MACHINE" -- sh -c "
  set -e
  mkdir -p /opt/vk-compute-check && cd /opt/vk-compute-check
  echo $C_SRC | base64 -d > check.c
  echo $SHADER | base64 -d > shader.comp
  command -v glslangValidator >/dev/null || { echo 'need glslang in the guest'; exit 2; }
  glslangValidator -V shader.comp -o comp.spv >/dev/null
  cc -O2 -o check check.c -lvulkan
  cp comp.spv /tmp/comp.spv
  sudo -u \"\${SUDO_USER:-root}\" true 2>/dev/null || true
  env -u LD_LIBRARY_PATH VK_DRIVER_FILES=/opt/smolvm-vulkan/virtio_icd.json ./check
"
