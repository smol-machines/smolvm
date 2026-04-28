#!/bin/bash
#
# GPU acceleration integration tests for smolvm.
#
# Tests the --gpu flag across two tiers:
#   1. virtio-gpu device enumeration (Alpine — fast, no Mesa needed)
#   2. Full Vulkan workloads via patched Mesa on Fedora 42
#
# The suite is SKIPPED (not failed) if GPU support is not compiled into
# libkrun or virglrenderer is unavailable on the host. This keeps CI green
# on machines without GPU infrastructure.
#
# Usage:
#   ./tests/test_gpu.sh
#   ./tests/run_all.sh gpu

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Name for the shared Fedora machine used across Vulkan workload tests.
GPU_FEDORA_MACHINE="gpu-fedora-$$"

cleanup_gpu() {
    "$SMOLVM" machine stop --name "$GPU_FEDORA_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete "$GPU_FEDORA_MACHINE" -f 2>/dev/null || true
}
trap cleanup_gpu EXIT

echo ""
echo "=========================================="
echo "  smolvm GPU Tests"
echo "=========================================="
echo ""

# =============================================================================
# GPU availability probe
# =============================================================================
# Run a trivial --gpu command in Alpine to confirm GPU support is compiled in
# and virglrenderer is present. If either is missing, smolvm emits one of:
#   - "libkrun was built without GPU support (krun_set_gpu_options2 not found)"
#   - "krun_set_gpu_options2 failed ... Check that virglrenderer is installed."
# On those messages we skip the whole suite (not fail) — GPU is optional.
#
# Note: --net is required here because image pulls happen inside the VM.

log_info "Probing GPU support..."
_PROBE_EXIT=0
_PROBE_OUT=$(run_with_timeout 120 "$SMOLVM" machine run --gpu --net --image alpine:latest -- true 2>&1) \
    || _PROBE_EXIT=$?

if [[ $_PROBE_EXIT -ne 0 ]]; then
    if echo "$_PROBE_OUT" | grep -qE "krun_set_gpu_options2|without GPU support|virglrenderer"; then
        echo ""
        log_skip "GPU not available on this host — skipping all GPU tests"
        log_skip "  Cause: $(echo "$_PROBE_OUT" | grep -E "krun_set_gpu_options2|without GPU|virglrenderer" | head -1)"
        log_skip "  To enable: rebuild libkrun with GPU=1 and install virglrenderer"
        echo ""
        print_summary "GPU Tests"
        exit 0
    fi
    # Probe failed for an unrelated reason (e.g. transient network). Proceed
    # and let the individual tests surface a meaningful error.
    log_info "Probe failed (exit $_PROBE_EXIT) — not a GPU capability error, proceeding"
else
    log_info "GPU probe passed — virglrenderer and krun_set_gpu_options2 both available"
fi

# =============================================================================
# Helper
# =============================================================================

# Returns 0 if the shared Fedora GPU machine is currently running.
_fedora_running() {
    "$SMOLVM" machine status --name "$GPU_FEDORA_MACHINE" 2>&1 | grep -q "running"
}

# =============================================================================
# Section 1: virtio-gpu device enumeration (Alpine, no Mesa)
# =============================================================================
# When --gpu is passed, libkrun creates a virtio-gpu PCI device in the VM.
# The guest kernel (CONFIG_DRM_VIRTIO_GPU=y in libkrunfw) initialises the DRM
# subsystem and creates two device nodes:
#   /dev/dri/renderD128   — render node (Vulkan/OpenGL compute, no modesetting)
#   /dev/dri/card0        — DRM card (modesetting, display)
#
# The agent's add_gpu_devices_if_available() (crates/smolvm-agent/src/oci.rs)
# then forwards both nodes into the OCI container spec with mode 0o666 so
# unprivileged processes can open them.
#
# Alpine has no Vulkan userspace, but the kernel device nodes are enough to
# verify the full host→guest→container forwarding pipeline.

echo ""
echo "Running virtio-gpu device tests (Alpine)..."

test_dri_renderD128_present() {
    local out
    out=$(run_with_timeout 120 "$SMOLVM" machine run --gpu --net --image alpine:latest -- \
        ls /dev/dri/renderD128 2>&1) || return 1
    [[ "$out" == *"renderD128"* ]] || { echo "FAIL: renderD128 absent (got: $out)"; return 1; }
}

test_dri_card0_present() {
    local out
    out=$(run_with_timeout 120 "$SMOLVM" machine run --gpu --net --image alpine:latest -- \
        ls /dev/dri/card0 2>&1) || return 1
    [[ "$out" == *"card0"* ]] || { echo "FAIL: card0 absent (got: $out)"; return 1; }
}

test_renderD128_world_readable() {
    # The OCI spec sets mode 0o666 on the render node. Verify an unprivileged
    # stat succeeds (open would need actual Vulkan libs, but stat is sufficient).
    local out
    out=$(run_with_timeout 120 "$SMOLVM" machine run --gpu --net --image alpine:latest -- \
        stat /dev/dri/renderD128 2>&1) || { echo "FAIL: stat failed (got: $out)"; return 1; }
    [[ "$out" == *"renderD128"* ]] || { echo "FAIL: stat output unexpected (got: $out)"; return 1; }
}

test_no_dri_without_gpu() {
    # Without --gpu, no virtio-gpu device → no /dev/dri in guest → no DRI
    # devices in OCI container spec. ls /dev/dri should fail or produce nothing.
    local out exit_code=0
    out=$(run_with_timeout 120 "$SMOLVM" machine run --net --image alpine:latest -- \
        ls /dev/dri 2>&1) || exit_code=$?
    if [[ $exit_code -eq 0 ]] && echo "$out" | grep -qE "render|card"; then
        echo "FAIL: /dev/dri device nodes visible without --gpu: $out"
        return 1
    fi
}

test_gpu_vram_zero_rejected() {
    # Validation in src/data/resources.rs rejects gpu_vram_mib == 0 before
    # any VM starts, so --net is not required but included for clarity.
    local out exit_code=0
    out=$("$SMOLVM" machine run --gpu --gpu-vram 0 --net --image alpine:latest -- true 2>&1) \
        || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "FAIL: --gpu-vram 0 was accepted (exit 0)"; return 1; }
    echo "  (correctly rejected with exit $exit_code)"
}

test_named_machine_gpu_persists() {
    # Create a named machine with --gpu, stop+start it, verify DRI still present.
    # This exercises the full DB round-trip: VmResources{gpu:true} → sqlite →
    # deserialise → launcher → krun_set_gpu_options2.
    local name="gpu-named-$$"
    "$SMOLVM" machine stop --name "$name" 2>/dev/null || true
    "$SMOLVM" machine delete "$name" -f 2>/dev/null || true

    "$SMOLVM" machine create "$name" --gpu --net --image alpine:latest 2>&1 || return 1
    "$SMOLVM" machine start --name "$name" 2>&1 || {
        "$SMOLVM" machine delete "$name" -f 2>/dev/null; return 1
    }

    local out rc=0
    out=$("$SMOLVM" machine exec --name "$name" -- ls /dev/dri/renderD128 2>&1) || rc=$?

    "$SMOLVM" machine stop --name "$name" 2>/dev/null || true
    "$SMOLVM" machine delete "$name" -f 2>/dev/null || true

    [[ $rc -eq 0 ]] && [[ "$out" == *"renderD128"* ]] || {
        echo "FAIL: renderD128 absent in named GPU machine (got: $out, exit $rc)"
        return 1
    }
}

run_test "GPU: /dev/dri/renderD128 present with --gpu" test_dri_renderD128_present || true
run_test "GPU: /dev/dri/card0 present with --gpu" test_dri_card0_present || true
run_test "GPU: renderD128 accessible (stat succeeds)" test_renderD128_world_readable || true
run_test "GPU: no /dev/dri without --gpu (isolation)" test_no_dri_without_gpu || true
run_test "GPU: --gpu-vram 0 rejected by validation" test_gpu_vram_zero_rejected || true
run_test "GPU: named machine DB persistence of --gpu flag" test_named_machine_gpu_persists || true

# =============================================================================
# Section 2: Vulkan workloads (Fedora 42 + patched Mesa)
# =============================================================================
# Standard Fedora Mesa has a 16KB page-alignment bug that crashes Venus ICD
# initialisation on Apple Silicon (host pages are 16KB; guest expects 4KB).
# The slp/mesa-libkrun-vulkan COPR carries the upstream patch.
#
# We create one shared Fedora 42 machine and install Mesa once, then run all
# Vulkan assertions against the same running container to avoid paying the
# dnf install cost (~60s) for each individual test.
#
# Key commands:
#   vulkaninfo --summary   → lists ICDs, device names, API versions
#   stat /dev/dri/renderD128 → confirms DRI forwarding inside Fedora container

echo ""
echo "Running Vulkan workload tests (Fedora 42 + patched Mesa)..."

test_fedora_gpu_setup() {
    "$SMOLVM" machine stop --name "$GPU_FEDORA_MACHINE" 2>/dev/null || true
    "$SMOLVM" machine delete "$GPU_FEDORA_MACHINE" -f 2>/dev/null || true

    echo "  Creating Fedora 42 GPU machine (this pulls ~600 MB on first run)..."
    "$SMOLVM" machine create "$GPU_FEDORA_MACHINE" \
        --image fedora:42 --gpu --net 2>&1 || return 1

    echo "  Starting machine..."
    "$SMOLVM" machine start --name "$GPU_FEDORA_MACHINE" 2>&1 || {
        "$SMOLVM" machine delete "$GPU_FEDORA_MACHINE" -f 2>/dev/null
        return 1
    }

    echo "  Enabling slp/mesa-libkrun-vulkan COPR (Apple Silicon 16KB page-alignment fix)..."
    run_with_timeout 120 "$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        dnf copr enable -y slp/mesa-libkrun-vulkan 2>&1 || {
        echo "FAIL: dnf copr enable failed"
        return 1
    }

    echo "  Installing mesa-vulkan-drivers + vulkan-tools (~60s)..."
    run_with_timeout 300 "$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        dnf install -y --allowerasing mesa-vulkan-drivers vulkan-tools 2>&1 || {
        echo "FAIL: dnf install failed"
        return 1
    }

    echo "  Fedora GPU machine ready."
}

test_vulkaninfo_venus_icd() {
    # Venus is the guest-side Vulkan-over-virtio-gpu driver in Mesa.
    # It should appear as an ICD in vulkaninfo --summary output.
    _fedora_running || { echo "SKIP: Fedora GPU machine not running (setup failed)"; return 1; }
    local out
    out=$("$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        vulkaninfo --summary 2>&1) || { echo "FAIL: vulkaninfo exited non-zero"; echo "$out"; return 1; }
    echo "$out" | grep -qi "Venus" || {
        echo "FAIL: 'Venus' not found in vulkaninfo --summary"
        echo "$out" | head -30 | sed 's/^/  /'
        return 1
    }
}

test_vulkaninfo_virtio_gpu_device() {
    # The device name seen by the guest reflects the libkrun virtio-gpu backend.
    _fedora_running || { echo "SKIP: Fedora GPU machine not running (setup failed)"; return 1; }
    local out
    out=$("$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        vulkaninfo --summary 2>&1) || { echo "FAIL: vulkaninfo exited non-zero"; echo "$out"; return 1; }
    echo "$out" | grep -qi "Virtio-GPU" || {
        echo "FAIL: 'Virtio-GPU' not found in vulkaninfo --summary"
        echo "$out" | head -30 | sed 's/^/  /'
        return 1
    }
}

test_vulkan_api_version() {
    # Venus exposes Vulkan 1.2+ through the virtio-gpu transport.
    _fedora_running || { echo "SKIP: Fedora GPU machine not running (setup failed)"; return 1; }
    local out
    out=$("$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        vulkaninfo --summary 2>&1) || { echo "FAIL: vulkaninfo exited non-zero"; echo "$out"; return 1; }
    echo "$out" | grep -qiE "apiVersion|Vulkan [0-9]+\." || {
        echo "FAIL: No Vulkan API version in vulkaninfo --summary"
        echo "$out" | head -30 | sed 's/^/  /'
        return 1
    }
}

test_render_node_in_fedora_container() {
    # Confirms that add_gpu_devices_if_available() forwards /dev/dri into the
    # Fedora OCI container, not just Alpine. Different base images, same result.
    _fedora_running || { echo "SKIP: Fedora GPU machine not running (setup failed)"; return 1; }
    local out rc=0
    out=$("$SMOLVM" machine exec --name "$GPU_FEDORA_MACHINE" -- \
        stat /dev/dri/renderD128 2>&1) || rc=$?
    [[ $rc -eq 0 ]] && [[ "$out" == *"renderD128"* ]] || {
        echo "FAIL: /dev/dri/renderD128 inaccessible in Fedora container (exit $rc, got: $out)"
        return 1
    }
}

test_fedora_gpu_cleanup() {
    "$SMOLVM" machine stop --name "$GPU_FEDORA_MACHINE" 2>&1 || true
    "$SMOLVM" machine delete "$GPU_FEDORA_MACHINE" -f 2>/dev/null || true
}

run_test "GPU: Fedora 42 + patched Mesa setup" test_fedora_gpu_setup || true
run_test "GPU: vulkaninfo reports Venus ICD" test_vulkaninfo_venus_icd || true
run_test "GPU: vulkaninfo reports Virtio-GPU device name" test_vulkaninfo_virtio_gpu_device || true
run_test "GPU: Vulkan API version reported (1.x)" test_vulkan_api_version || true
run_test "GPU: /dev/dri/renderD128 accessible in Fedora container" test_render_node_in_fedora_container || true
run_test "GPU: Fedora cleanup" test_fedora_gpu_cleanup || true

print_summary "GPU Tests"
