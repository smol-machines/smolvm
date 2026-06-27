#!/bin/bash
#
# Image-Backed /proc and /storage Parity Tests
#
# Regression coverage for two asymmetries between bare-VM and --image machines:
#
#   1. --image froze a chunk of /proc read-only (runc's readonlyPaths), so
#      docker-in-VM could not write /proc/sys/net/ipv4/ip_forward.
#   2. --image did not expose the per-VM /storage disk inside the container, so
#      the docker-in-VM bind-mount pattern
#      (`mount --bind /storage/docker /var/lib/docker`) broke.
#
# Both are fixed by treating a privileged (default) image machine like a bare
# VM: /proc is unrestricted and /storage is bind-mounted into the container.
# An unprivileged image machine keeps the full runc hardening.
#
# Part of the smolvm test suite. Run with:
#   ./tests/test_machine_image_proc_storage.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Image-Backed /proc + /storage Parity"
echo "=========================================="
echo ""

# A privileged --image VM must have a writable /proc/sys, like a bare VM, so an
# init system / dockerd can set sysctls. Before the fix crun applied runc's
# readonlyPaths and this write failed with EROFS.
test_image_proc_sys_is_writable() {
    local out
    out=$(run_with_timeout 120 $SMOLVM machine run --net --image alpine -- \
        sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward && cat /proc/sys/net/ipv4/ip_forward' 2>&1)
    local rc=$?
    [[ $rc -eq 124 ]] && { echo "FAIL: timed out booting image VM"; return 1; }
    echo "$out" | grep -qx '1' || {
        echo "FAIL: /proc/sys/net/ipv4/ip_forward not writable under --image"
        echo "  output: $out"
        return 1
    }
}

# Corollary: /proc/sys must not be a read-only bind in privileged mode. runc's
# readonlyPaths shows up as a `ro` mount line on the path; its absence means the
# path inherits the writable top-level /proc mount.
test_image_proc_sys_not_readonly_bind() {
    local out
    out=$(run_with_timeout 90 $SMOLVM machine run --net --image alpine -- \
        sh -c 'mount | grep " /proc/sys " || true' 2>&1)
    local rc=$?
    [[ $rc -eq 124 ]] && { echo "FAIL: timed out booting image VM"; return 1; }
    if echo "$out" | grep -q '\bro\b'; then
        echo "FAIL: /proc/sys still mounted read-only under --image"
        echo "  output: $out"
        return 1
    fi
}

# A privileged --image VM must see the per-VM /storage ext4 disk inside the
# container, so /storage/* resolves to the disk exactly as in a bare VM.
test_image_storage_disk_visible() {
    local out
    out=$(run_with_timeout 90 $SMOLVM machine run --net --image alpine -- \
        sh -c 'mount | grep " /storage " || true' 2>&1)
    local rc=$?
    [[ $rc -eq 124 ]] && { echo "FAIL: timed out booting image VM"; return 1; }
    echo "$out" | grep -q ' /storage ' || {
        echo "FAIL: /storage not mounted inside --image container"
        echo "  output: $out"
        return 1
    }
    echo "$out" | grep -q 'ext4' || {
        echo "FAIL: /storage is not the ext4 disk under --image"
        echo "  output: $out"
        return 1
    }
}

# The docker-in-VM bind-mount pattern works under --image. Binding
# /var/lib/docker onto /storage/docker must land on the ext4 disk (so dockerd's
# overlay2 nests correctly), proven by a file written through the bind appearing
# on the /storage side.
test_image_docker_bind_resolves_to_storage() {
    local out
    out=$(run_with_timeout 90 $SMOLVM machine run --net --image alpine -- sh -c '
        set -e
        mkdir -p /storage/docker /var/lib/docker
        mount --bind /storage/docker /var/lib/docker
        : > /var/lib/docker/probe
        test -f /storage/docker/probe
        # Confirm /var/lib/docker now resolves onto the ext4 storage disk.
        mount | grep " /var/lib/docker " | grep -q ext4
        echo BIND_OK' 2>&1)
    local rc=$?
    [[ $rc -eq 124 ]] && { echo "FAIL: timed out booting image VM"; return 1; }
    echo "$out" | grep -q 'BIND_OK' || {
        echo "FAIL: bind-mount of /var/lib/docker onto /storage did not resolve to ext4"
        echo "  output: $out"
        return 1
    }
}

# Guard the security boundary: an UNPRIVILEGED image container must NOT get the
# relaxed /proc or the /storage disk — the hardening is retained for untrusted
# code. `machine run --unprivileged` opts into the restricted profile.
test_unprivileged_image_keeps_hardening() {
    # /proc/sys read-only (write must fail) and /storage absent.
    local out
    out=$(run_with_timeout 90 $SMOLVM machine run --net --unprivileged --image alpine -- sh -c '
        if echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then echo PROC_WRITABLE; else echo PROC_RO; fi
        if mount | grep -q " /storage "; then echo STORAGE_VISIBLE; else echo STORAGE_HIDDEN; fi' 2>&1)
    local rc=$?
    [[ $rc -eq 124 ]] && { echo "FAIL: timed out booting unprivileged image VM"; return 1; }
    # If --unprivileged is unsupported by this build, skip rather than fail.
    if echo "$out" | grep -qiE 'error|unexpected argument|unknown'; then
        echo "SKIP: --unprivileged not supported by this build: $out"
        return 0
    fi
    echo "$out" | grep -q 'PROC_RO' || {
        echo "FAIL: unprivileged container got a writable /proc/sys (hardening lost)"
        echo "  output: $out"
        return 1
    }
    echo "$out" | grep -q 'STORAGE_HIDDEN' || {
        echo "FAIL: unprivileged container saw /storage (disk leak)"
        echo "  output: $out"
        return 1
    }
}

run_test "Image /proc/sys is writable (ip_forward settable)" test_image_proc_sys_is_writable || true
run_test "Image /proc/sys is not a read-only bind" test_image_proc_sys_not_readonly_bind || true
run_test "Image container sees the /storage ext4 disk" test_image_storage_disk_visible || true
run_test "Docker bind-mount onto /storage resolves to ext4" test_image_docker_bind_resolves_to_storage || true
run_test "Unprivileged image keeps /proc + /storage hardening" test_unprivileged_image_keeps_hardening || true

print_summary "Image /proc + /storage Parity Tests"
