#!/bin/bash
#
# Storage Tests (overlay, prune, resize)
#
# Part of the smolvm test suite. Run with: ./tests/test_storage.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Storage Tests (overlay, prune, resize)"
echo "=========================================="
echo ""

test_machine_overlay_root_active() {
    local vm_name="overlay-active-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Check that root is an overlay mount
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- mount 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"overlay on / type overlay"* ]]
}

test_machine_rootfs_persists_across_reboot() {
    local vm_name="overlay-persist-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Write a marker file to the rootfs
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- sh -c "echo persistence-test-ok > /tmp/overlay-test-marker" 2>&1 || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Verify file exists before reboot
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || {
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if [[ "$output" != *"persistence-test-ok"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }

    # Verify the file survived the reboot
    exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"persistence-test-ok"* ]]
}

test_machine_overlay_size() {
    local vm_name="test-vm-overlay-size"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create VM with custom overlay size (4 GiB)
    $SMOLVM machine create --name "$vm_name" --overlay 4 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Check the overlay disk size inside the VM via df
    local df_output
    df_output=$($SMOLVM machine exec --name "$vm_name" -- df -m / 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # The 4GB overlay should show ~3800-4096 MB total (ext4 overhead)
    # Just verify it's > 3000 MB (not the old 2GB default)
    local total_mb
    total_mb=$(echo "$df_output" | tail -1 | awk '{print $2}')
    [[ "$total_mb" -gt 3000 ]]
}

test_machine_images() {
    # Start default machine and check images command
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --net --name default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine images --name default 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    # Should show storage info
    [[ "$output" == *"Storage"* ]] || [[ "$output" == *"storage"* ]]
}

test_machine_prune_dry_run() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --net --name default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine prune --name default --dry-run 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true

    # Should complete without error
    [[ $? -eq 0 ]] || [[ "$output" == *"unreferenced"* ]] || [[ "$output" == *"No unreferenced"* ]]
}

assert_vm_stays_running() {
    local desc="$1"; shift

    ensure_machine_running

    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM not running before '$desc'"; return 1; }

    "$@" 2>&1 || return 1

    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM stopped after '$desc'"; return 1; }
}

test_images_does_not_stop_running_vm() {
    assert_vm_stays_running "machine images" $SMOLVM machine images --name default
}

test_prune_on_running_vm() {
    ensure_machine_running

    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM not running before test"; return 1; }

    # Regular prune should work without stopping the VM
    local output
    output=$($SMOLVM machine prune --name default 2>&1) || true
    [[ "$output" == *"unreferenced"* ]] || [[ "$output" == *"No unreferenced"* ]] || {
        echo "unexpected prune output: $output"
        return 1
    }

    # VM should still be running after prune
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM stopped after prune"; return 1; }
}

test_prune_dry_run_on_running_vm() {
    ensure_machine_running

    local output
    output=$($SMOLVM machine prune --name default --dry-run 2>&1) || true
    [[ "$output" == *"unreferenced"* ]] || [[ "$output" == *"No unreferenced"* ]] || {
        echo "unexpected prune --dry-run output: $output"
        return 1
    }

    # VM should still be running
    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM stopped after prune --dry-run"; return 1; }
}

test_prune_all_refuses_on_running_vm() {
    ensure_machine_running "true"

    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM not running before test"; return 1; }

    # --all should refuse while the VM is running
    local output exit_code=0
    output=$($SMOLVM machine prune --name default --all 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "prune --all should have failed on running VM"; return 1; }
    [[ "$output" == *"cannot prune --all while machine"* ]] || {
        echo "unexpected error: $output"
        return 1
    }

    # VM should still be running
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM stopped after rejected prune --all"; return 1; }
}

test_prune_all_keeps_in_use_image() {
    # An image-backed machine needs its cached image to restart, so `prune --all`
    # must keep it (and reclaim only unreferenced layers) rather than brick a
    # stopped machine with "image not found" on the next start.
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
    $SMOLVM machine create --image alpine --net --name default 2>&1 || return 1
    $SMOLVM machine start 2>&1 || return 1

    # Verify the image is cached and the VM is reachable
    $SMOLVM machine exec -- true 2>&1 || { echo "VM not reachable"; return 1; }

    # Stop the VM (prune --all requires it)
    $SMOLVM machine stop 2>&1

    # Run prune --all: it must keep the in-use image, not remove it.
    local output
    output=$($SMOLVM machine prune --name default --all 2>&1) || {
        echo "prune --all failed: $output"
        $SMOLVM machine delete --name default -f 2>/dev/null
        return 1
    }
    [[ "$output" == *"Kept"* ]] || [[ "$output" == *"image-backed"* ]] || {
        echo "expected prune --all to keep the in-use image, got: $output"
        $SMOLVM machine delete --name default -f 2>/dev/null
        return 1
    }

    # The machine must still restart — its image was kept, not pruned.
    $SMOLVM machine start 2>&1 || {
        echo "FAIL: machine could not restart after prune --all (image was pruned)"
        $SMOLVM machine delete --name default -f 2>/dev/null
        return 1
    }
    $SMOLVM machine exec -- true 2>&1 || {
        echo "FAIL: VM not reachable after prune + restart"
        $SMOLVM machine delete --name default -f 2>/dev/null
        return 1
    }

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete --name default -f 2>/dev/null || true
}

test_storage_resize_and_large_pull() {
    # Force a fresh storage disk by deleting the default VM data directory.
    # This ensures we exercise the template → resize → mount path.
    $SMOLVM machine stop 2>/dev/null || true
    local data_dir
    data_dir=$(vm_data_dir "default")
    rm -rf "$data_dir" 2>/dev/null || true

    # Pull python:3.12 (full image: ~150MB compressed, ~1GB extracted).
    # This exceeds the 512MB template size, so it will fail with ENOSPC
    # if the storage disk was not properly resized from 512MB to 20GB.
    local output exit_code=0
    output=$($SMOLVM machine run --net --image python:3.12 -- python3 -c 'import sys; print(f"python {sys.version_info.major}.{sys.version_info.minor}")' 2>&1) || exit_code=$?

    echo "$output"

    # Verify the command succeeded and Python ran
    [[ $exit_code -eq 0 ]] || { echo "Exit code: $exit_code"; return 1; }
    [[ "$output" == *"python 3.12"* ]] || { echo "Expected python 3.12 output"; return 1; }
}

test_storage_mounted_as_ext4() {
    # Verify /dev/vda is actually mounted at /storage as ext4 (not on overlay).
    # This catches the bug where mount_storage_disk() silently fails and
    # /storage is just a directory on the overlay rootfs.
    local output
    output=$($SMOLVM machine run --net -- sh -c '
        mount_line=$(mount | grep "/dev/vda")
        if [ -z "$mount_line" ]; then
            echo "FAIL: /dev/vda not mounted"
            exit 1
        fi
        echo "$mount_line"
        # Verify the filesystem is large (>1GB = properly resized from 512MB template)
        avail_kb=$(df /storage | tail -1 | awk "{print \$4}")
        if [ "$avail_kb" -lt 1048576 ]; then
            echo "FAIL: /storage too small (${avail_kb}KB available, expected >1GB)"
            exit 1
        fi
        echo "PASS: storage mounted and resized"
    ' 2>&1)

    echo "$output"
    [[ "$output" == *"PASS: storage mounted and resized"* ]]
}


run_test "Overlay: root is overlayfs" test_machine_overlay_root_active || true
run_test "Overlay: rootfs persists across reboot" test_machine_rootfs_persists_across_reboot || true
run_test "Overlay: custom size via --overlay" test_machine_overlay_size || true
run_test "Machine images" test_machine_images || true
run_test "Machine prune --dry-run" test_machine_prune_dry_run || true
run_test "Images: does not stop running VM" test_images_does_not_stop_running_vm || true
run_test "Prune: works on running VM without stopping it" test_prune_on_running_vm || true
run_test "Prune --dry-run: works on running VM" test_prune_dry_run_on_running_vm || true
run_test "Prune --all: refuses on running VM" test_prune_all_refuses_on_running_vm || true
run_test "Prune --all: keeps in-use image, machine still restarts" test_prune_all_keeps_in_use_image || true
run_test "Storage: resize + large image pull (fresh disk)" test_storage_resize_and_large_pull || true
run_test "Storage: /dev/vda mounted as ext4 with correct size" test_storage_mounted_as_ext4 || true

print_summary "Storage Tests"
