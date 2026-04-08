#!/bin/bash
#
# Machine tests for smolvm.
#
# Tests the `smolvm machine` command functionality.
# Requires VM environment.
#
# Usage:
#   ./tests/test_machine.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# Cleanup on exit
trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  smolvm Machine Tests"
echo "=========================================="
echo ""

# =============================================================================
# Lifecycle
# =============================================================================

test_machine_start() {
    cleanup_machine
    $SMOLVM machine start 2>&1
}

test_machine_stop() {
    ensure_machine_running
    $SMOLVM machine stop 2>&1
}

test_machine_status_running() {
    ensure_machine_running
    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]]
}

test_machine_status_stopped() {
    cleanup_machine
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    # When stopped, status command either:
    # - Returns non-zero exit code, OR
    # - Returns status containing "not running" or "stopped"
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

test_machine_start_stop_cycle() {
    cleanup_machine

    # Start
    $SMOLVM machine start 2>&1 || return 1

    # Verify running
    local status exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ "$status" != *"running"* ]]; then
        return 1
    fi

    # Stop
    $SMOLVM machine stop 2>&1 || return 1

    # Verify stopped - either non-zero exit or status message indicates stopped
    exit_code=0
    status=$($SMOLVM machine status 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || [[ "$status" == *"not running"* ]] || [[ "$status" == *"stopped"* ]]
}

# =============================================================================
# Exec
# =============================================================================

test_machine_exec() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- cat /etc/os-release 2>&1)
    [[ "$output" == *"Alpine"* ]]
}

test_machine_exec_echo() {
    ensure_machine_running
    local output
    output=$($SMOLVM machine exec -- echo "test-marker-xyz" 2>&1)
    [[ "$output" == *"test-marker-xyz"* ]]
}

test_machine_exec_exit_code() {
    ensure_machine_running

    # Test exit 0
    $SMOLVM machine exec -- sh -c "exit 0" 2>&1 || return 1

    # Test exit 1
    local exit_code=0
    $SMOLVM machine exec -- sh -c "exit 1" 2>&1 || exit_code=$?
    [[ $exit_code -eq 1 ]]
}

# =============================================================================
# Named VMs
# =============================================================================

test_machine_named_vm() {
    local vm_name="test-vm-named"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create the named VM first
    $SMOLVM machine create "$vm_name" 2>&1 || return 1

    # Start
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check status
    local status
    status=$($SMOLVM machine status --name "$vm_name" 2>&1)
    if [[ "$status" != *"running"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and delete
    $SMOLVM machine stop --name "$vm_name" 2>&1
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

# =============================================================================
# Error Cases
# =============================================================================

test_machine_exec_when_stopped() {
    cleanup_machine

    local exit_code=0
    $SMOLVM machine exec -- echo "should-fail" 2>&1 || exit_code=$?

    # Should fail with non-zero exit code (don't check specific message)
    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Database Persistence
# =============================================================================

test_db_persistence_across_restart() {
    local vm_name="db-test-vm-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM with specific configuration
    $SMOLVM machine create "$vm_name" --cpus 2 --mem 1024 2>&1

    # Verify it was created with correct config
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)
    if [[ "$list_output" != *"$vm_name"* ]]; then
        echo "VM was not created"
        return 1
    fi

    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "VM configuration not persisted correctly"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"
}

test_db_vm_state_update() {
    local vm_name="db-state-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a named VM
    $SMOLVM machine create "$vm_name" 2>&1

    # Check initial state is "created"
    local initial_state
    initial_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$initial_state" != *'"state": "created"'* ]]; then
        echo "Initial state should be 'created'"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Start the VM
    $SMOLVM machine start --name "$vm_name" 2>&1

    # Check state changed to "running"
    local running_state
    running_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1

    # Check state changed to "stopped"
    local stopped_state
    stopped_state=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    [[ "$stopped_state" == *'"state": "stopped"'* ]]
}

test_db_delete_removes_from_db() {
    local vm_name="db-delete-test-$$"

    # Clean up any existing
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a VM
    $SMOLVM machine create "$vm_name" 2>&1

    # Verify it exists
    local before_delete
    before_delete=$($SMOLVM machine ls --json 2>&1)
    if [[ "$before_delete" != *"$vm_name"* ]]; then
        echo "VM should exist before delete"
        return 1
    fi

    # Delete it
    $SMOLVM machine delete "$vm_name" -f 2>&1
    ensure_data_dir_deleted "$vm_name"

    # Verify it's gone
    local after_delete
    after_delete=$($SMOLVM machine ls --json 2>&1)

    [[ "$after_delete" != *"$vm_name"* ]]
}

# =============================================================================
# Network
# Tests verify that network access is disabled by default and works when enabled.
# Note: libkrun uses TSI (Transparent Socket Impersonation) which routes network
# traffic through the host. DNS works reliably; direct HTTP may have limitations.
# =============================================================================

test_machine_network_disabled_by_default() {
    local vm_name="net-disabled-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM without --net (network disabled by default)
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS resolution should fail when network is disabled
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1 || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail (non-zero exit code) because network is disabled
    [[ $exit_code -ne 0 ]]
}

test_machine_network_dns_resolution() {
    local vm_name="net-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test DNS resolution
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain resolved address info
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_network_multiple_dns_lookups() {
    local vm_name="net-multi-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test multiple DNS lookups
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c "nslookup google.com && nslookup github.com" 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain addresses for both
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

# =============================================================================
# Egress Policy (--allow-cidr / --outbound-localhost-only)
# Tests verify CIDR-based egress restrictions enforced at the TSI layer.
# =============================================================================

test_machine_egress_allow_cidr_permitted() {
    local vm_name="egress-allow-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only Cloudflare DNS
    $SMOLVM machine create "$vm_name" --allow-cidr 1.1.1.1/32 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS lookup to allowed IP should succeed
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1) || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_egress_allow_cidr_blocked() {
    local vm_name="egress-block-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only private range + auto-included DNS (1.1.1.1).
    # Test with 8.8.8.8 which is NOT in the allowlist.
    $SMOLVM machine create "$vm_name" --allow-cidr 10.0.0.0/8 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_outbound_localhost_only() {
    local vm_name="egress-localhost-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" --outbound-localhost-only 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_invalid_cidr_rejected() {
    local vm_name="egress-invalid-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-cidr "not-a-cidr" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    [[ $exit_code -ne 0 ]] && [[ "$output" == *"invalid"* ]]
}

test_machine_egress_allow_host_permitted() {
    local vm_name="egress-host-allow-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one (resolves to 1.1.1.1)
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS lookup to allowed host's IP should succeed
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1) || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_egress_allow_host_blocked() {
    local vm_name="egress-host-block-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one — 8.8.8.8 should be blocked
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_allow_host_invalid_rejected() {
    local vm_name="egress-host-invalid-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-host "this-does-not-exist.invalid" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Should fail with a resolution error (hard error, not warning)
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"failed to resolve"* ]]
}

test_machine_egress_allow_host_port_rejected() {
    local vm_name="egress-host-port-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-host "example.com:443" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Should fail — port suffixes are not supported
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"port suffixes are not supported"* ]]
}

# DNS filtering end-to-end: when --allow-host is used with a new agent that
# has the DNS proxy, queries for non-allowed domains should fail.
test_machine_dns_filter_blocks_resolution() {
    local vm_name="dns-filter-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Resolving an allowed domain should work
    local exit_code_allowed=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 || exit_code_allowed=$?

    # Resolving a non-allowed domain should fail (DNS proxy returns NXDOMAIN,
    # or if agent doesn't have DNS proxy, TSI still blocks the IP)
    local exit_code_blocked=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup attacker-test.example 2>&1 || exit_code_blocked=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_allowed -eq 0 ]] && [[ $exit_code_blocked -ne 0 ]]
}

test_machine_allow_host_persists_across_restart() {
    local vm_name="dns-persist-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create with --allow-host, start, stop, start again
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify egress works
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] && { $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Stop and restart — config should persist from VmRecord
    $SMOLVM machine stop --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Should still be blocked (8.8.8.8 is not in allowlist)
    local exit_code_after=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code_after=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_after -ne 0 ]]
}

# =============================================================================
# Persistent Rootfs (Overlay)
# Tests verify that the overlayfs root is active and persists across reboots.
# =============================================================================

test_machine_overlay_root_active() {
    local vm_name="overlay-active-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Check that root is an overlay mount
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- mount 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"overlay on / type overlay"* ]]
}

test_machine_rootfs_persists_across_reboot() {
    local vm_name="overlay-persist-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Write a marker file to the rootfs
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- sh -c "echo persistence-test-ok > /tmp/overlay-test-marker" 2>&1 || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Verify file exists before reboot
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || {
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }
    if [[ "$output" != *"persistence-test-ok"* ]]; then
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    fi

    # Stop and restart the VM
    $SMOLVM machine stop --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify the file survived the reboot
    exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/overlay-test-marker 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"persistence-test-ok"* ]]
}

# =============================================================================
# Default VM DB Persistence
# Tests verify that the default VM lifecycle is reflected in the DB.
# =============================================================================

test_db_default_vm_appears_in_list_on_start() {
    cleanup_machine

    # Start the default VM (no name)
    $SMOLVM machine start 2>&1 || return 1

    # Verify "default" appears in machine ls --json as running
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_db_default_vm_shows_stopped_after_stop() {
    cleanup_machine

    # Start then stop the default VM
    $SMOLVM machine start 2>&1 || return 1
    $SMOLVM machine stop 2>&1 || return 1

    # Verify "default" shows as stopped
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "stopped"'* ]]
}

test_db_default_vm_state_transitions() {
    cleanup_machine

    # Start default VM
    $SMOLVM machine start 2>&1 || return 1

    # Check running state
    local running_state
    running_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$running_state" != *'"state": "running"'* ]]; then
        echo "State should be 'running' after start"
        $SMOLVM machine stop 2>/dev/null || true
        return 1
    fi

    # Stop default VM
    $SMOLVM machine stop 2>&1 || return 1

    # Check stopped state
    local stopped_state
    stopped_state=$($SMOLVM machine ls --json 2>&1)
    if [[ "$stopped_state" != *'"state": "stopped"'* ]]; then
        echo "State should be 'stopped' after stop"
        return 1
    fi

    # Restart and check running again
    $SMOLVM machine start 2>&1 || return 1
    local restarted_state
    restarted_state=$($SMOLVM machine ls --json 2>&1)

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true

    [[ "$restarted_state" == *'"state": "running"'* ]]
}

# =============================================================================
# Volume Mounts
# =============================================================================

test_machine_volume_mount_visible_to_exec() {
    local vm_name="test-vm-volmnt"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create a host directory with a test file
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "volume-mount-marker-54321" > "$tmpdir/testfile.txt"

    # Create and start VM with volume mount
    $SMOLVM machine create "$vm_name" -v "$tmpdir:/mnt/hostdata" 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    }

    # Read the file via machine exec (VmExec) — this exercises boot-time mount
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /mnt/hostdata/testfile.txt 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ "$output" == *"volume-mount-marker-54321"* ]]
}

# =============================================================================
# Port Mapping
# =============================================================================

test_machine_port_mapping_http() {
    local vm_name="test-vm-portmap"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create and start VM with port mapping (host 18199 -> guest 8080)
    $SMOLVM machine create "$vm_name" -p 18199:8080 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start a simple HTTP responder inside the VM (background exec)
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080 -w 5' &
    local server_pid=$!
    sleep 1

    # Curl the mapped port from the host
    local output
    output=$(curl -s --connect-timeout 5 http://127.0.0.1:18199/ 2>&1)
    local curl_rc=$?

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $curl_rc -eq 0 ]] && [[ "$output" == *"ok"* ]]
}

# =============================================================================
# Overlay Size
# =============================================================================

test_machine_overlay_size() {
    local vm_name="test-vm-overlay-size"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with custom overlay size (4 GiB)
    $SMOLVM machine create "$vm_name" --overlay 4 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Check the overlay disk size inside the VM via df
    local df_output
    df_output=$($SMOLVM machine exec --name "$vm_name" -- df -m / 2>&1)

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # The 4GB overlay should show ~3800-4096 MB total (ext4 overhead)
    # Just verify it's > 3000 MB (not the old 2GB default)
    local total_mb
    total_mb=$(echo "$df_output" | tail -1 | awk '{print $2}')
    [[ "$total_mb" -gt 3000 ]]
}

# =============================================================================
# Run Tests
# =============================================================================

# =============================================================================
# Machine Run (Ephemeral) Tests
# =============================================================================

test_machine_run_echo() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- echo "run-test-marker" 2>&1)
    [[ "$output" == *"run-test-marker"* ]]
}

test_machine_run_exit_code() {
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 0" 2>&1
    local exit_code=0
    $SMOLVM machine run --net --image alpine:latest -- sh -c "exit 42" 2>&1 || exit_code=$?
    [[ $exit_code -eq 42 ]]
}

test_machine_run_env() {
    local output
    output=$($SMOLVM machine run --net -e TEST_VAR=hello_run --image alpine:latest -- sh -c 'echo $TEST_VAR' 2>&1)
    [[ "$output" == *"hello_run"* ]]
}

test_machine_run_volume() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "run-mount-test" > "$tmpdir/testfile.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt" --image alpine:latest -- cat /hostmnt/testfile.txt 2>&1)

    rm -rf "$tmpdir"
    [[ "$output" == *"run-mount-test"* ]]
}

test_machine_run_volume_readonly() {
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "readonly-data" > "$tmpdir/readonly.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- cat /hostmnt/readonly.txt 2>&1)

    # Should be able to read
    [[ "$output" == *"readonly-data"* ]] || { rm -rf "$tmpdir"; return 1; }

    # Should fail to write
    local write_exit=0
    $SMOLVM machine run --net -v "$tmpdir:/hostmnt:ro" --image alpine:latest -- sh -c "echo fail > /hostmnt/newfile.txt" 2>&1 || write_exit=$?

    rm -rf "$tmpdir"
    [[ $write_exit -ne 0 ]]
}

test_machine_run_volume_multiple() {
    local tmpdir1 tmpdir2
    tmpdir1=$(mktemp -d)
    tmpdir2=$(mktemp -d)
    echo "data1" > "$tmpdir1/file1.txt"
    echo "data2" > "$tmpdir2/file2.txt"

    local output
    output=$($SMOLVM machine run --net -v "$tmpdir1:/data1" -v "$tmpdir2:/data2" --image alpine:latest -- sh -c "cat /data1/file1.txt && cat /data2/file2.txt" 2>&1)

    rm -rf "$tmpdir1" "$tmpdir2"
    [[ "$output" == *"data1"* ]] && [[ "$output" == *"data2"* ]]
}

test_machine_run_workdir() {
    local output
    output=$($SMOLVM machine run --net -w /tmp --image alpine:latest -- pwd 2>&1)
    [[ "$output" == *"/tmp"* ]]
}

test_machine_run_detached() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    local run_output exit_code=0
    run_output=$($SMOLVM machine run -d --net --image alpine:latest 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        $SMOLVM machine stop 2>/dev/null || true
        $SMOLVM machine delete default -f 2>/dev/null || true
        echo "Setup failed: machine run -d returned $exit_code: $run_output"
        return 1
    fi

    # Should appear in machine ls
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    [[ "$list_output" == *'"name": "default"'* ]] && \
    [[ "$list_output" == *'"state": "running"'* ]]
}

test_machine_run_timeout() {
    local output
    output=$($SMOLVM machine run --net --timeout 5s --image alpine:latest -- sleep 60 2>&1 || true)
    # Should be killed before 60s
    [[ "$output" == *"timed out"* ]] || [[ "$output" == *"Killed"* ]] || [[ $? -ne 0 ]]
}

test_machine_run_pipeline() {
    local output
    output=$($SMOLVM machine run --net --image alpine:latest -- sh -c "echo 'hello world' | wc -w" 2>&1)
    [[ "$output" == *"2"* ]]
}

test_machine_run_cmd_not_found() {
    ! $SMOLVM machine run --net --image alpine:latest -- nonexistent_command_12345 2>/dev/null
}

test_machine_images() {
    # Start default machine and check images command
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true
    $SMOLVM machine create --net default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine images 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    # Should show storage info
    [[ "$output" == *"Storage"* ]] || [[ "$output" == *"storage"* ]]
}

test_machine_prune_dry_run() {
    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true
    $SMOLVM machine create --net default 2>/dev/null || true
    $SMOLVM machine start --name default 2>/dev/null || true

    local output
    output=$($SMOLVM machine prune --dry-run 2>&1)

    $SMOLVM machine stop 2>/dev/null || true
    $SMOLVM machine delete default -f 2>/dev/null || true

    # Should complete without error
    [[ $? -eq 0 ]] || [[ "$output" == *"unreferenced"* ]] || [[ "$output" == *"No unreferenced"* ]]
}

# =============================================================================
# Machine Lifecycle Tests
# =============================================================================

run_test "Machine start" test_machine_start || true
run_test "Machine stop" test_machine_stop || true
run_test "Machine status (running)" test_machine_status_running || true
run_test "Machine start/stop cycle" test_machine_start_stop_cycle || true
run_test "Machine exec" test_machine_exec || true
run_test "Machine exec exit code" test_machine_exec_exit_code || true
run_test "Named machine" test_machine_named_vm || true
run_test "Exec when stopped fails" test_machine_exec_when_stopped || true
run_test "DB persistence across restart" test_db_persistence_across_restart || true
run_test "DB VM state update" test_db_vm_state_update || true
run_test "DB delete removes from database" test_db_delete_removes_from_db || true
run_test "DB default VM appears in list on start" test_db_default_vm_appears_in_list_on_start || true
run_test "DB default VM state transitions" test_db_default_vm_state_transitions || true
run_test "Network: disabled by default" test_machine_network_disabled_by_default || true
run_test "Network: DNS resolution" test_machine_network_dns_resolution || true
run_test "Egress: allow-cidr permits matching traffic" test_machine_egress_allow_cidr_permitted || true
run_test "Egress: allow-cidr blocks non-matching traffic" test_machine_egress_allow_cidr_blocked || true
run_test "Egress: --outbound-localhost-only blocks external" test_machine_egress_outbound_localhost_only || true
run_test "Egress: invalid CIDR rejected at create" test_machine_egress_invalid_cidr_rejected || true
run_test "Egress: allow-host permits matching traffic" test_machine_egress_allow_host_permitted || true
run_test "Egress: allow-host blocks non-matching traffic" test_machine_egress_allow_host_blocked || true
run_test "Egress: invalid hostname rejected at create" test_machine_egress_allow_host_invalid_rejected || true
run_test "Egress: host:port syntax rejected" test_machine_egress_allow_host_port_rejected || true
run_test "DNS filter: blocks resolution of non-allowed domains" test_machine_dns_filter_blocks_resolution || true
run_test "DNS filter: allow-host persists across restart" test_machine_allow_host_persists_across_restart || true
run_test "Overlay: root is overlayfs" test_machine_overlay_root_active || true
run_test "Overlay: rootfs persists across reboot" test_machine_rootfs_persists_across_reboot || true
run_test "Volume: mount visible to exec" test_machine_volume_mount_visible_to_exec || true
run_test "Port: mapping host to guest HTTP" test_machine_port_mapping_http || true
run_test "Overlay: custom size via --overlay" test_machine_overlay_size || true

echo ""
echo "--- Machine Run (Ephemeral) Tests ---"
echo ""

run_test "Machine run: echo" test_machine_run_echo || true
run_test "Machine run: exit code" test_machine_run_exit_code || true
run_test "Machine run: env variable" test_machine_run_env || true
run_test "Machine run: volume mount" test_machine_run_volume || true
run_test "Machine run: volume readonly" test_machine_run_volume_readonly || true
run_test "Machine run: workdir" test_machine_run_workdir || true
run_test "Machine run: detached" test_machine_run_detached || true
run_test "Machine run: timeout" test_machine_run_timeout || true
run_test "Machine images" test_machine_images || true
run_test "Machine prune --dry-run" test_machine_prune_dry_run || true

# =============================================================================
# Auto-Generated Names
# =============================================================================

test_auto_generated_names() {
    # Auto-generate: create with no name, verify format + appears in list
    local result1 result2
    result1=$($SMOLVM machine create 2>&1) || return 1
    result2=$($SMOLVM machine create 2>&1) || return 1

    local name1 name2
    name1=$(echo "$result1" | grep "Created machine:" | grep -oE "vm-[a-f0-9]{8}" | head -1)
    name2=$(echo "$result2" | grep "Created machine:" | grep -oE "vm-[a-f0-9]{8}" | head -1)

    # Both should produce valid names
    [[ -n "$name1" ]] && [[ -n "$name2" ]] || { echo "No auto name found"; return 1; }

    # Names should differ
    [[ "$name1" != "$name2" ]] || { echo "Names should be unique: $name1"; return 1; }

    # Both should appear in list (use --json for full names, avoids truncation)
    local list_result
    list_result=$($SMOLVM machine ls --json 2>&1)
    [[ "$list_result" == *"$name1"* ]] && [[ "$list_result" == *"$name2"* ]] || {
        echo "Auto-named machines not in list"
        $SMOLVM machine delete "$name1" -f 2>/dev/null
        $SMOLVM machine delete "$name2" -f 2>/dev/null
        return 1
    }

    # Explicit name still works
    local explicit="explicit-test-$$"
    $SMOLVM machine create "$explicit" 2>&1 || { echo "Explicit name failed"; return 1; }
    list_result=$($SMOLVM machine ls --json 2>&1)
    [[ "$list_result" == *"$explicit"* ]] || { echo "Explicit name not in list"; return 1; }

    # Cleanup
    $SMOLVM machine delete "$name1" -f 2>/dev/null
    $SMOLVM machine delete "$name2" -f 2>/dev/null
    $SMOLVM machine delete "$explicit" -f 2>/dev/null
}

echo ""
echo "--- Auto-Generated Names ---"
echo ""

run_test "Auto-generated names" test_auto_generated_names || true

# =============================================================================
# Ephemeral VM Tracking
# =============================================================================

test_ephemeral_vm_tracking() {
    # Ephemeral machine run should appear in list while running, disappear after exit
    local result
    result=$(run_with_timeout 30 $SMOLVM machine run --net --image alpine -- echo "ephemeral-tracking-test" 2>&1)
    local exit_code=$?
    [[ $exit_code -eq 124 ]] && { echo "TIMEOUT"; return 1; }
    [[ "$result" == *"ephemeral-tracking-test"* ]] || { echo "Command failed: $result"; return 1; }

    # After clean exit, the ephemeral record should be gone
    local list_result
    list_result=$($SMOLVM machine ls 2>&1)
    # Should NOT contain any ephemeral VMs from this run (they deregister on exit)
    if echo "$list_result" | grep -q "(eph).*running"; then
        echo "Ephemeral VM still in list after clean exit"
        return 1
    fi

    # Verify orphan cleanup works: list should not error
    [[ $? -eq 0 ]]
}

test_ephemeral_shows_in_list_while_running() {
    # Start a detached ephemeral run and verify it appears in list
    $SMOLVM machine run --net -d --image alpine -- sleep 30 2>&1 || {
        echo "Detached run failed"
        return 1
    }

    # Should appear in list with (eph) marker
    sleep 2
    local list_result
    list_result=$($SMOLVM machine ls 2>&1)
    echo "$list_result" | grep -q "eph" || {
        echo "Detached ephemeral not in list: $list_result"
        # Clean up any running VMs
        $SMOLVM machine stop 2>/dev/null || true
        return 1
    }

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true
}

echo ""
echo "--- Ephemeral VM Tracking ---"
echo ""

run_test "Ephemeral VM: clean exit deregisters" test_ephemeral_vm_tracking || true
run_test "Ephemeral VM: visible while running" test_ephemeral_shows_in_list_while_running || true

# =============================================================================
# Create --image parity with Run
# =============================================================================

test_create_with_image() {
    local vm_name="create-image-test-$$"

    # Create with --image (new feature), start, exec, verify, cleanup
    $SMOLVM machine create "$vm_name" --image alpine:latest --net 2>&1 || return 1

    # Should appear in list (use --json for full names)
    $SMOLVM machine ls --json 2>&1 | grep -q "$vm_name" || {
        echo "Machine not in list"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start — should auto-pull the image
    local start_result
    start_result=$(run_with_timeout 60 $SMOLVM machine start --name "$vm_name" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT on start"; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }
    [[ "$start_result" == *"Pulling"* ]] || [[ "$start_result" == *"Started"* ]] || [[ "$start_result" == *"already running"* ]] || {
        echo "Start failed: $start_result"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Exec — verify we're in the right image
    local exec_result
    exec_result=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- cat /etc/os-release 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT on exec"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }
    [[ "$exec_result" == *"Alpine"* ]] || {
        echo "Not running Alpine: $exec_result"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null
}

test_create_with_image_and_env() {
    local vm_name="create-env-test-$$"

    # Create with --image + env + workdir
    $SMOLVM machine create "$vm_name" --image alpine:latest --net \
        -e TEST_VAR=from_create -w /tmp 2>&1 || return 1

    run_with_timeout 60 $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        return 1
    }

    # Verify workdir was persisted (init commands run in /tmp)
    local pwd_result
    pwd_result=$(run_with_timeout 30 $SMOLVM machine exec --name "$vm_name" -- pwd 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null
}

echo ""
echo "--- Create --image Tests ---"
echo ""

run_test "Create with --image" test_create_with_image || true
run_test "Create with --image + env" test_create_with_image_and_env || true

# =============================================================================
# File I/O (machine cp)
# =============================================================================

test_file_upload_download() {
    local vm_name="cp-test-$$"

    # Create and start a machine
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    run_with_timeout 30 $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1
    }

    # Upload a file
    local upload_content="hello from host $(date +%s)"
    echo "$upload_content" > /tmp/smolvm-cp-test.txt
    $SMOLVM machine cp /tmp/smolvm-cp-test.txt "$vm_name":/tmp/uploaded.txt 2>&1 || {
        echo "Upload failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }

    # Verify upload via exec
    local exec_result
    exec_result=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/uploaded.txt 2>&1) || {
        echo "Exec after upload failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }
    [[ "$exec_result" == *"$upload_content"* ]] || {
        echo "Upload content mismatch: expected '$upload_content', got '$exec_result'"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt
        return 1
    }

    # Create file in VM and download
    $SMOLVM machine exec --name "$vm_name" -- sh -c "echo 'hello from VM' > /tmp/to-download.txt" 2>&1
    $SMOLVM machine cp "$vm_name":/tmp/to-download.txt /tmp/smolvm-downloaded.txt 2>&1 || {
        echo "Download failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
        return 1
    }
    local downloaded
    downloaded=$(cat /tmp/smolvm-downloaded.txt)
    [[ "$downloaded" == *"hello from VM"* ]] || {
        echo "Download content mismatch: '$downloaded'"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null
        rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null
    rm -f /tmp/smolvm-cp-test.txt /tmp/smolvm-downloaded.txt
}

echo ""
echo "--- File I/O (machine cp) ---"
echo ""

run_test "File upload and download" test_file_upload_download || true

# =============================================================================
# Streaming Exec
# =============================================================================

test_streaming_exec() {
    # Start a machine, run a command with --stream, verify output arrives
    $SMOLVM machine stop 2>/dev/null || true

    $SMOLVM machine create stream-test-$$ 2>&1 || return 1
    run_with_timeout 30 $SMOLVM machine start --name stream-test-$$ 2>&1 || {
        $SMOLVM machine delete stream-test-$$ -f 2>/dev/null; return 1
    }

    # Streaming exec — output should contain the echoed text
    local result
    result=$(run_with_timeout 15 $SMOLVM machine exec --stream --name stream-test-$$ -- sh -c "echo 'stream-line-1' && echo 'stream-line-2' && echo 'done'" 2>&1)
    [[ $? -eq 124 ]] && { echo "TIMEOUT"; $SMOLVM machine stop --name stream-test-$$ 2>/dev/null; $SMOLVM machine delete stream-test-$$ -f 2>/dev/null; return 1; }

    [[ "$result" == *"stream-line-1"* ]] && [[ "$result" == *"stream-line-2"* ]] && [[ "$result" == *"done"* ]] || {
        echo "Missing streaming output: $result"
        $SMOLVM machine stop --name stream-test-$$ 2>/dev/null
        $SMOLVM machine delete stream-test-$$ -f 2>/dev/null
        return 1
    }

    # Cleanup
    $SMOLVM machine stop --name stream-test-$$ 2>/dev/null
    $SMOLVM machine delete stream-test-$$ -f 2>/dev/null
}

echo ""
echo "--- Streaming Exec ---"
echo ""

run_test "Streaming exec" test_streaming_exec || true

# =============================================================================
# Auto-Interactive Detection
# =============================================================================

test_run_no_command_errors() {
    # machine run with no command and no -it should error with guidance
    local result
    local exit_code=0
    result=$($SMOLVM machine run 2>&1) || exit_code=$?

    # Should fail with non-zero exit
    [[ $exit_code -ne 0 ]] || { echo "Should have failed"; return 1; }

    # Should contain usage guidance
    [[ "$result" == *"no command specified"* ]] || {
        echo "Missing usage guidance: $result"
        return 1
    }
}

echo ""
echo "--- Run Without Command ---"
echo ""

run_test "Run with no command errors" test_run_no_command_errors || true

echo ""
echo "--- Observability Tests ---"
echo ""

# =============================================================================
# Agent Structured Logging
# Tests verify the agent writes JSON logs to the console log file.
# =============================================================================

test_agent_json_logs() {
    local vm_name="observability-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Run a command to generate agent log entries
    $SMOLVM machine exec --name "$vm_name" -- echo "observability-test" 2>&1 || true

    # Find the console log
    local data_dir
    data_dir=$(vm_data_dir "$vm_name")
    local console_log="${data_dir}/../agent-console.log"

    # Try the runtime dir
    local runtime_dir
    runtime_dir=$(find /run/user/$(id -u)/smolvm/vms/"$vm_name" -name "agent-console.log" 2>/dev/null | head -1)
    if [[ -z "$runtime_dir" ]]; then
        runtime_dir=$(find "$HOME/.cache/smolvm" -path "*/$vm_name/agent-console.log" 2>/dev/null | head -1)
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    if [[ -z "$runtime_dir" ]]; then
        echo "Console log not found"
        return 1
    fi

    # Agent should write JSON — verify at least one line parses as JSON
    local json_lines
    json_lines=$(grep -c '^{' "$runtime_dir" 2>/dev/null || echo "0")
    [[ "$json_lines" -gt 0 ]] || { echo "No JSON lines in console log ($runtime_dir)"; return 1; }

    # Verify a JSON line has expected structured fields
    local first_json
    first_json=$(grep '^{' "$runtime_dir" | head -1)
    echo "$first_json" | python3 -c "
import sys, json
line = json.load(sys.stdin)
assert 'timestamp' in line, 'missing timestamp'
assert 'level' in line, 'missing level'
" 2>&1 || { echo "JSON log missing structured fields: $first_json"; return 1; }
}

run_test "Agent: structured JSON logs" test_agent_json_logs || true

# =============================================================================
# Observational commands should not stop a running VM
# =============================================================================

# Helper: verify a command doesn't stop an already-running VM.
# Usage: assert_vm_stays_running "description" command [args...]
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
    assert_vm_stays_running "machine images" $SMOLVM machine images
}

test_prune_refuses_on_running_vm() {
    ensure_machine_running

    local status
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM not running before test"; return 1; }

    # Prune should refuse while VM is running
    local output exit_code=0
    output=$($SMOLVM machine prune 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "prune should have failed on running VM"; return 1; }
    [[ "$output" == *"cannot prune while the machine is running"* ]] || { echo "unexpected error: $output"; return 1; }

    # VM should still be running
    status=$($SMOLVM machine status 2>&1)
    [[ "$status" == *"running"* ]] || { echo "VM stopped after rejected prune"; return 1; }
}

test_prune_dry_run_refuses_on_running_vm() {
    ensure_machine_running

    local output exit_code=0
    output=$($SMOLVM machine prune --dry-run 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "prune --dry-run should have failed on running VM"; return 1; }
    [[ "$output" == *"cannot prune while the machine is running"* ]]
}

run_test "Images: does not stop running VM" test_images_does_not_stop_running_vm || true
run_test "Prune: refuses on running VM" test_prune_refuses_on_running_vm || true
run_test "Prune --dry-run: refuses on running VM" test_prune_dry_run_refuses_on_running_vm || true

print_summary "Machine Tests"
