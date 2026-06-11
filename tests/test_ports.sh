#!/bin/bash
#
# Port Mapping Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_ports.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Port Mapping Tests"
echo "=========================================="
echo ""

test_machine_port_mapping_http() {
    local vm_name="test-vm-portmap"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create and start VM with port mapping (host 18199 -> guest 8080)
    $SMOLVM machine create --name "$vm_name" -p 18199:8080 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Start a simple HTTP responder inside the VM (background exec)
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080 -w 5' &
    local server_pid=$!
    # nc serves exactly one connection; any TCP probe would consume it before
    # curl gets a chance. A fixed sleep is the right wait here.
    sleep 1

    # Curl the mapped port from the host
    local output
    output=$(curl -s --connect-timeout 5 http://127.0.0.1:18199/ 2>&1)
    local curl_rc=$?

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $curl_rc -eq 0 ]] && [[ "$output" == *"ok"* ]]
}

test_port_conflict_across_vms() {
    local vm_a="port-conflict-a-$$"
    local vm_b="port-conflict-b-$$"

    $SMOLVM machine create --name "$vm_a" -p 19876:80 --net 2>&1 >/dev/null || return 1
    $SMOLVM machine create --name "$vm_b" -p 19876:80 --net 2>&1 >/dev/null || return 1

    $SMOLVM machine start --name "$vm_a" 2>&1 >/dev/null || {
        $SMOLVM machine delete --name "$vm_a" -f 2>/dev/null
        $SMOLVM machine delete --name "$vm_b" -f 2>/dev/null
        return 1
    }

    # Second start should fail with port conflict
    local exit_code=0
    local output
    output=$($SMOLVM machine start --name "$vm_b" 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "expected port conflict error"; }
    [[ "$output" == *"already in use"* ]] || { echo "expected 'already in use' message"; }

    $SMOLVM machine stop --name "$vm_a" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_a" -f 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_b" -f 2>/dev/null || true

    [[ $exit_code -ne 0 ]]
}


run_test "Port: mapping host to guest HTTP" test_machine_port_mapping_http || true
run_test "Port: cross-VM conflict detected" test_port_conflict_across_vms || true

print_summary "Port Tests"
