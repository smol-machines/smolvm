#!/usr/bin/env bash
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


test_publish_socket_http() {
    local vm_name="test-vm-pubsock"
    local sock_path="/tmp/smolvm-pubsock-$$.sock"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # A stale file at the host path must be replaced at start, like the other
    # host-listening bridges.
    echo "stale" > "$sock_path"

    # Publish guest TCP 18080 as a host unix socket — no -p, so the VM process
    # must not open any host TCP listener.
    $SMOLVM machine create --name "$vm_name" --publish-socket "$sock_path:18080" 2>&1 || {
        rm -f "$sock_path"
        return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f "$sock_path"
        return 1
    }

    # The stale file was replaced by a socket.
    local sock_ok=0
    [[ -S "$sock_path" ]] && sock_ok=1

    # Serve several requests on guest TCP 18080 (nc handles one connection per
    # iteration; the loop lets consecutive host requests through).
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'i=0; while [ $i -lt 5 ]; do echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 18080 -w 5; i=$((i+1)); done' &
    local server_pid=$!
    sleep 1

    # Round-trip through the published socket, twice — the socket file must
    # keep serving across connections.
    local output_a output_b
    output_a=$(curl -s --max-time 5 --unix-socket "$sock_path" http://localhost/ 2>&1)
    local rc_a=$?
    output_b=$(curl -s --max-time 5 --unix-socket "$sock_path" http://localhost/ 2>&1)
    local rc_b=$?

    # No host TCP listener may appear on the published guest port (that is the
    # point of publishing a socket instead of -p). Assert on the port, not the
    # process name: `ss -p` needs privileges and the VMM process name can vary,
    # either of which would make a name-based check pass vacuously.
    local tcp_listeners
    tcp_listeners=$(ss -ltn 2>/dev/null | awk '{print $4}' | grep -c ':18080$' || true)

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"
    rm -f "$sock_path"

    [[ $sock_ok -eq 1 ]] \
        && [[ $rc_a -eq 0 ]] && [[ "$output_a" == *"ok"* ]] \
        && [[ $rc_b -eq 0 ]] && [[ "$output_b" == *"ok"* ]] \
        && [[ "$tcp_listeners" -eq 0 ]]
}

test_publish_socket_no_listener() {
    local vm_name="test-vm-pubsock-nl"
    local sock_path="/tmp/smolvm-pubsock-nl-$$.sock"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create --name "$vm_name" --publish-socket "$sock_path:19090" 2>&1 || {
        rm -f "$sock_path"
        return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -f "$sock_path"
        return 1
    }

    # No listener on the guest port: the connection must fail fast (reset/empty
    # reply), not hang — the same no-start-order-coupling contract as expose.
    local rc_missing=0
    curl -s --max-time 5 --unix-socket "$sock_path" http://localhost/ >/dev/null 2>&1 || rc_missing=$?

    # Once a listener appears, the same published socket serves without a
    # restart.
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 19090 -w 5' &
    local server_pid=$!
    sleep 1

    local output
    output=$(curl -s --max-time 5 --unix-socket "$sock_path" http://localhost/ 2>&1)
    local rc_after=$?

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"
    rm -f "$sock_path"

    [[ $rc_missing -ne 0 ]] && [[ $rc_after -eq 0 ]] && [[ "$output" == *"ok"* ]]
}

run_test "Port: mapping host to guest HTTP" test_machine_port_mapping_http || true
run_test "Port: cross-VM conflict detected" test_port_conflict_across_vms || true
run_test "Port: publish socket HTTP round-trip, no host TCP listener" test_publish_socket_http || true
run_test "Port: publish socket without guest listener fails fast, recovers" test_publish_socket_no_listener || true

print_summary "Port Tests"
