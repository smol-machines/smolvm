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

test_machine_port_range_mapping_http() {
    local vm_name="test-vm-portmap"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    # Create and start VM with one-to-one port mappings:
    # host 18199 -> guest 8080 and host 18200 -> guest 8081.
    $SMOLVM machine create --name "$vm_name" -p 18199-18200:8080-8081 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    # Each nc responder serves one request. Avoid readiness probes because they
    # would consume that request before curl reaches the published port.
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none" | nc -l -p 8080 -w 5' &
    local first_server_pid=$!
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo" | nc -l -p 8081 -w 5' &
    local second_server_pid=$!
    sleep 1

    local first_output
    local first_curl_rc
    first_output=$(curl -s --connect-timeout 5 http://127.0.0.1:18199/ 2>&1)
    first_curl_rc=$?

    local second_output
    local second_curl_rc
    second_output=$(curl -s --connect-timeout 5 http://127.0.0.1:18200/ 2>&1)
    second_curl_rc=$?

    kill "$first_server_pid" "$second_server_pid" 2>/dev/null || true
    wait "$first_server_pid" "$second_server_pid" 2>/dev/null || true

    # Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $first_curl_rc -eq 0 ]] && [[ "$first_output" == *"one"* ]] &&
        [[ $second_curl_rc -eq 0 ]] && [[ "$second_output" == *"two"* ]]
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


test_machine_ports_change_while_running() {
    local vm_name="test-vm-liveports"
    local port=18210

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create --name "$vm_name" -p 18209:9 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    local ok=true
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlive" | nc -l -p 8080 -w 10' &
    local server_pid=$!
    sleep 1

    if curl -s --connect-timeout 2 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
        echo "host port $port answered before it was published"
        ok=false
    fi
    $SMOLVM machine update --name "$vm_name" -p "$port:8080" 2>&1 || ok=false
    local output
    output=$(curl -s --connect-timeout 5 "http://127.0.0.1:$port/" 2>&1)
    [[ "$output" == "live" ]] || { echo "published port returned: $output"; ok=false; }
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    local status
    status=$($SMOLVM machine status --name "$vm_name" 2>&1)
    [[ "$status" == *unning* ]] || { echo "machine stopped during the update: $status"; ok=false; }

    $SMOLVM machine update --name "$vm_name" --remove-port "$port:8080" 2>&1 || ok=false
    if curl -s --connect-timeout 2 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
        echo "host port $port still answered after it was removed"
        ok=false
    fi

    $SMOLVM machine update --name "$vm_name" -p "$port:8080" 2>&1 || ok=false
    $SMOLVM machine stop --name "$vm_name" 2>&1 || ok=false
    $SMOLVM machine start --name "$vm_name" 2>&1 || ok=false
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c 'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nkept" | nc -l -p 8080 -w 10' &
    server_pid=$!
    sleep 1
    output=$(curl -s --connect-timeout 5 "http://127.0.0.1:$port/" 2>&1)
    [[ "$output" == "kept" ]] || { echo "port was not kept across a restart: $output"; ok=false; }
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    [[ "$ok" == true ]]
}

# Poll `machine status` until its output does (want=yes) or does not (want=no)
# contain $2, for up to 15 s. The guest reports listeners about once a second.
wait_for_status_line() {
    local vm_name="$1" line="$2" want="$3"
    local i status
    for i in $(seq 1 30); do
        status=$($SMOLVM machine status --name "$vm_name" 2>&1)
        if [[ "$status" == *"$line"* ]]; then
            [[ "$want" == yes ]] && return 0
        else
            [[ "$want" == no ]] && return 0
        fi
        sleep 0.5
    done
    echo "status after 15 s: $status"
    return 1
}

test_machine_auto_ports_follow_guest_listeners() {
    local vm_name="test-vm-autoports-$$"
    local port=18231

    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    if curl -s --connect-timeout 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
        echo "host port $port is already in use; cannot run this test"
        return 1
    fi

    $SMOLVM machine create --name "$vm_name" --auto-ports 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }

    local ok=true output
    # Bound to the guest's loopback only: a `-p` port could not reach it, auto
    # ports do. One response, then nc exits and the port closes.
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c "printf 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nauto' | nc -l -s 127.0.0.1 -p $port" &
    local server_pid=$!

    wait_for_status_line "$vm_name" "port $port -> $port: auto" yes || ok=false
    output=$($SMOLVM machine ls --json 2>&1)
    [[ "$output" == *'"auto":true'* || "$output" == *'"auto": true'* ]] || {
        echo "ls --json does not mark the port auto: $output"
        ok=false
    }
    output=$(curl -s --max-time 5 "http://127.0.0.1:$port/" 2>&1)
    [[ "$output" == "auto" ]] || { echo "auto-published port returned: $output"; ok=false; }
    wait "$server_pid" 2>/dev/null || true

    # nc served its one request and exited: the host port must close.
    wait_for_status_line "$vm_name" "port $port -> $port: auto" no || ok=false
    if curl -s --max-time 2 "http://127.0.0.1:$port/" 2>/dev/null | grep -q auto; then
        echo "host port $port still answered after the guest stopped listening"
        ok=false
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    [[ "$ok" == true ]]
}

test_machine_auto_ports_off_by_default() {
    local vm_name="test-vm-noautoports-$$"
    local port=18232

    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    $SMOLVM machine create --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        return 1
    }
    $SMOLVM machine exec --name "$vm_name" -- \
        sh -c "printf 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nleak' | nc -l -p $port -w 5" &
    local server_pid=$!
    sleep 3
    local ok=true
    if curl -s --max-time 2 "http://127.0.0.1:$port/" 2>/dev/null | grep -q leak; then
        echo "a guest port reached the host without --auto-ports"
        ok=false
    fi
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    [[ "$ok" == true ]]
}

run_test "Port: range mappings reach distinct guest HTTP servers" test_machine_port_range_mapping_http || true
run_test "Port: cross-VM conflict detected" test_port_conflict_across_vms || true
run_test "Port: published ports change while the machine runs" test_machine_ports_change_while_running || true
run_test "Port: --auto-ports publishes and closes guest listeners" test_machine_auto_ports_follow_guest_listeners || true
run_test "Port: guest listeners stay private without --auto-ports" test_machine_auto_ports_off_by_default || true

print_summary "Port Tests"
