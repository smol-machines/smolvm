#!/bin/bash
#
# End-to-end HTTP API tests for smolvm.
#
# Tests the `smolvm serve` command with real VM operations.
#
# Usage:
#   ./tests/test_api.sh

source "$(dirname "$0")/common.sh"
init_smolvm

echo ""
echo "=========================================="
echo "  smolvm HTTP API Tests (End-to-End)"
echo "=========================================="
echo ""

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

# API server configuration
API_SOCKET="${XDG_RUNTIME_DIR:-/tmp}/smolvm.sock"
API_URL="http://localhost"
SERVER_PID=""
MACHINE_NAME="api-test-machine"
REGISTRY_TEST_NAME="registry-coherence-test"

# API client shortcut
CURL=(curl --unix-socket "$API_SOCKET")

# =============================================================================
# Setup / Teardown
# =============================================================================

start_server() {
    log_info "Starting API server on unix://$API_SOCKET..."
    rm -f "$API_SOCKET"
    $SMOLVM serve start &
    SERVER_PID=$!

    local retries=30
    while [[ $retries -gt 0 ]]; do
        if "${CURL[@]}" -s "$API_URL/health" >/dev/null 2>&1; then
            log_info "Server started (PID: $SERVER_PID)"
            return 0
        fi
        sleep 0.1
        ((retries--))
    done

    log_fail "Server failed to start"
    return 1
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        log_info "Stopping API server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

cleanup() {
    # Delete machines via API (this stops the VMs properly)
    if "${CURL[@]}" -s "$API_URL/health" >/dev/null 2>&1; then
        "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$MACHINE_NAME" >/dev/null 2>&1 || true
        "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME" >/dev/null 2>&1 || true
    fi
    stop_server

    # Fallback: if server died unexpectedly, try to stop any orphan VMs
    # This handles cases where tests were interrupted
    $SMOLVM machine stop 2>/dev/null || true
}

trap cleanup EXIT

# =============================================================================
# Tests
# =============================================================================

test_health() {
    local response
    response=$("${CURL[@]}" -s "$API_URL/health")
    [[ "$response" == *'"status":"ok"'* ]]
}

test_create_and_start_machine() {
    # Create machine
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$MACHINE_NAME\", \"network\": true, \"cpus\": 1, \"mem\": 512}")
    [[ "$status" != "200" ]] && return 1

    # Start machine (boots VM)
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/start")
    [[ "$response" == *'"state":"running"'* ]]
}

test_exec_echo() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "api-test-marker"]}')
    [[ "$response" == *"api-test-marker"* ]]
}

test_exec_reads_vm_filesystem() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["cat", "/etc/os-release"]}')
    [[ "$response" == *"Alpine"* ]] || [[ "$response" == *"alpine"* ]]
}

test_exec_exit_codes() {
    # Test exit code 0
    local response exit_code
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 0"]}')
    exit_code=$(echo "$response" | grep -o '"exitCode":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" != "0" ]] && return 1

    # Test exit code 42
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 42"]}')
    exit_code=$(echo "$response" | grep -o '"exitCode":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" == "42" ]]
}

test_exec_with_env() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo $MY_VAR"], "env": [{"name": "MY_VAR", "value": "hello_from_api"}]}')
    [[ "$response" == *"hello_from_api"* ]]
}

test_exec_with_workdir() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["pwd"], "workdir": "/tmp"}')
    [[ "$response" == *"/tmp"* ]]
}

test_exec_shell_pipeline() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo hello world | wc -w"]}')
    [[ "$response" == *"2"* ]]
}

test_pull_and_run_image() {
    # Pull image
    "${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/images/pull" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest"}' >/dev/null

    # Run in image
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/run" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest", "command": ["echo", "container-test"]}')
    [[ "$response" == *"container-test"* ]]
}

test_stop_machine() {
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/stop")
    [[ "$response" == *'"state":"stopped"'* ]] || [[ "$response" == *'"name":'* ]]
}

test_delete_machine() {
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X DELETE "$API_URL/api/v1/machines/$MACHINE_NAME")
    [[ "$status" == "200" ]]
}

test_error_not_found() {
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/machines/nonexistent-12345")
    [[ "$status" == "404" ]]
}

test_error_bad_request() {
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d '{"name": ""}')
    [[ "$status" == "400" ]]
}

# =============================================================================
# Registry Coherence Tests
# Validates that create → start → exec works in a single server session
# without restart. This was a known bug where ApiState and DB were out of sync.
# =============================================================================

test_registry_create_start_exec() {
    # Create a fresh machine
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$REGISTRY_TEST_NAME\", \"network\": true, \"cpus\": 1, \"mem\": 512}")
    [[ "$status" != "200" ]] && { echo "create failed: $status"; return 1; }

    # Start it
    local response
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/start")
    [[ "$response" != *'"state":"running"'* ]] && { echo "start failed: $response"; return 1; }

    # Exec immediately — this is the key test. Before the registry fix, this returned 404.
    response=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "registry-ok"]}')
    [[ "$response" == *"registry-ok"* ]]
}

test_registry_get_machine() {
    local response
    response=$("${CURL[@]}" -s "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME")
    [[ "$response" == *"\"name\":\"$REGISTRY_TEST_NAME\""* ]] && \
    [[ "$response" == *'"state":"running"'* ]]
}

test_registry_cleanup() {
    # Stop + delete the registry test machine
    "${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/stop" >/dev/null 2>&1 || true
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X DELETE "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME")
    [[ "$status" == "200" ]]
}

# =============================================================================
# Run Tests
# =============================================================================

if ! start_server; then
    echo -e "${RED}Failed to start server, aborting tests${NC}"
    exit 1
fi

run_test "Health check" test_health || true
run_test "Create and start machine" test_create_and_start_machine || true
run_test "Exec echo" test_exec_echo || true
run_test "Exec reads VM filesystem" test_exec_reads_vm_filesystem || true
run_test "Exec exit codes" test_exec_exit_codes || true
run_test "Exec with environment variable" test_exec_with_env || true
run_test "Exec with workdir" test_exec_with_workdir || true
run_test "Exec shell pipeline" test_exec_shell_pipeline || true
run_test "Pull and run image" test_pull_and_run_image || true
run_test "Stop machine" test_stop_machine || true
run_test "Delete machine" test_delete_machine || true
run_test "Error: not found (404)" test_error_not_found || true
run_test "Error: bad request (400)" test_error_bad_request || true

# Registry coherence tests (validates create→start→exec without restart)
run_test "Registry: create→start→exec in one session" test_registry_create_start_exec || true
run_test "Registry: get machine after create" test_registry_get_machine || true
run_test "Registry: cleanup test machine" test_registry_cleanup || true

# Auto-generated names via API
test_api_auto_generated_names() {
    # Without name → auto-generated vm-* name
    local response
    response=$("${CURL[@]}" -sf -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d '{"cpus": 1, "memoryMb": 512}' 2>&1) || { echo "Create failed: $response"; return 1; }

    local auto_name
    auto_name=$(echo "$response" | jq -r '.name // empty')
    [[ "$auto_name" == vm-* ]] || { echo "Expected vm-* name, got: $auto_name"; return 1; }

    # With explicit name → uses it
    local explicit="api-name-test-$$"
    response=$("${CURL[@]}" -sf -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$explicit\", \"cpus\": 1, \"memoryMb\": 512}" 2>&1) || return 1
    local name
    name=$(echo "$response" | jq -r '.name')
    [[ "$name" == "$explicit" ]] || { echo "Expected $explicit, got: $name"; return 1; }

    # Cleanup
    "${CURL[@]}" -sf -X DELETE "$API_URL/api/v1/machines/$auto_name" 2>/dev/null
    "${CURL[@]}" -sf -X DELETE "$API_URL/api/v1/machines/$explicit" 2>/dev/null
}

echo ""
echo "--- Auto-Generated Names (API) ---"
echo ""

run_test "API: auto-generated names" test_api_auto_generated_names || true

# =============================================================================
# Observability (Trace ID correlation)
# Tests verify that the API server returns trace IDs and they propagate
# through to the agent for end-to-end request correlation.
# =============================================================================

test_trace_id_in_response_header() {
    # Every API response should have an X-Trace-Id header
    local headers
    headers=$("${CURL[@]}" -sI "$API_URL/health" 2>&1)
    echo "$headers" | grep -qi "x-trace-id" || { echo "Missing X-Trace-Id header"; return 1; }

    # Trace ID should be a hex string
    local trace_id
    trace_id=$(echo "$headers" | grep -i "x-trace-id" | tr -d '\r' | awk '{print $2}')
    [[ "$trace_id" =~ ^[0-9a-f]{16}$ ]] || { echo "Invalid trace_id format: '$trace_id'"; return 1; }
}

test_trace_id_unique_per_request() {
    # Two requests should get different trace IDs
    local tid1 tid2
    tid1=$("${CURL[@]}" -sI "$API_URL/health" 2>&1 | grep -i "x-trace-id" | tr -d '\r' | awk '{print $2}')
    tid2=$("${CURL[@]}" -sI "$API_URL/health" 2>&1 | grep -i "x-trace-id" | tr -d '\r' | awk '{print $2}')

    [[ -n "$tid1" ]] && [[ -n "$tid2" ]] && [[ "$tid1" != "$tid2" ]] || {
        echo "Trace IDs not unique: '$tid1' vs '$tid2'"
        return 1
    }
}

echo ""
echo "--- Observability Tests ---"
echo ""

run_test "Trace ID: present in response header" test_trace_id_in_response_header || true
run_test "Trace ID: unique per request" test_trace_id_unique_per_request || true

test_trace_id_end_to_end() {
    # Create and start a machine via API
    local vm_name="trace-e2e-test-$$"
    "${CURL[@]}" -sf -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$vm_name\", \"cpus\": 1, \"memoryMb\": 512}" >/dev/null 2>&1 || return 1
    "${CURL[@]}" -sf -X POST "$API_URL/api/v1/machines/$vm_name/start" >/dev/null 2>&1 || {
        "${CURL[@]}" -sf -X DELETE "$API_URL/api/v1/machines/$vm_name" >/dev/null 2>&1
        return 1
    }

    # Exec a command and capture the trace ID from the response header
    local trace_id
    trace_id=$("${CURL[@]}" -sD - -X POST "$API_URL/api/v1/machines/$vm_name/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "trace-e2e"]}' 2>&1 | grep -i "x-trace-id" | tr -d '\r' | awk '{print $2}')

    # Cleanup
    "${CURL[@]}" -sf -X POST "$API_URL/api/v1/machines/$vm_name/stop" >/dev/null 2>&1
    "${CURL[@]}" -sf -X DELETE "$API_URL/api/v1/machines/$vm_name" >/dev/null 2>&1

    # Verify we got a trace ID back
    [[ -n "$trace_id" ]] || { echo "No trace ID returned from exec"; return 1; }
    [[ "$trace_id" =~ ^[0-9a-f]{16}$ ]] || { echo "Invalid trace ID: '$trace_id'"; return 1; }

    echo "End-to-end trace ID: $trace_id"
}

run_test "Trace ID: end-to-end with running VM" test_trace_id_end_to_end || true

test_metrics_endpoint() {
    local response
    response=$("${CURL[@]}" -s "$API_URL/metrics" 2>&1)

    # Should return Prometheus text format
    [[ -n "$response" ]] || { echo "Empty metrics response"; return 1; }

    # After making requests, the counter should exist
    echo "$response" | grep -q "smolvm_api_requests_total" || { echo "Missing request counter"; return 1; }
}

test_health_enriched() {
    local response
    response=$("${CURL[@]}" -s "$API_URL/health" 2>&1)

    # Should have version
    echo "$response" | grep -q '"version"' || { echo "Missing version"; return 1; }

    # Should have machine counts
    echo "$response" | grep -q '"machines"' || { echo "Missing machines"; return 1; }

    # Should have uptime
    echo "$response" | grep -q '"uptime_seconds"' || { echo "Missing uptime"; return 1; }
}

run_test "Prometheus: /metrics endpoint" test_metrics_endpoint || true
run_test "Health: enriched response" test_health_enriched || true

# =============================================================================
# Create from .smolmachine via API
# =============================================================================

test_api_create_from_smolmachine() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local pack_output="$tmpdir/api-from-pack"

    # Pack alpine
    $SMOLVM pack create --image alpine:latest -o "$pack_output" --cpus 1 --mem 512 2>&1 >/dev/null || {
        echo "SKIP: pack create failed"
        rm -rf "$tmpdir"
        return 0
    }
    local sidecar
    sidecar=$(cd "$tmpdir" && pwd)/api-from-pack.smolmachine
    [[ -f "$sidecar" ]] || { echo "FAIL: no sidecar"; rm -rf "$tmpdir"; return 1; }

    local vm_name="api-from-$$"

    # Create via API with from field
    local create_resp
    create_resp=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$vm_name\", \"from\": \"$sidecar\", \"memoryMb\": 512}")
    echo "$create_resp" | grep -q "$vm_name" || {
        echo "FAIL: create response missing name: $create_resp"
        rm -rf "$tmpdir"; return 1
    }

    # Start
    local start_resp
    start_resp=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$vm_name/start")
    echo "$start_resp" | grep -q "running" || {
        echo "FAIL: start failed: $start_resp"
        "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$vm_name" >/dev/null
        rm -rf "$tmpdir"; return 1
    }

    # Exec
    local exec_resp
    exec_resp=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$vm_name/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "api-from-ok"]}')
    echo "$exec_resp" | grep -q "api-from-ok" || {
        echo "FAIL: exec failed: $exec_resp"
        "${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$vm_name/stop" >/dev/null
        "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$vm_name" >/dev/null
        rm -rf "$tmpdir"; return 1
    }

    # Cleanup
    "${CURL[@]}" -s -X POST "$API_URL/api/v1/machines/$vm_name/stop" >/dev/null
    "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$vm_name" >/dev/null
    rm -rf "$tmpdir"
}

test_api_from_and_image_conflict() {
    local resp
    resp=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d '{"from": "/tmp/test.smolmachine", "image": "alpine"}')
    echo "$resp" | grep -q "mutually exclusive" || {
        echo "FAIL: expected conflict error: $resp"
        return 1
    }
}

test_api_from_nonexistent_sidecar() {
    local resp
    resp=$("${CURL[@]}" -s -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d '{"from": "/nonexistent/file.smolmachine"}')
    echo "$resp" | grep -q "not found" || {
        echo "FAIL: expected not found error: $resp"
        return 1
    }
}

echo ""
echo "--- Create from .smolmachine via API ---"
echo ""

run_test "API: create from .smolmachine" test_api_create_from_smolmachine || true
run_test "API: from + image conflict" test_api_from_and_image_conflict || true
run_test "API: from nonexistent sidecar" test_api_from_nonexistent_sidecar || true

# =============================================================================
# Created-state machines survive server restart
# =============================================================================

test_created_machine_survives_restart() {
    local name="created-survive-$$"

    # Create a machine (never start it)
    local status
    status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\", \"cpus\": 1, \"memoryMb\": 512}")
    [[ "$status" == "200" ]] || { echo "FAIL: create returned $status"; return 1; }

    # Verify it exists
    local get_status
    get_status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/machines/$name")
    [[ "$get_status" == "200" ]] || { echo "FAIL: machine not found after create"; return 1; }

    # Restart the server
    stop_server
    start_server || { echo "FAIL: server restart failed"; return 1; }

    # Machine should still exist
    get_status=$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/machines/$name")
    [[ "$get_status" == "200" ]] || {
        echo "FAIL: created machine deleted on server restart (got $get_status)"
        return 1
    }

    # Cleanup
    "${CURL[@]}" -s -X DELETE "$API_URL/api/v1/machines/$name" >/dev/null 2>&1 || true
}

run_test "API: created machine survives server restart" test_created_machine_survives_restart || true

print_summary "HTTP API Tests"
