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
API_PORT=18080
API_URL="http://127.0.0.1:$API_PORT"
SERVER_PID=""
MACHINE_NAME="api-test-machine"
REGISTRY_TEST_NAME="registry-coherence-test"

# =============================================================================
# Setup / Teardown
# =============================================================================

start_server() {
    log_info "Starting API server on port $API_PORT..."
    $SMOLVM serve start --listen "127.0.0.1:$API_PORT" &
    SERVER_PID=$!

    local retries=30
    while [[ $retries -gt 0 ]]; do
        if curl -s "$API_URL/health" >/dev/null 2>&1; then
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
    if curl -s "$API_URL/health" >/dev/null 2>&1; then
        curl -s -X DELETE "$API_URL/api/v1/machines/$MACHINE_NAME" >/dev/null 2>&1 || true
        curl -s -X DELETE "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME" >/dev/null 2>&1 || true
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
    response=$(curl -s "$API_URL/health")
    [[ "$response" == *'"status":"ok"'* ]]
}

test_create_and_start_machine() {
    # Create machine
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$MACHINE_NAME\", \"network\": true, \"cpus\": 1, \"mem\": 512}")
    [[ "$status" != "200" ]] && return 1

    # Start machine (boots VM)
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/start")
    [[ "$response" == *'"state":"running"'* ]]
}

test_exec_echo() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "api-test-marker"]}')
    [[ "$response" == *"api-test-marker"* ]]
}

test_exec_reads_vm_filesystem() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["cat", "/etc/os-release"]}')
    [[ "$response" == *"Alpine"* ]] || [[ "$response" == *"alpine"* ]]
}

test_exec_exit_codes() {
    # Test exit code 0
    local response exit_code
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 0"]}')
    exit_code=$(echo "$response" | grep -o '"exitCode":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" != "0" ]] && return 1

    # Test exit code 42
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 42"]}')
    exit_code=$(echo "$response" | grep -o '"exitCode":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" == "42" ]]
}

test_exec_with_env() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo $MY_VAR"], "env": [{"name": "MY_VAR", "value": "hello_from_api"}]}')
    [[ "$response" == *"hello_from_api"* ]]
}

test_exec_with_workdir() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["pwd"], "workdir": "/tmp"}')
    [[ "$response" == *"/tmp"* ]]
}

test_exec_shell_pipeline() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo hello world | wc -w"]}')
    [[ "$response" == *"2"* ]]
}

test_pull_and_run_image() {
    # Pull image
    curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/images/pull" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest"}' >/dev/null

    # Run in image
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/run" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest", "command": ["echo", "container-test"]}')
    [[ "$response" == *"container-test"* ]]
}

test_stop_machine() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$MACHINE_NAME/stop")
    [[ "$response" == *'"state":"stopped"'* ]] || [[ "$response" == *'"name":'* ]]
}

test_delete_machine() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API_URL/api/v1/machines/$MACHINE_NAME")
    [[ "$status" == "200" ]]
}

test_error_not_found() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/machines/nonexistent-12345")
    [[ "$status" == "404" ]]
}

test_error_bad_request() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
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
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/machines" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$REGISTRY_TEST_NAME\", \"network\": true, \"cpus\": 1, \"mem\": 512}")
    [[ "$status" != "200" ]] && { echo "create failed: $status"; return 1; }

    # Start it
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/start")
    [[ "$response" != *'"state":"running"'* ]] && { echo "start failed: $response"; return 1; }

    # Exec immediately — this is the key test. Before the registry fix, this returned 404.
    response=$(curl -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "registry-ok"]}')
    [[ "$response" == *"registry-ok"* ]]
}

test_registry_get_machine() {
    local response
    response=$(curl -s "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME")
    [[ "$response" == *"\"name\":\"$REGISTRY_TEST_NAME\""* ]] && \
    [[ "$response" == *'"state":"running"'* ]]
}

test_registry_cleanup() {
    # Stop + delete the registry test machine
    curl -s -X POST "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME/stop" >/dev/null 2>&1 || true
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API_URL/api/v1/machines/$REGISTRY_TEST_NAME")
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

print_summary "HTTP API Tests"
