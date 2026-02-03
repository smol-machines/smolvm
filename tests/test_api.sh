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
SANDBOX_NAME="api-test-sandbox"

# =============================================================================
# Setup / Teardown
# =============================================================================

start_server() {
    log_info "Starting API server on port $API_PORT..."
    $SMOLVM serve --listen "127.0.0.1:$API_PORT" &
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
    # Delete sandbox via API (this stops the VM properly)
    if curl -s "$API_URL/health" >/dev/null 2>&1; then
        curl -s -X DELETE "$API_URL/api/v1/sandboxes/$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi
    stop_server

    # Fallback: if server died unexpectedly, try to stop any orphan VMs
    # This handles cases where tests were interrupted
    $SMOLVM microvm stop 2>/dev/null || true
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

test_create_and_start_sandbox() {
    # Create sandbox
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/sandboxes" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$SANDBOX_NAME\"}")
    [[ "$status" != "200" ]] && return 1

    # Start sandbox (boots VM)
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/start")
    [[ "$response" == *'"state":"running"'* ]]
}

test_exec_echo() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["echo", "api-test-marker"]}')
    [[ "$response" == *"api-test-marker"* ]]
}

test_exec_reads_vm_filesystem() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["cat", "/etc/os-release"]}')
    [[ "$response" == *"Alpine"* ]] || [[ "$response" == *"alpine"* ]]
}

test_exec_exit_codes() {
    # Test exit code 0
    local response exit_code
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 0"]}')
    exit_code=$(echo "$response" | grep -o '"exit_code":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" != "0" ]] && return 1

    # Test exit code 42
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "exit 42"]}')
    exit_code=$(echo "$response" | grep -o '"exit_code":[0-9]*' | cut -d: -f2)
    [[ "$exit_code" == "42" ]]
}

test_exec_with_env() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo $MY_VAR"], "env": [{"name": "MY_VAR", "value": "hello_from_api"}]}')
    [[ "$response" == *"hello_from_api"* ]]
}

test_exec_with_workdir() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["pwd"], "workdir": "/tmp"}')
    [[ "$response" == *"/tmp"* ]]
}

test_exec_shell_pipeline() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/exec" \
        -H "Content-Type: application/json" \
        -d '{"command": ["sh", "-c", "echo hello world | wc -w"]}')
    [[ "$response" == *"2"* ]]
}

test_pull_and_run_image() {
    # Pull image
    curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/images/pull" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest"}' >/dev/null

    # Run in image
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/run" \
        -H "Content-Type: application/json" \
        -d '{"image": "alpine:latest", "command": ["echo", "container-test"]}')
    [[ "$response" == *"container-test"* ]]
}

test_stop_sandbox() {
    local response
    response=$(curl -s -X POST "$API_URL/api/v1/sandboxes/$SANDBOX_NAME/stop")
    [[ "$response" == *'"state":"stopped"'* ]] || [[ "$response" == *'"name":'* ]]
}

test_delete_sandbox() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API_URL/api/v1/sandboxes/$SANDBOX_NAME")
    [[ "$status" == "200" ]]
}

test_error_not_found() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/sandboxes/nonexistent-12345")
    [[ "$status" == "404" ]]
}

test_error_bad_request() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/sandboxes" \
        -H "Content-Type: application/json" \
        -d '{"name": ""}')
    [[ "$status" == "400" ]]
}

# =============================================================================
# Run Tests
# =============================================================================

if ! start_server; then
    echo -e "${RED}Failed to start server, aborting tests${NC}"
    exit 1
fi

run_test "Health check" test_health || true
run_test "Create and start sandbox" test_create_and_start_sandbox || true
run_test "Exec echo" test_exec_echo || true
run_test "Exec reads VM filesystem" test_exec_reads_vm_filesystem || true
run_test "Exec exit codes" test_exec_exit_codes || true
run_test "Exec with environment variable" test_exec_with_env || true
run_test "Exec with workdir" test_exec_with_workdir || true
run_test "Exec shell pipeline" test_exec_shell_pipeline || true
run_test "Pull and run image" test_pull_and_run_image || true
run_test "Stop sandbox" test_stop_sandbox || true
run_test "Delete sandbox" test_delete_sandbox || true
run_test "Error: not found (404)" test_error_not_found || true
run_test "Error: bad request (400)" test_error_bad_request || true

print_summary "HTTP API Tests"
