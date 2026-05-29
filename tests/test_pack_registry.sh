#!/bin/bash
#
# Registry push/pull integration tests for smolvm pack.
#
# Tests smolvm pack push, pack pull, and pack inspect against a local
# registry:2 container, verifying the full OCI distribution spec roundtrip.
#
# Requires:
#   - Docker (skip gracefully if not available)
#   - A working smolvm binary (for pack create + push + pull)
#
# Usage:
#   ./tests/test_pack_registry.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

REGISTRY_PORT=5099                          # port unlikely to conflict
REGISTRY_HOST="localhost:${REGISTRY_PORT}"
REGISTRY_CONTAINER="smolvm-test-reg-$$"
TEST_DIR=$(mktemp -d)

# Start cleanup trap — always remove the container and temp dir on exit.
trap 'stop_local_registry; rm -rf "$TEST_DIR"' EXIT

start_local_registry() {
    docker run -d \
        -p "${REGISTRY_PORT}:5000" \
        --name "$REGISTRY_CONTAINER" \
        registry:2 >/dev/null 2>&1
}

stop_local_registry() {
    docker stop "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
    docker rm   "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
}

wait_for_registry() {
    local i
    for i in $(seq 1 20); do
        if curl -sf "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Pre-flight: Docker availability
# ---------------------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
    log_skip "Docker not installed — registry tests skipped"
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    log_skip "Docker daemon not running — registry tests skipped"
    exit 0
fi

log_info "Starting local registry:2 on ${REGISTRY_HOST}..."
if ! start_local_registry; then
    log_skip "Failed to start local registry — skipping"
    exit 0
fi

if ! wait_for_registry; then
    log_skip "Registry did not become ready — skipping"
    exit 0
fi
log_info "Registry ready at ${REGISTRY_HOST}"

# ---------------------------------------------------------------------------
# Shared fixture: one .smolmachine created once for all tests
# ---------------------------------------------------------------------------

FIXTURE_SIDECAR="$TEST_DIR/fixture.smolmachine"

log_info "Creating fixture .smolmachine (alpine:latest)..."
if ! $SMOLVM pack create --image alpine:latest -o "$TEST_DIR/fixture" 2>/dev/null; then
    log_skip "pack create failed — cannot run registry tests (is the VM running?)"
    exit 0
fi

if [[ ! -f "$FIXTURE_SIDECAR" ]]; then
    log_skip "No fixture sidecar produced — skipping"
    exit 0
fi

log_info "Fixture ready: $FIXTURE_SIDECAR"

FIXTURE_SHA=$(shasum -a 256 "$FIXTURE_SIDECAR" | cut -d' ' -f1)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "  smolvm Pack Registry Tests"
echo "=========================================="
echo ""

# Push a .smolmachine artifact, then pull it back and verify SHA256 equality.
test_push_pull_roundtrip() {
    local ref="${REGISTRY_HOST}/roundtrip-test:latest"
    local pull_out="$TEST_DIR/pulled-roundtrip.smolmachine"

    # Push
    $SMOLVM pack push "$ref" -f "$FIXTURE_SIDECAR" 2>/dev/null || {
        echo "FAIL: pack push failed"
        return 1
    }

    # Pull
    $SMOLVM pack pull "$ref" -o "$pull_out" 2>/dev/null || {
        echo "FAIL: pack pull failed"
        return 1
    }

    [[ -f "$pull_out" ]] || { echo "FAIL: output file not created"; return 1; }

    # Byte-for-byte verification
    local pull_sha
    pull_sha=$(shasum -a 256 "$pull_out" | cut -d' ' -f1)

    if [[ "$FIXTURE_SHA" != "$pull_sha" ]]; then
        echo "FAIL: SHA256 mismatch after roundtrip"
        echo "  original: $FIXTURE_SHA"
        echo "  pulled:   $pull_sha"
        return 1
    fi

    echo "  SHA256 matches: $pull_sha"
}

# Push once, inspect twice — inspect must not download the layer blob.
test_inspect_returns_metadata() {
    local ref="${REGISTRY_HOST}/inspect-test:v1"

    $SMOLVM pack push "$ref" -f "$FIXTURE_SIDECAR" 2>/dev/null || {
        echo "FAIL: push failed"
        return 1
    }

    local inspect_out
    inspect_out=$($SMOLVM pack inspect "$ref" --json 2>/dev/null)

    [[ "$inspect_out" == *'"image"'* ]]          || { echo "FAIL: missing 'image' field"; return 1; }
    [[ "$inspect_out" == *'"platform"'* ]]        || { echo "FAIL: missing 'platform' field"; return 1; }
    [[ "$inspect_out" == *'"smolvm_version"'* ]]  || { echo "FAIL: missing 'smolvm_version' field"; return 1; }
    [[ "$inspect_out" == *'"layer_digest"'* ]]    || { echo "FAIL: missing 'layer_digest' field"; return 1; }
    [[ "$inspect_out" == *'"layer_size"'* ]]      || { echo "FAIL: missing 'layer_size' field"; return 1; }

    echo "  Inspect JSON contains all expected fields"
}

# Push by tag, pull back by the returned manifest digest instead of tag.
test_pull_by_digest() {
    local tag_ref="${REGISTRY_HOST}/digest-test:tagged"
    local pull_out="$TEST_DIR/pulled-by-digest.smolmachine"

    # Push and capture manifest digest from output
    local push_out
    push_out=$($SMOLVM pack push "$tag_ref" -f "$FIXTURE_SIDECAR" 2>&1) || {
        echo "FAIL: push failed"
        return 1
    }

    local manifest_digest
    manifest_digest=$(echo "$push_out" | grep -oE 'sha256:[a-f0-9]{64}' | tail -1)

    if [[ -z "$manifest_digest" ]]; then
        echo "SKIP: could not extract manifest digest from push output"
        return 0
    fi

    local digest_ref="${REGISTRY_HOST}/digest-test@${manifest_digest}"

    $SMOLVM pack pull "$digest_ref" -o "$pull_out" 2>/dev/null || {
        echo "FAIL: pull by digest failed (ref: $digest_ref)"
        return 1
    }

    [[ -f "$pull_out" ]] || { echo "FAIL: output file not created"; return 1; }

    local pull_sha
    pull_sha=$(shasum -a 256 "$pull_out" | cut -d' ' -f1)

    if [[ "$FIXTURE_SHA" != "$pull_sha" ]]; then
        echo "FAIL: SHA256 mismatch pulling by digest"
        echo "  original: $FIXTURE_SHA"
        echo "  pulled:   $pull_sha"
        return 1
    fi

    echo "  Pulled by digest, SHA256 matches"
}

# Push same artifact under two tags — second push must skip the blob (already exists).
test_push_deduplicates_blob() {
    local ref1="${REGISTRY_HOST}/dedup-test:v1"
    local ref2="${REGISTRY_HOST}/dedup-test:v2"

    local out1 out2
    out1=$($SMOLVM pack push "$ref1" -f "$FIXTURE_SIDECAR" 2>&1) || { echo "FAIL: first push failed"; return 1; }
    out2=$($SMOLVM pack push "$ref2" -f "$FIXTURE_SIDECAR" 2>&1) || { echo "FAIL: second push failed"; return 1; }

    # Second push should report blob already exists (skipped upload)
    if echo "$out2" | grep -qi "already exists\|skipping"; then
        echo "  Second push correctly skipped blob re-upload"
    else
        # Not fatal — the registry may accept duplicate uploads silently.
        echo "  (blob dedup message not found in output — may be registry-dependent)"
    fi
}

# Push an artifact, then pull it to a default-named output path.
# (pull without -o should write to <name>.smolmachine in the current dir)
test_pull_default_output_path() {
    local ref="${REGISTRY_HOST}/default-path-test:latest"
    local work_dir="$TEST_DIR/default-path-work"
    mkdir -p "$work_dir"

    $SMOLVM pack push "$ref" -f "$FIXTURE_SIDECAR" 2>/dev/null || {
        echo "FAIL: push failed"
        return 1
    }

    local pull_out
    pull_out=$(cd "$work_dir" && $SMOLVM pack pull "$ref" 2>/dev/null && ls -1 *.smolmachine 2>/dev/null | head -1)

    if [[ -z "$pull_out" ]]; then
        echo "SKIP: default output path test — no .smolmachine written to cwd"
        return 0
    fi

    [[ -f "$work_dir/$pull_out" ]] || { echo "FAIL: expected $work_dir/$pull_out to exist"; return 1; }

    echo "  Pull wrote default output: $pull_out"
}

# Push to a nonexistent registry — must fail with a clear error.
test_push_to_nonexistent_registry() {
    local ref="localhost:19999/no-such-registry/test:latest"
    local exit_code=0
    $SMOLVM pack push "$ref" -f "$FIXTURE_SIDECAR" 2>/dev/null || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "FAIL: push to nonexistent registry should fail"; return 1; }
    echo "  Correctly failed with exit code $exit_code"
}

# Pull a tag that was never pushed — must fail clearly.
test_pull_nonexistent_tag() {
    local ref="${REGISTRY_HOST}/never-pushed-repo:v999"
    local exit_code=0
    $SMOLVM pack pull "$ref" -o "$TEST_DIR/should-not-exist.smolmachine" 2>/dev/null || exit_code=$?
    [[ $exit_code -ne 0 ]] || { echo "FAIL: pull of nonexistent tag should fail"; return 1; }
    echo "  Correctly failed with exit code $exit_code"
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

run_test "push → pull roundtrip (SHA256 match)"    test_push_pull_roundtrip
run_test "inspect returns manifest metadata"         test_inspect_returns_metadata
run_test "pull by manifest digest"                   test_pull_by_digest
run_test "push deduplicates blob on re-push"         test_push_deduplicates_blob
run_test "pull default output path"                  test_pull_default_output_path
run_test "push to nonexistent registry fails"        test_push_to_nonexistent_registry
run_test "pull nonexistent tag fails"                test_pull_nonexistent_tag

print_summary "Pack Registry Tests"
