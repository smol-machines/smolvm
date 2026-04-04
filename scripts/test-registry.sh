#!/usr/bin/env bash
# Integration test for smolvm registry push/pull against local zot.
#
# Prerequisites:
#   - docker compose (for local zot)
#   - cargo build (smolvm binary)
#   - A .smolmachine file to push (or pass as $1)
#
# Usage:
#   ./scripts/test-registry.sh [path-to-smolmachine]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
INFRA_DIR="$REPO_DIR/smolmachines-registry"
REGISTRY="localhost:5050"
TEST_REF="localhost:5050/test-machine:latest"
SMOLVM="$REPO_DIR/target/debug/smolvm"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() {
    echo -e "${RED}FAIL${NC}: $1"
    # Clean up registry on failure.
    docker compose -f "$INFRA_DIR/docker-compose.yml" down > /dev/null 2>&1 || true
    exit 1
}
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Build if needed.
if [ ! -f "$SMOLVM" ]; then
    info "Building smolvm..."
    cargo build --manifest-path "$REPO_DIR/Cargo.toml"
fi

# Find or create a test .smolmachine file.
TEST_SMOLMACHINE="${1:-}"
if [ -z "$TEST_SMOLMACHINE" ]; then
    # Look for any existing .smolmachine in the repo.
    TEST_SMOLMACHINE=$(find "$REPO_DIR" -maxdepth 1 -name "*.smolmachine" -type f | head -1)
fi

if [ -z "$TEST_SMOLMACHINE" ] || [ ! -f "$TEST_SMOLMACHINE" ]; then
    info "No .smolmachine file found. Skipping integration test."
    info "To run: smolvm pack create --image alpine:latest -o /tmp/test-alpine"
    info "Then:   $0 /tmp/test-alpine.smolmachine"
    exit 0
fi

info "Using test artifact: $TEST_SMOLMACHINE"

# ---------------------------------------------------------------------------
# Start local registry
# ---------------------------------------------------------------------------

info "Starting local zot registry..."
if ! docker compose -f "$INFRA_DIR/docker-compose.yml" up -d 2>/dev/null; then
    info "docker compose failed — is Docker running?"
    info "Skipping integration test."
    exit 0
fi

# Wait for registry to be ready.
for i in $(seq 1 10); do
    if curl -sf "http://$REGISTRY/v2/" > /dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        fail "Registry did not start within 10 seconds"
    fi
    sleep 1
done
pass "Registry is running at $REGISTRY"

# ---------------------------------------------------------------------------
# Test push
# ---------------------------------------------------------------------------

info "Pushing $TEST_SMOLMACHINE to $TEST_REF..."
$SMOLVM registry push "$TEST_REF" -f "$TEST_SMOLMACHINE"
pass "Push succeeded"

# ---------------------------------------------------------------------------
# Test pull
# ---------------------------------------------------------------------------

PULL_OUTPUT=$(mktemp -d)/pulled.smolmachine

info "Pulling $TEST_REF to $PULL_OUTPUT..."
$SMOLVM registry pull "$TEST_REF" -o "$PULL_OUTPUT"
pass "Pull succeeded"

# Verify file sizes match.
ORIG_SIZE=$(wc -c < "$TEST_SMOLMACHINE" | tr -d ' ')
PULL_SIZE=$(wc -c < "$PULL_OUTPUT" | tr -d ' ')

if [ "$ORIG_SIZE" -eq "$PULL_SIZE" ]; then
    pass "File sizes match ($ORIG_SIZE bytes)"
else
    fail "Size mismatch: original=$ORIG_SIZE pulled=$PULL_SIZE"
fi

# Verify file contents match.
ORIG_SHA=$(shasum -a 256 "$TEST_SMOLMACHINE" | cut -d' ' -f1)
PULL_SHA=$(shasum -a 256 "$PULL_OUTPUT" | cut -d' ' -f1)

if [ "$ORIG_SHA" = "$PULL_SHA" ]; then
    pass "SHA256 digests match ($ORIG_SHA)"
else
    fail "Digest mismatch: original=$ORIG_SHA pulled=$PULL_SHA"
fi

# ---------------------------------------------------------------------------
# Test cached pull
# ---------------------------------------------------------------------------

PULL_OUTPUT2=$(mktemp -d)/pulled2.smolmachine

info "Pulling again (should hit cache)..."
OUTPUT=$($SMOLVM registry pull "$TEST_REF" -o "$PULL_OUTPUT2" 2>&1)
if echo "$OUTPUT" | grep -q "cached"; then
    pass "Second pull used cache"
else
    info "Second pull did not report cache hit (may be expected)"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

rm -f "$PULL_OUTPUT" "$PULL_OUTPUT2"
info "Stopping local registry..."
docker compose -f "$INFRA_DIR/docker-compose.yml" down > /dev/null 2>&1

echo ""
echo -e "${GREEN}All registry integration tests passed.${NC}"
