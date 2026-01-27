#!/bin/bash
#
# Run all smolvm integration tests.
#
# Usage:
#   ./tests/run_all.sh              # Run all tests
#   ./tests/run_all.sh cli          # Run only CLI tests
#   ./tests/run_all.sh sandbox      # Run only sandbox tests
#   ./tests/run_all.sh microvm      # Run only microvm tests
#   ./tests/run_all.sh container    # Run only container tests
#   ./tests/run_all.sh api          # Run only HTTP API tests
#   ./tests/run_all.sh pack         # Run only pack tests
#   ./tests/run_all.sh pack-quick   # Run pack tests (quick mode, skips large images)
#
# Environment:
#   SMOLVM=/path/to/smolvm   # Use specific binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Track overall results
SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0

run_suite() {
    local name="$1"
    local script="$2"

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Running: $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    ((SUITES_RUN++))

    if bash "$script"; then
        ((SUITES_PASSED++))
    else
        ((SUITES_FAILED++))
    fi
}

# Determine which tests to run
if [[ $# -eq 0 ]]; then
    TESTS_TO_RUN="all"
else
    TESTS_TO_RUN="$1"
fi

echo ""
echo "=========================================="
echo "  smolvm Integration Test Suite"
echo "=========================================="

case "$TESTS_TO_RUN" in
    cli)
        run_suite "CLI Tests" "$SCRIPT_DIR/test_cli.sh"
        ;;
    sandbox)
        run_suite "Sandbox Tests" "$SCRIPT_DIR/test_sandbox.sh"
        ;;
    microvm)
        run_suite "MicroVM Tests" "$SCRIPT_DIR/test_microvm.sh"
        ;;
    container)
        run_suite "Container Tests" "$SCRIPT_DIR/test_container.sh"
        ;;
    api)
        run_suite "HTTP API Tests" "$SCRIPT_DIR/test_api.sh"
        ;;
    pack)
        run_suite "Pack Tests" "$SCRIPT_DIR/test_pack.sh"
        ;;
    pack-quick)
        run_suite "Pack Tests (Quick)" "$SCRIPT_DIR/test_pack.sh --quick"
        ;;
    all)
        run_suite "CLI Tests" "$SCRIPT_DIR/test_cli.sh"
        run_suite "Sandbox Tests" "$SCRIPT_DIR/test_sandbox.sh"
        run_suite "MicroVM Tests" "$SCRIPT_DIR/test_microvm.sh"
        run_suite "Container Tests" "$SCRIPT_DIR/test_container.sh"
        run_suite "HTTP API Tests" "$SCRIPT_DIR/test_api.sh"
        run_suite "Pack Tests" "$SCRIPT_DIR/test_pack.sh"
        ;;
    *)
        echo "Unknown test suite: $TESTS_TO_RUN"
        echo "Available: cli, sandbox, microvm, container, api, pack, pack-quick, all"
        exit 1
        ;;
esac

# Print overall summary
echo ""
echo "=========================================="
echo "  Overall Summary"
echo "=========================================="
echo ""
echo "Test suites run:    $SUITES_RUN"
echo -e "Test suites passed: ${GREEN}$SUITES_PASSED${NC}"
echo -e "Test suites failed: ${RED}$SUITES_FAILED${NC}"
echo ""

if [[ $SUITES_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}Some test suites failed.${NC}"
    exit 1
fi
