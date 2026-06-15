#!/bin/bash
#
# run_tests.sh -- primary test runner for smolvm
#
# Usage:
#   ./tests/run_tests.sh                        # run all 11 feature suites (~10 min)
#   ./tests/run_tests.sh bare network           # run specific groups
#   SMOLVM_SKIP_SLOW=1 ./tests/run_tests.sh     # skip tests with long sleeps
#
# Feature suites (run by default with no args):
#   bare            test_machine_bare.sh
#   db              test_db.sh
#   network         test_network.sh
#   volumes         test_volumes.sh
#   ports           test_ports.sh
#   storage         test_storage.sh
#   resources       test_resources.sh
#   reliability     test_reliability.sh
#   run             test_machine_run.sh
#   image           test_machine_image.sh
#   local-image     test_machine_local_image.sh
#   packed          test_machine_packed.sh
#
# Extended suites (opt-in only, not run by default):
#   cli             test_cli.sh
#   api             test_api.sh
#   virtio-net      test_virtio_net.sh
#   smolfile        test_smolfile.sh
#   secrets         test_secrets.sh
#   pack            test_pack.sh
#   pack-quick      test_pack.sh --quick
#   gpu             test_gpu.sh  (requires GPU hardware)
#
# Non-pass/fail:
#   bench           bench_vm_startup.sh (prints timing, always exits 0)
#
# Environment:
#   SMOLVM_SKIP_SLOW=1   Skip long-running tests (>=25 s intentional sleeps)
#
# Parallelism (no-args mode only):
#   resources runs in the background (pure CLI, no VMs -- always safe).
#   All VM-starting suites run sequentially to avoid host resource contention
#   that causes intermittent machine-start failures under concurrent load.
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Map a group name to its script path and optional extra args.
# Prints "script [args...]" on stdout; returns non-zero for unknown groups.
get_suite() {
    case "$1" in
        bare)        echo "$SCRIPT_DIR/test_machine_bare.sh" ;;
        db)          echo "$SCRIPT_DIR/test_db.sh" ;;
        network)     echo "$SCRIPT_DIR/test_network.sh" ;;
        volumes)     echo "$SCRIPT_DIR/test_volumes.sh" ;;
        ports)       echo "$SCRIPT_DIR/test_ports.sh" ;;
        storage)     echo "$SCRIPT_DIR/test_storage.sh" ;;
        resources)   echo "$SCRIPT_DIR/test_resources.sh" ;;
        reliability) echo "$SCRIPT_DIR/test_reliability.sh" ;;
        run)         echo "$SCRIPT_DIR/test_machine_run.sh" ;;
        image)       echo "$SCRIPT_DIR/test_machine_image.sh" ;;
        local-image) echo "$SCRIPT_DIR/test_machine_local_image.sh" ;;
        packed)      echo "$SCRIPT_DIR/test_machine_packed.sh" ;;
        cli)         echo "$SCRIPT_DIR/test_cli.sh" ;;
        api)         echo "$SCRIPT_DIR/test_api.sh" ;;
        virtio-net)  echo "$SCRIPT_DIR/test_virtio_net.sh" ;;
        smolfile)    echo "$SCRIPT_DIR/test_smolfile.sh" ;;
        secrets)     echo "$SCRIPT_DIR/test_secrets.sh" ;;
        pack)        echo "$SCRIPT_DIR/test_pack.sh" ;;
        pack-quick)  echo "$SCRIPT_DIR/test_pack.sh --quick" ;;
        gpu)         echo "$SCRIPT_DIR/test_gpu.sh" ;;
        scale)       echo "$SCRIPT_DIR/test_scale.sh" ;;
        *)           return 1 ;;
    esac
}

FAILED_SUITES=()
PASSED_SUITES=()

# Tell each suite to skip its own kill_orphan_smolvm_processes pre-flight.
# We do a single pre-flight kill here before launching anything, so per-suite
# kills are skipped to avoid parallel suites killing each other's VMs.
export SMOLVM_ORCHESTRATED=1

run_suite() {
    local name="$1"
    local suite_line
    suite_line="$(get_suite "$name")"
    echo ""
    echo "------------------------------------------------"
    echo "  Running: $name"
    echo "------------------------------------------------"
    # shellcheck disable=SC2086
    if bash $suite_line; then
        PASSED_SUITES+=("$name")
    else
        FAILED_SUITES+=("$name")
    fi
}

# Single pre-flight orphan kill before any suite touches the system.
echo "Pre-flight: killing orphan smolvm processes..."
pkill -f "smolvm serve" 2>/dev/null || true
pkill -f "smolvm-bin machine start" 2>/dev/null || true
pkill -f "smolvm machine start" 2>/dev/null || true
sleep 1

if [[ $# -eq 0 ]]; then
    # resources: pure CLI validation (no VMs) -- safe to run concurrently with anything.
    # All other suites start VMs, which under concurrent load causes intermittent
    # machine-start failures in the sequential group, so they run sequentially.
    PARALLEL_ORDER=(resources)
    PARALLEL_PIDS=()
    PARALLEL_OUTFILES=()

    for i in "${!PARALLEL_ORDER[@]}"; do
        _name="${PARALLEL_ORDER[$i]}"
        _outfile=$(mktemp)
        PARALLEL_OUTFILES[$i]="$_outfile"
        _suite_line="$(get_suite "$_name")"
        # shellcheck disable=SC2086
        bash $_suite_line > "$_outfile" 2>&1 &
        PARALLEL_PIDS[$i]=$!
    done

    # Sequential suites -- run one at a time.
    for _name in bare db reliability storage run image local-image network volumes ports packed; do
        run_suite "$_name"
    done

    # Print buffered output from parallel suites and collect results.
    for i in "${!PARALLEL_ORDER[@]}"; do
        _name="${PARALLEL_ORDER[$i]}"
        echo ""
        echo "------------------------------------------------"
        echo "  Results: $_name"
        echo "------------------------------------------------"
        cat "${PARALLEL_OUTFILES[$i]}"
        if wait "${PARALLEL_PIDS[$i]}"; then
            PASSED_SUITES+=("$_name")
        else
            FAILED_SUITES+=("$_name")
        fi
        rm -f "${PARALLEL_OUTFILES[$i]}"
    done
else
    for group in "$@"; do
        # bench is not a pass/fail suite -- run directly and exit
        if [[ "$group" == "bench" ]]; then
            bash "$SCRIPT_DIR/bench_vm_startup.sh"
            continue
        fi
        get_suite "$group" > /dev/null || {
            echo "Unknown group: $group"
            echo "Feature suites: bare db network volumes ports storage resources reliability run image local-image packed"
            echo "Extended suites: cli api virtio-net smolfile pack pack-quick gpu scale"
            echo "Other: bench"
            exit 1
        }
        run_suite "$group"
    done
fi

echo ""
echo "================================================"
echo "  Suite Summary"
echo "================================================"
[[ ${#PASSED_SUITES[@]} -gt 0 ]] && echo "  PASSED: ${PASSED_SUITES[*]}"
if [[ ${#FAILED_SUITES[@]} -gt 0 ]]; then
    echo "  FAILED: ${FAILED_SUITES[*]}"
    exit 1
fi
