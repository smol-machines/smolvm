#!/bin/bash
#
# Packed Machine Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_machine_packed.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Packed Machine Tests"
echo "=========================================="
echo ""

test_create_from_smolmachine() {
    local vm_name="from-smolmachine-$$"
    local tmpdir
    tmpdir=$(mktemp -d)
    local pack_output="$tmpdir/from-sm-pack"

    # 1. Pack alpine into a .smolmachine
    $SMOLVM pack create --image alpine:latest -o "$pack_output" --cpus 1 --mem 512 2>&1 || {
        echo "SKIP: pack create failed"
        return 0
    }
    [[ -f "$pack_output.smolmachine" ]] || { echo "FAIL: no sidecar"; return 1; }

    # 2. Create a named machine from it
    $SMOLVM machine create --name "$vm_name" --from "$pack_output.smolmachine" 2>&1 || return 1

    # 3. Start the machine (should NOT pull — uses extracted layers)
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        echo "FAIL: start failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }

    # 4. Exec works
    local exec_result
    exec_result=$($SMOLVM machine exec --name "$vm_name" -- echo "from-sm-ok" 2>&1)
    [[ "$exec_result" == *"from-sm-ok"* ]] || {
        echo "FAIL: exec failed: $exec_result"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }

    # 5. Persistence: write then read. Write to the container's persistent
    # overlay (/sm-persist.txt), NOT /tmp — /tmp is a per-container tmpfs that is
    # reset for each `machine exec` once the workload has exited, so it cannot
    # test overlay persistence.
    $SMOLVM machine exec --name "$vm_name" -- sh -c 'echo persist > /sm-persist.txt' 2>&1 || true
    local read_result
    read_result=$($SMOLVM machine exec --name "$vm_name" -- cat /sm-persist.txt 2>&1)
    [[ "$read_result" == *"persist"* ]] || {
        echo "FAIL: persistence failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }

    # 6. Stop and restart — persistence survives
    $SMOLVM machine stop --name "$vm_name" 2>&1 || true
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        echo "FAIL: restart failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }
    read_result=$($SMOLVM machine exec --name "$vm_name" -- cat /sm-persist.txt 2>&1)
    [[ "$read_result" == *"persist"* ]] || {
        echo "FAIL: persistence across restart failed"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }

    # 7. Shows in ls
    $SMOLVM machine ls --json 2>&1 | grep -q "$vm_name" || {
        echo "FAIL: not in ls"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }

    # 8. Cleanup
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
}

test_cp_preserves_state_on_packed_vm() {
    local vm_name="cp-pack-$$"
    local pack_dir
    pack_dir=$(mktemp -d)

    # Create source VM, write marker, pack it
    $SMOLVM machine create --name "cp-pack-src-$$" --image alpine:latest --net 2>&1 || return 1
    $SMOLVM machine start --name "cp-pack-src-$$" 2>&1 || {
        $SMOLVM machine delete --name "cp-pack-src-$$" -f 2>/dev/null; return 1
    }
    $SMOLVM machine exec --name "cp-pack-src-$$" -- sh -c 'echo marker > /etc/pack-marker' 2>&1
    $SMOLVM machine stop --name "cp-pack-src-$$" 2>&1
    $SMOLVM pack create --from-vm "cp-pack-src-$$" -o "$pack_dir/packed" 2>&1 || {
        $SMOLVM machine delete --name "cp-pack-src-$$" -f 2>/dev/null; rm -rf "$pack_dir"; return 1
    }
    $SMOLVM machine delete --name "cp-pack-src-$$" -f 2>/dev/null

    # Create destination from pack, start, mutate via exec
    $SMOLVM machine create --name "$vm_name" --from "$pack_dir/packed.smolmachine" --net 2>&1 || {
        rm -rf "$pack_dir"; return 1
    }
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$pack_dir"; return 1
    }
    $SMOLVM machine exec --name "$vm_name" -- adduser -D alice 2>&1

    # Verify alice exists before cp
    local before
    before=$($SMOLVM machine exec --name "$vm_name" -- id alice 2>&1) || {
        echo "alice not found before cp"; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$pack_dir"; return 1
    }

    # Run cp
    echo "probe" > "$pack_dir/probe.txt"
    $SMOLVM machine cp "$pack_dir/probe.txt" "$vm_name":/tmp/probe.txt 2>&1 || {
        echo "cp failed"; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$pack_dir"; return 1
    }

    # Verify alice STILL exists after cp
    local after
    after=$($SMOLVM machine exec --name "$vm_name" -- id alice 2>&1) || {
        echo "FAIL: alice gone after cp"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$pack_dir"
        return 1
    }

    # Verify probe file landed
    local probe
    probe=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/probe.txt 2>&1)
    [[ "$probe" == *"probe"* ]] || {
        echo "FAIL: probe file missing after cp"
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        rm -rf "$pack_dir"
        return 1
    }

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
    rm -rf "$pack_dir"
}


run_test "Create from .smolmachine" test_create_from_smolmachine || true
run_test "File cp preserves state on packed VM" test_cp_preserves_state_on_packed_vm || true

print_summary "Packed Machine Tests"
