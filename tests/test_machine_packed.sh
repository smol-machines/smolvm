#!/usr/bin/env bash
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

    # 2. An attached disk must survive the packed-create path and reach libkrun.
    local attached_disk="$tmpdir/attached.img"
    python3 -c 'import sys; open(sys.argv[1], "wb").truncate(1 << 30)' "$attached_disk"
    $SMOLVM machine create --name "$vm_name" --from "$pack_output.smolmachine" --disk "$attached_disk" 2>&1 || return 1
    local listed
    listed=$($SMOLVM machine ls --json)
    [[ "$listed" == *"$attached_disk"* ]] || {
        echo "FAIL: --disk was not recorded for packed machine"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }

    # 3. Start the machine (should NOT pull — uses extracted layers)
    $SMOLVM machine start --name "$vm_name" 2>&1 || {
        echo "FAIL: start failed"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; rm -rf "$tmpdir"; return 1
    }
    $SMOLVM machine exec --name "$vm_name" -- test -b /dev/vdc 2>&1 || {
        echo "FAIL: attached disk is not visible as /dev/vdc"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }

    # A pager closing stdout must neither panic nor stop the running machine.
    local status_line
    status_line=$($SMOLVM machine status --name "$vm_name" | head -1) || {
        echo "FAIL: status failed when stdout closed early"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }
    [[ "$status_line" == *"running"* ]] || {
        echo "FAIL: status did not report running"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }
    $SMOLVM machine exec --name "$vm_name" -- true 2>&1 || {
        echo "FAIL: status with closed stdout stopped the machine"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
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


# Symlinks in a machine made from a --from-vm pack keep their owners, and can be
# re-owned. Both broke on host-extracted packs: Linux showed every link as the
# host user (links cannot carry the owner xattr), and macOS refused `chown -h`
# on an absolute link with ENOENT, because the overlay copy-up read the link's
# xattrs through a server call that followed the link to a host path.
test_packed_symlinks_keep_owners_and_rechown() {
    local src="symown-src-$$" vm_name="symown-$$" pack_dir
    pack_dir=$(mktemp -d)
    finish() {
        $SMOLVM machine stop --name "$vm_name" 2>/dev/null
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
        $SMOLVM machine delete --name "$src" -f 2>/dev/null
        rm -rf "$pack_dir"
    }

    $SMOLVM machine create --name "$src" --image alpine:latest 2>&1 || { finish; return 1; }
    $SMOLVM machine start --name "$src" 2>&1 || { finish; return 1; }
    $SMOLVM machine exec --name "$src" -- sh -c '
        adduser -D -u 1000 amika && touch /home/amika/f &&
        ln -s /home/amika/f /home/amika/abs && ln -s f /home/amika/rel &&
        chown -h 1000:1000 /home/amika/f /home/amika/abs /home/amika/rel' 2>&1 || { finish; return 1; }
    $SMOLVM machine stop --name "$src" 2>&1
    $SMOLVM pack create --from-vm "$src" -o "$pack_dir/packed" 2>&1 || { finish; return 1; }

    $SMOLVM machine create --name "$vm_name" --from "$pack_dir/packed.smolmachine" 2>&1 || { finish; return 1; }
    $SMOLVM machine start --name "$vm_name" 2>&1 || { finish; return 1; }

    local owners
    owners=$($SMOLVM machine exec --name "$vm_name" -- stat -c '%n %u:%g' /home/amika/abs /home/amika/rel 2>&1)
    [[ "$owners" == *"/home/amika/abs 1000:1000"* && "$owners" == *"/home/amika/rel 1000:1000"* ]] || {
        echo "FAIL: packed symlinks lost their owners: $owners"; finish; return 1
    }

    local rechowned
    rechowned=$($SMOLVM machine exec --name "$vm_name" -- sh -c '
        chown -h 2000:2000 /home/amika/abs /home/amika/rel &&
        stat -c "%n %u:%g" /home/amika/abs /home/amika/rel &&
        readlink /home/amika/abs && readlink /home/amika/rel' 2>&1)
    [[ "$rechowned" == *"/home/amika/abs 2000:2000"* && "$rechowned" == *"/home/amika/rel 2000:2000"* \
        && "$rechowned" == *"/home/amika/f"* ]] || {
        echo "FAIL: chown -h on packed symlinks: $rechowned"; finish; return 1
    }

    $SMOLVM machine stop --name "$vm_name" 2>&1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { finish; return 1; }
    owners=$($SMOLVM machine exec --name "$vm_name" -- stat -c '%n %u:%g' /home/amika/abs /home/amika/rel 2>&1)
    [[ "$owners" == *"/home/amika/abs 2000:2000"* && "$owners" == *"/home/amika/rel 2000:2000"* ]] || {
        echo "FAIL: re-owned symlinks reverted after restart: $owners"; finish; return 1
    }
    finish
}

# The same at/below-/workspace volume matrix as the --image suite, against a
# packed machine. Packed layers only change where the rootfs comes from, not how
# the container spec's mounts are assembled, so the matrix must come out
# identical — this is the arm that proves it rather than assuming it.
test_packed_volume_targets_resolve_inside_guest() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local pack_output="$tmpdir/vol-matrix-pack"

    if ! $SMOLVM pack create --image alpine:latest -o "$pack_output" --cpus 1 --mem 512 2>&1; then
        echo "FAIL: pack create failed, packed arm not validated"
        rm -rf "$tmpdir"
        return 1
    fi
    if [[ ! -f "$pack_output.smolmachine" ]]; then
        echo "FAIL: no .smolmachine sidecar produced"
        rm -rf "$tmpdir"
        return 1
    fi

    assert_volume_targets_resolve packed --from "$pack_output.smolmachine"
    local rc=$?
    rm -rf "$tmpdir"
    return $rc
}

# The workload's /tmp is a directory on its root filesystem, emptied at each
# boot and left out of every export, so a secret parked in /tmp never travels
# with a pack made from the machine while a file renamed out of /tmp into
# /root does. This is the one persistence rule a mount boundary no longer
# enforces (see storage::reset_workload_tmp and FLATTEN_TAR_EXCLUDES).
test_pack_from_vm_leaves_tmp_behind() {
    local vm_name="tmp-pack-$$"
    local tmpdir
    tmpdir=$(mktemp -d)
    local pack_output="$tmpdir/tmp-pack"
    $SMOLVM machine create --name "$vm_name" --image alpine:latest --cpus 1 --mem 512 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }
    $SMOLVM machine exec --name "$vm_name" -- sh -c '
        echo TMPSECRET > /tmp/secret.txt && mkdir -p /tmp/sub && echo deep > /tmp/sub/d.txt
        echo keep > /root/keep.txt
        echo moved > /tmp/moved.txt && mv /tmp/moved.txt /root/moved.txt
        grep -q " /tmp " /proc/self/mounts && { echo "FAIL: /tmp is a separate mount"; exit 1; }
        true' 2>&1 || { echo "FAIL: setup in guest"; $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1; }
    # a restart empties /tmp and keeps /root
    $SMOLVM machine stop --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1
    local after
    after=$($SMOLVM machine exec --name "$vm_name" -- sh -c 'echo "tmp=$(ls -A /tmp | wc -l) root=$(cat /root/keep.txt /root/moved.txt | tr "\n" ,)"')
    [[ "$after" == "tmp=0 root=keep,moved," ]] || {
        echo "FAIL: after restart: $after"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }
    $SMOLVM machine exec --name "$vm_name" -- sh -c 'echo TMPSECRET > /tmp/secret.txt' 2>&1 || return 1
    $SMOLVM machine stop --name "$vm_name" 2>&1 || return 1
    # a pack from the stopped machine carries /root and not /tmp
    $SMOLVM pack create --from-vm "$vm_name" -o "$pack_output" 2>&1 || {
        echo "FAIL: pack create --from-vm"
        $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null; return 1
    }
    local packed
    packed=$("$pack_output" run -- sh -c 'echo "tmp=$(ls -A /tmp | wc -l) root=$(cat /root/keep.txt /root/moved.txt | tr "\n" ,)"' 2>/dev/null | tail -1)
    $SMOLVM machine delete --name "$vm_name" -f 2>/dev/null
    rm -rf "$tmpdir"
    [[ "$packed" == "tmp=0 root=keep,moved," ]] || {
        echo "FAIL: packed machine shows: $packed"
        return 1
    }
    return 0
}

run_test "Create from .smolmachine" test_create_from_smolmachine || true
run_test "Packed: a pack from a machine leaves /tmp behind and keeps /root" test_pack_from_vm_leaves_tmp_behind || true
run_test "File cp preserves state on packed VM" test_cp_preserves_state_on_packed_vm || true
run_test "Packed: volume targets at/below /workspace resolve in guest" test_packed_volume_targets_resolve_inside_guest || true
run_test "Packed: symlinks keep owners and can be re-owned" test_packed_symlinks_keep_owners_and_rechown || true

print_summary "Packed Machine Tests"
