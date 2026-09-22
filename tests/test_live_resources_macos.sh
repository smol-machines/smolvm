#!/bin/bash
set -euo pipefail
# Isolated Mac acceptance; no installed binary or rootfs is modified.
test "$(uname -s)" = Darwin
export PATH=/opt/homebrew/bin:/usr/bin:/bin:$PATH
binary=$(command -v "${SMOLVM_BIN:-smolvm}")
: "${SMOLVM_TEST_AGENT:?Set SMOLVM_TEST_AGENT to the matching aarch64 guest agent}"
: "${SMOLVM_TEST_PROBE:?Set SMOLVM_TEST_PROBE to a static Linux aarch64 build of fixtures/live-ram-probe.c}"
: "${SMOLVM_AGENT_ROOTFS:?Set SMOLVM_AGENT_ROOTFS to a prepared guest rootfs}"
source_rootfs=$(cd "$SMOLVM_AGENT_ROOTFS" && pwd -P)
root=$(mktemp -d "${SMOLVM_TEST_TMPDIR:-/var/tmp}/mac-live-ram-XXXXXX")
name="ram-$(basename "$root")"
owned_names=("$name")
export SMOLVM_DATA_DIR="$root/node" XDG_DATA_HOME="$root/data" XDG_CACHE_HOME="$root/cache"
export SMOLVM_AGENT_ROOTFS="$root/agent-rootfs"
cp -cR "$source_rootfs" "$SMOLVM_AGENT_ROOTFS"
test ! -L "$SMOLVM_AGENT_ROOTFS/usr/local/bin/smolvm-agent"
cp "$SMOLVM_TEST_AGENT" "$SMOLVM_AGENT_ROOTFS/usr/local/bin/smolvm-agent"
cp "$SMOLVM_TEST_PROBE" "$root/live-ram-probe"
machine() { "$binary" machine "$@"; }
guest() { machine exec --name "$name" -- sh -ec "$1"; }
cleanup() {
    result=$?
    trap - EXIT
    if test "$result" -ne 0; then
        guest 'cat /run/ram-probe.log; cat /proc/meminfo; dmesg | tail -60' || true
    fi
    for ((index=${#owned_names[@]}-1; index>=0; index--)); do
        if ! machine delete --name "${owned_names[index]}" --force; then
            printf 'Failed to clean up test machine: %s\n' "${owned_names[index]}" >&2
            # Preserve an earlier failure, but never report a clean acceptance
            # run when an owned VM may still be running.
            if test "$result" -eq 0; then result=1; fi
        fi
    done
    printf 'live_ram_resize_exit=%s retained_root=%s\n' "$result" "$root"
    exit "$result"
}
trap cleanup EXIT
machine create --name "$name" --cpus 2 --mem 512 --storage 1 --overlay 1
machine start --name "$name" --branchable
boot=$(guest 'cat /proc/sys/kernel/random/boot_id')
block=$(guest 'cat /sys/devices/system/memory/block_size_bytes')
test "$((16#$block))" -eq 134217728
machine cp "$root/live-ram-probe" "$name:/root/live-ram-probe"
guest 'chmod 755 /root/live-ram-probe'
guest 'ulimit -l unlimited; /root/live-ram-probe >/run/ram-probe.log 2>&1 &'
for i in $(seq 1 30); do
    if guest 'test -f /run/ram-probe-status'; then break; fi
    sleep 1
done
read -r pid initial_sequence initial_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$initial_bytes" -eq 67108864
# Model an interrupted resize after host CPU creation but before guest online.
# The checkpoint must fail promptly without changing the running source state.
python3 - "$root" "$binary" "$name" <<'PY'
import pathlib, socket, subprocess, sys
root, binary, name = sys.argv[1:]
machine_dir = subprocess.check_output([binary, "machine", "data-dir", "--name", name], text=True).strip()
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(5)
    control.connect(str(pathlib.Path(machine_dir) / "control.sock"))
    control.sendall(b"PROTOTYPE_GROW_CPUS 3\n")
    reply = control.recv(4096)
    assert b"OK created 3 vCPUs" in reply, reply
result = subprocess.run([binary, "machine", "checkpoint", "--name", name,
                         "--output", str(pathlib.Path(root) / "incomplete.smolcheckpoint")],
                        capture_output=True, text=True, timeout=10)
assert result.returncode != 0, result.stdout
assert "CPU onlining is incomplete" in result.stdout + result.stderr, result.stdout + result.stderr
print("mac_incomplete_cpu_checkpoint_refused_without_hang")
PY
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
machine resize --name "$name" --cpus 3
machine resize --name "$name" --cpus 4
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3; taskset -c 3 sh -ec "test 1 -eq 1"'
machine resize --name "$name" --mem 1024
if machine resize --name "$name" --mem 1024 --cpus 4 >"$root/mixed-resize.log" 2>&1; then exit 1; fi
grep -q 'resize CPUs, RAM, and disks in separate requests' "$root/mixed-resize.log"
machine resize --name "$name" --mem 1024
machine resize --name "$name" --cpus 4
if machine resize --name "$name" --mem 512; then exit 1; fi
if machine resize --name "$name" --cpus 2; then exit 1; fi
if machine resize --name "$name" --cpus 17; then exit 1; fi
guest 'touch /run/ram-probe-grow'
for i in $(seq 1 60); do
    read -r live_pid sequence bytes <<<"$(guest 'cat /run/ram-probe-status')"
    test "$live_pid" = "$pid"
    if test "$bytes" -eq 738197504; then break; fi
    sleep 1
done
test "$bytes" -eq 738197504
test "$sequence" -gt "$initial_sequence"
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
guest "cat /proc/$pid/status; cat /proc/meminfo; cat /sys/devices/system/memory/block_size_bytes"
locked=$(guest "awk '/^VmLck:/ {print \$2}' /proc/$pid/status")
test "$locked" -ge 720896
sleep 5
read -r live_pid final_sequence final_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$live_pid" = "$pid"
test "$final_bytes" = "$bytes"
test "$final_sequence" -gt "$sequence"
echo "mac_cpu_ram_growth_allocation_passed boot=$boot pid=$pid bytes=$bytes locked_kib=$locked block=$block"
guest 'echo source >/dev/shm/lineage-marker; echo source >/storage/lineage-marker'
mkdir -m 700 "$root/artifacts"
machine checkpoint --name "$name" --output "$root/artifacts/grown.smolcheckpoint"
machine delete --name "$name" --force
name="${name}-restored"
owned_names=("$name")
machine create --name "$name" --from "$root/artifacts/grown.smolcheckpoint"
machine start --name "$name" --branchable
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
read -r restored_pid restored_sequence restored_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$restored_pid" = "$pid"
test "$restored_bytes" = "$bytes"
sleep 5
read -r restored_pid next_sequence restored_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$next_sequence" -gt "$restored_sequence"
guest 'test "$(cat /dev/shm/lineage-marker)" = source; test "$(cat /storage/lineage-marker)" = source'
before_kib=$(guest "awk '/^MemTotal:/ {print \$2}' /proc/meminfo")
machine resize --name "$name" --mem 1152
machine resize --name "$name" --cpus 6
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-5; taskset -c 5 sh -ec "test 1 -eq 1"'
after_kib=$(guest "awk '/^MemTotal:/ {print \$2}' /proc/meminfo")
test "$after_kib" -gt "$((before_kib + 120 * 1024))"
guest 'dd if=/dev/urandom of=/dev/shm/after-restore-growth bs=1048576 count=32'
payload_hash=$(guest 'sha256sum /dev/shm/after-restore-growth' | awk '{print $1}')
parent=$name
child="${name}-child"
owned_names+=("$child")
machine branch --from "$parent" --name "$child" --branchable
name=$child
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
test "$(guest 'sha256sum /dev/shm/after-restore-growth' | awk '{print $1}')" = "$payload_hash"
read -r child_pid child_sequence child_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$child_pid" = "$pid"
test "$child_bytes" = "$bytes"
guest 'echo child >/dev/shm/lineage-marker; echo child >/storage/lineage-marker'
guest 'touch /run/ram-probe-mutate'
for i in $(seq 1 60); do
    if guest 'test -f /run/ram-probe-mutated'; then break; fi
    sleep 1
done
guest 'test -f /run/ram-probe-mutated'
sleep 5
read -r child_pid child_next child_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$child_next" -gt "$child_sequence"
# Verify that child mutations did not change the continuing Mac source by
# creating another child and checking both RAM and disk state.
machine delete --name "$child" --force
owned_names=("$parent")
second="${parent}-independence"
owned_names+=("$second")
machine branch --from "$parent" --name "$second"
name=$second
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-5; taskset -c 5 sh -ec "test 1 -eq 1"'
guest 'test "$(cat /dev/shm/lineage-marker)" = source; test "$(cat /storage/lineage-marker)" = source'
guest 'test ! -e /run/ram-probe-mutate; test ! -e /run/ram-probe-mutated'
test "$(guest 'sha256sum /dev/shm/after-restore-growth' | awk '{print $1}')" = "$payload_hash"
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
read -r second_pid second_sequence second_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$second_pid" = "$pid"
test "$second_bytes" = "$bytes"
sleep 5
read -r second_pid later_sequence second_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$later_sequence" -gt "$second_sequence"
echo mac_grown_cpu_ram_restore_branch_independence_passed
