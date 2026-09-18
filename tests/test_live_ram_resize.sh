#!/bin/bash
set -euo pipefail
# Standalone Linux RAM lifecycle acceptance. Requires KVM, root/systemd-managed
# scopes, a memory controller, and a native static C compiler (default musl-gcc).
# Set SMOLVM_BIN, SMOLVM_AGENT_ROOTFS and SMOLVM_LIB_DIR for an uninstalled build.
# Only this test's machines are deleted; fixture/artifact paths are printed.
test "$(uname -s)" = Linux
test "$(id -u)" -eq 0
grep -qw memory /sys/fs/cgroup/cgroup.controllers
test_dir=$(cd "$(dirname "$0")" && pwd)
binary=$(command -v "${SMOLVM_BIN:-smolvm}")
root=$(mktemp -d "${SMOLVM_TEST_TMPDIR:-/var/tmp}/live-ram-resize-XXXXXX")
name="ram-$(basename "$root")"
owned_names=("$name")
export SMOLVM_DATA_DIR="$root/node" XDG_DATA_HOME="$root/data" XDG_CACHE_HOME="$root/cache"
export SMOLVM_VM_USE_SCOPE=1
"${SMOLVM_TEST_CC:-musl-gcc}" -static -O2 -Wall -Wextra -Werror \
    "$test_dir/fixtures/live-ram-probe.c" -o "$root/live-ram-probe"
machine() { timeout "${SMOLVM_TEST_COMMAND_TIMEOUT:-600}" "$binary" machine "$@"; }
guest() { machine exec --name "$name" -- sh -ec "$1"; }
cleanup() {
    result=$?
    trap - EXIT
    if test "$result" -ne 0; then
        guest 'cat /run/ram-probe.log; cat /proc/meminfo; dmesg | tail -60' || true
    fi
    for ((index=${#owned_names[@]}-1; index>=0; index--)); do
        machine delete --name "${owned_names[index]}" --force || true
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
machine resize --name "$name" --mem 1024
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
echo "linux_ram_growth_allocation_passed boot=$boot pid=$pid bytes=$bytes locked_kib=$locked block=$block"
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
machine resize --name "$name" --mem 1152
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
sleep 5
read -r child_pid child_next child_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$child_next" -gt "$child_sequence"
# Linux ARM currently retains a frozen source. Verify that child mutations did
# not change that source by resuming a second child from the same frozen base.
machine delete --name "$child" --force
owned_names=("$parent")
second="${parent}-independence"
owned_names+=("$second")
machine branch --from "$parent" --name "$second"
name=$second
guest 'test "$(cat /dev/shm/lineage-marker)" = source; test "$(cat /storage/lineage-marker)" = source'
test "$(guest 'sha256sum /dev/shm/after-restore-growth' | awk '{print $1}')" = "$payload_hash"
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
read -r second_pid second_sequence second_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$second_pid" = "$pid"
test "$second_bytes" = "$bytes"
sleep 5
read -r second_pid later_sequence second_bytes <<<"$(guest 'cat /run/ram-probe-status')"
test "$later_sequence" -gt "$second_sequence"
echo linux_grown_ram_restore_branch_independence_passed
