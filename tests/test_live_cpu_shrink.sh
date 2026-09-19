#!/bin/bash
set -euo pipefail
# Run only with an isolated, matching engine/runtime/guest-agent bundle.
test "$(uname -s)-$(uname -m)" = Linux-x86_64
binary=$(command -v "${SMOLVM_BIN:-smolvm}")
: "${SMOLVM_AGENT_ROOTFS:?Set a matching isolated guest rootfs}"
root=$(mktemp -d "${SMOLVM_TEST_TMPDIR:-/var/tmp}/cpu-shrink-XXXXXX")
export SMOLVM_DATA_DIR="$root/node" XDG_DATA_HOME="$root/data" XDG_CACHE_HOME="$root/cache"
name="cpu-$(basename "$root")"
owned=("$name")
machine() { "$binary" machine "$@"; }
guest() { machine exec --name "$name" -- sh -ec "$1"; }
quota() {
    if test "${SMOLVM_TEST_REQUIRE_CPU_QUOTA:-0}" != 1; then return; fi
    python3 - "$(machine data-dir --name "$name")" "$1" <<'PY'
import pathlib, sys
pid = int((pathlib.Path(sys.argv[1]) / 'agent.pid').read_text().splitlines()[0])
entry = next(line for line in pathlib.Path(f'/proc/{pid}/cgroup').read_text().splitlines() if line.startswith('0::'))
directory = pathlib.Path('/sys/fs/cgroup') / entry[3:].lstrip('/')
budget, period = (directory / 'cpu.max').read_text().split()
assert budget != 'max', f'VMM has no CPU quota: {directory}'
assert int(budget) == int(period) * int(sys.argv[2]), (budget, period, sys.argv[2])
print(f'verified_host_cpu_quota={sys.argv[2]} pid={pid}')
PY
}
cleanup() {
    result=$?
    trap - EXIT
    for ((index=${#owned[@]}-1; index>=0; index--)); do
        vm=${owned[index]}
        if test "$result" -ne 0; then
            vm_dir=$(machine data-dir --name "$vm") || vm_dir=""
            if test -n "$vm_dir"; then
                for log in agent-console.log agent-startup-error.log; do
                    if test -f "$vm_dir/$log"; then
                        cp "$vm_dir/$log" "$root/$vm-$log"
                        tail -30 "$vm_dir/$log"
                    fi
                done
            fi
        fi
        machine delete --name "$vm" --force || result=1
    done
    printf 'cpu_shrink_exit=%s retained_root=%s\n' "$result" "$root"
    exit "$result"
}
trap cleanup EXIT
machine create --name "$name" --cpus 4 --mem 512 --storage 1 --overlay 1
machine start --name "$name" --branchable
quota 4
boot=$(guest 'cat /proc/sys/kernel/random/boot_id')
guest 'echo parent >/dev/shm/state; (while :; do date +%s >/run/heartbeat; sleep 1; done) >/run/workload.log 2>&1 & echo $! >/run/workload.pid'
pid=$(guest 'cat /run/workload.pid')
machine resize --name "$name" --cpus 2
quota 2
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1'
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
guest "kill -0 $pid"
before=$(guest 'cat /run/heartbeat')
sleep 2
after=$(guest 'cat /run/heartbeat')
test "$after" -gt "$before"
if machine resize --name "$name" --cpus 0; then exit 1; fi
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1'
memory_before=$(guest "awk '/^MemTotal:/ {print \$2}' /proc/meminfo")
disk_before=$(guest 'cat /sys/class/block/vda/size')
if machine resize --name "$name" --mem 256; then exit 1; fi
if machine resize --name "$name" --storage 0; then exit 1; fi
test "$(guest "awk '/^MemTotal:/ {print \$2}' /proc/meminfo")" = "$memory_before"
test "$(guest 'cat /sys/class/block/vda/size')" = "$disk_before"
machine resize --name "$name" --cpus 1
quota 1
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0'
machine resize --name "$name" --cpus 2
mkdir -m 700 "$root/artifacts"
machine checkpoint --name "$name" --output "$root/artifacts/shrunk.smolcheckpoint"
machine delete --name "$name" --force
owned=()
name="${name}-restored"
owned+=("$name")
machine create --name "$name" --from "$root/artifacts/shrunk.smolcheckpoint"
machine start --name "$name" --branchable
quota 2
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1; test "$(cat /dev/shm/state)" = parent'
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
guest "kill -0 $pid"
machine resize --name "$name" --cpus 4
quota 4
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3; taskset -c 3 true'
machine resize --name "$name" --cpus 2
parent=$name
name="${parent}-child"
owned+=("$name")
machine branch --from "$parent" --name "$name" --branchable
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1; echo child >/dev/shm/state'
machine resize --name "$name" --cpus 4
quota 4
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3; taskset -c 3 true'
name=$parent
quota 2
guest 'test "$(cat /dev/shm/state)" = parent; test "$(cat /sys/devices/system/cpu/online)" = 0-1'
if test -n "${SMOLVM_TEST_LEGACY_LIB_DIR:-}"; then
    name="${parent}-legacy"
    owned+=("$name")
    machine create --name "$name" --cpus 4 --mem 512 --storage 1 --overlay 1
    SMOLVM_LIB_DIR="$SMOLVM_TEST_LEGACY_LIB_DIR" machine start --name "$name" --branchable
    if machine resize --name "$name" --cpus 2 >"$root/legacy-refusal.log" 2>&1; then exit 1; fi
    grep -q 'cannot safely restore offlined CPUs' "$root/legacy-refusal.log"
    guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3'
    echo legacy_runtime_refused_without_guest_mutation
fi
echo cpu_shrink_restore_regrow_branch_passed
