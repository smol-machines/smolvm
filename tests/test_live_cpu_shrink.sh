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
cleanup() {
    result=$?
    trap - EXIT
    for vm in "${owned[@]}"; do
        machine delete --name "$vm" --force || result=1
    done
    printf 'cpu_shrink_exit=%s retained_root=%s\n' "$result" "$root"
    exit "$result"
}
trap cleanup EXIT
machine create --name "$name" --cpus 4 --mem 512 --storage 1 --overlay 1
machine start --name "$name" --branchable
boot=$(guest 'cat /proc/sys/kernel/random/boot_id')
guest 'echo parent >/dev/shm/state; (while :; do date +%s >/run/heartbeat; sleep 1; done) >/run/workload.log 2>&1 & echo $! >/run/workload.pid'
pid=$(guest 'cat /run/workload.pid')
machine resize --name "$name" --cpus 2
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1'
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
guest "kill -0 $pid"
before=$(guest 'cat /run/heartbeat')
sleep 2
after=$(guest 'cat /run/heartbeat')
test "$after" -gt "$before"
if machine resize --name "$name" --cpus 0; then exit 1; fi
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1'
mkdir -m 700 "$root/artifacts"
machine checkpoint --name "$name" --output "$root/artifacts/shrunk.smolcheckpoint"
machine delete --name "$name" --force
owned=()
name="${name}-restored"
owned+=("$name")
machine create --name "$name" --from "$root/artifacts/shrunk.smolcheckpoint"
machine start --name "$name" --branchable
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1; test "$(cat /dev/shm/state)" = parent'
test "$(guest 'cat /proc/sys/kernel/random/boot_id')" = "$boot"
guest "kill -0 $pid"
machine resize --name "$name" --cpus 4
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3; taskset -c 3 true'
machine resize --name "$name" --cpus 2
parent=$name
name="${parent}-child"
owned+=("$name")
machine branch --from "$parent" --name "$name" --branchable
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-1; echo child >/dev/shm/state'
machine resize --name "$name" --cpus 4
guest 'test "$(cat /sys/devices/system/cpu/online)" = 0-3; taskset -c 3 true'
name=$parent
guest 'test "$(cat /dev/shm/state)" = parent; test "$(cat /sys/devices/system/cpu/online)" = 0-1'
echo cpu_shrink_restore_regrow_branch_passed
