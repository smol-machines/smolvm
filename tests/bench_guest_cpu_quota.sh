#!/usr/bin/env bash
# Run with a complete Linux or macOS smolvm distribution. Compare its output
# across builds on the same host. Guest timer latency varies with host load.
set -euo pipefail
binary=$(command -v "${SMOLVM_BIN:-smolvm}")
data=$(mktemp -d "${TMPDIR:-/tmp}/smolvm-quota.XXXXXX")
export SMOLVM_DATA_DIR="$data"
name=quota-bench
machine() { "$binary" machine "$@"; }
machine create --name "$name" --cpus 4 --mem 512 --storage 1 --overlay 1
cleanup() {
    machine stop --name "$name" >/dev/null 2>&1 || true
    if machine delete --name "$name" --force >/dev/null; then rm -rf "$data"; fi
}
trap cleanup EXIT
machine start --name "$name"
machine exec --name "$name" -- sh -ec '
set -eu
base=/sys/fs/cgroup
mount -o remount,rw "$base" 2>/dev/null || true
echo +cpu > "$base/cgroup.subtree_control"
group="$base/quota-$$"
mkdir "$group"
echo "100000 100000" > "$group/cpu.max"
stat_field() { awk -v key="$1" "\$1 == key {print \$2}" "$group/cpu.stat"; }
printf "workers,elapsed_s,cpu_s,throttled_s,throttled_periods\n"
for workers in 1 4; do
    pids=""
    for n in $(seq "$workers"); do
        sh -c '\''echo $$ > "$1/cgroup.procs"; exec yes >/dev/null'\'' sh "$group" &
        pids="$pids $!"
    done
    sleep 1
    read before rest < /proc/uptime
    cpu=$(stat_field usage_usec)
    wait_us=$(stat_field throttled_usec)
    periods=$(stat_field nr_throttled)
    sleep 8
    used=$(($(stat_field usage_usec) - cpu))
    waited=$(($(stat_field throttled_usec) - wait_us))
    throttled=$(($(stat_field nr_throttled) - periods))
    read after rest < /proc/uptime
    kill $pids
    wait
    awk -v n="$workers" -v a="$before" -v b="$after" -v cpu="$used" -v wait_us="$waited" -v periods="$throttled" '\''
        BEGIN {
            printf "%d,%.3f,%.6f,%.6f,%d\n", n,b-a,cpu/1e6,wait_us/1e6,periods
            # Allow for partially sampled quota periods and uptime resolution.
            exit !(cpu > 0 && cpu/1e6 <= b-a+0.22 && (n == 1 || periods > 0))
        }'\''
done
rmdir "$group"
'
