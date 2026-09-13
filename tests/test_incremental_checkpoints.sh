#!/usr/bin/env bash
# Real VM acceptance gate for stored checkpoints and standalone exports.
# Run with SMOLVM_BIN and SMOLVM_LIB_DIR pointing at the builds under test.
set -euo pipefail

bin=${SMOLVM_BIN:-smolvm}
root=$(mktemp -d "${SMOLVM_QA_ROOT:-$PWD}/checkpoint-qa.XXXXXX")
prefix="checkpoint-qa-$$"
source_vm="$prefix-source"
first_vm="$prefix-first"
second_vm="$prefix-second"
export_vm="$prefix-export"
branch_vm="$prefix-branch"
cleanup() {
    for name in "$branch_vm" "$export_vm" "$second_vm" "$first_vm" "$source_vm"; do
        "$bin" machine delete --name "$name" --force >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT
printf 'Artifacts and logs: %s\n' "$root"

"$bin" machine create --name "$source_vm" --image docker.io/library/alpine:3.22 --net --cpus 2 --mem 1024 --storage 2 --overlay 1
"$bin" machine start --name "$source_vm" --branchable
"$bin" machine exec --name "$source_vm" -- sh -ec 'dd if=/dev/urandom of=/dev/shm/cow-data bs=1048576 count=32; echo first > /root/checkpoint-marker; echo first > /dev/shm/checkpoint-marker'
"$bin" machine exec --name "$source_vm" --detach -- sh -ec 'echo $$ > /dev/shm/checkpoint-worker.pid; while :; do sleep 5; done'
"$bin" machine exec --name "$source_vm" -- sh -ec 'for n in 1 2 3 4 5; do test -s /dev/shm/checkpoint-worker.pid && break; sleep 1; done; kill -0 "$(cat /dev/shm/checkpoint-worker.pid)"'
first_hash=$("$bin" machine exec --name "$source_vm" -- sha256sum /dev/shm/cow-data | awk '/^[0-9a-f]+ / {print $1}')
[[ ${#first_hash} == 64 ]]

"$bin" machine checkpoint --name "$source_vm" --store "$root/store" --output "$root/first.smolcheckpoint" | tee "$root/first.log"
"$bin" machine exec --name "$source_vm" -- sh -ec 'dd if=/dev/zero of=/dev/shm/cow-data bs=4096 count=16 seek=256 conv=notrunc; echo second > /root/checkpoint-marker; echo second > /dev/shm/checkpoint-marker'
second_hash=$("$bin" machine exec --name "$source_vm" -- sha256sum /dev/shm/cow-data | awk '/^[0-9a-f]+ / {print $1}')
[[ ${#second_hash} == 64 && "$first_hash" != "$second_hash" ]]
"$bin" machine checkpoint --name "$source_vm" --store "$root/store" --output "$root/second.smolcheckpoint" | tee "$root/second.log"
if "$bin" machine checkpoint --name "$source_vm" --store "$root/store" --output "$root/second.smolcheckpoint"; then
    printf 'FAIL: overwrote a checkpoint\n' >&2; exit 1
fi
"$bin" machine exec --name "$source_vm" -- sh -ec 'echo later > /root/checkpoint-marker; echo later > /dev/shm/checkpoint-marker'

verify() {
    local name=$1 marker=$2 expected=$3
    "$bin" machine exec --name "$name" -- sh -ec "test \"\$(cat /root/checkpoint-marker)\" = '$marker'; test \"\$(cat /dev/shm/checkpoint-marker)\" = '$marker'"
    "$bin" machine exec --name "$name" -- sh -ec 'kill -0 "$(cat /dev/shm/checkpoint-worker.pid)"'
    local actual
    actual=$("$bin" machine exec --name "$name" -- sha256sum /dev/shm/cow-data | awk '/^[0-9a-f]+ / {print $1}')
    [[ "$actual" == "$expected" ]]
}

"$bin" machine create --name "$first_vm" --from "$root/first.smolcheckpoint"
"$bin" machine start --name "$first_vm"
verify "$first_vm" first "$first_hash"
"$bin" machine branch --from "$first_vm" --name "$branch_vm"
verify "$branch_vm" first "$first_hash"
"$bin" machine exec --name "$branch_vm" -- sh -ec 'echo private > /dev/shm/checkpoint-marker'
verify "$first_vm" first "$first_hash"

"$bin" machine create --name "$second_vm" --from "$root/second.smolcheckpoint"
"$bin" machine start --name "$second_vm"
verify "$second_vm" second "$second_hash"
"$bin" machine checkpoint --export-from "$root/second.smolcheckpoint" --output "$root/export.smolcheckpoint"
"$bin" machine checkpoint-prune --store "$root/store"
"$bin" machine create --name "$export_vm" --from "$root/export.smolcheckpoint"
"$bin" machine start --name "$export_vm"
verify "$export_vm" second "$second_hash"

# Interrupt only this test's capture client after a stored RAM object proves
# that the source has resumed and streaming has begun.
"$bin" machine checkpoint --name "$source_vm" --store "$root/interrupted-store" --output "$root/interrupted.smolcheckpoint" >"$root/interrupted.log" 2>&1 &
capture_pid=$!
streaming=false
for ((attempt = 0; attempt < 1000; attempt++)); do
    if [[ -d "$root/interrupted-store/objects" ]] && find "$root/interrupted-store/objects" -type f -name '????????????????????????????????????????????????????????????????' | read -r _; then
        streaming=true
        break
    fi
    kill -0 "$capture_pid" 2>/dev/null || break
    sleep 0.02
done
if [[ "$streaming" != true ]]; then
    wait "$capture_pid" || true
    printf 'FAIL: did not observe capture streaming\n' >&2; exit 1
fi
kill -KILL "$capture_pid"
wait "$capture_pid" 2>/dev/null || true
[[ ! -e "$root/interrupted.smolcheckpoint" ]]
"$bin" machine exec --name "$source_vm" -- sh -ec 'test "$(cat /dev/shm/checkpoint-marker)" = later'
"$bin" machine checkpoint-prune --store "$root/interrupted-store"
[[ -z $(find "$root/interrupted-store/staging" -mindepth 1 -maxdepth 1 -type d) ]]
[[ -z $(find "$root/interrupted-store/objects" -type f) ]]
"$bin" machine checkpoint --name "$source_vm" --store "$root/store" --output "$root/after-interrupt.smolcheckpoint"
printf 'PASS: RAM, disk, rollback, branch isolation, source continuation, standalone export, and interrupted-capture recovery\n'
