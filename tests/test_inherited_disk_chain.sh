#!/bin/bash
set -euo pipefail
test "$(uname -s)" = Linux
test -r /dev/kvm && test -w /dev/kvm
command -v qemu-img >/dev/null
command -v python3 >/dev/null
command -v curl >/dev/null
binary=$(command -v "${SMOLVM_BIN:-smolvm}")
root=$(mktemp -d "${SMOLVM_TEST_TMPDIR:-/var/tmp}/inherited-chain-XXXXXX")
export SMOLVM_DATA_DIR="$root/node"
owned_names=()
server_pid=
golden_flags=()
if test "${SMOLVM_TEST_FREEZE_GOLDENS:-0}" = 1; then golden_flags+=(--freeze-source); fi
machine() { timeout "${SMOLVM_TEST_COMMAND_TIMEOUT:-120}" "$binary" machine "$@"; }
check_markers() {
    machine exec --name "$1" -- sh -ec "for file in /storage/lineage-marker /root/lineage-marker /cache/lineage-marker /dev/shm/lineage-marker; do test \"\$(cat \"\$file\")\" = '$2'; done"
}
cleanup() {
    result=$?
    trap - EXIT
    if test -n "$server_pid"; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    for ((index=${#owned_names[@]}-1; index>=0; index--)); do
        if ! machine delete --name "${owned_names[index]}" --force; then
            result=1
        fi
    done
    printf 'inherited_chain_exit=%s retained_root=%s\n' "$result" "$root"
    exit "$result"
}
trap cleanup EXIT
source=chain-root
owned_names+=("$source")
truncate -s 1G "$root/cache.raw"
machine create --name "$source" --cpus 2 --mem 512 --storage 1 --overlay 1 --cache-disk "$root/cache.raw:/cache"
machine start --name "$source" --branchable
for cycle in $(seq 1 4); do
    for step in $(seq 1 9); do
        stamp="cycle-$cycle-step-$step"
        machine exec --name "$source" -- sh -ec "for file in /storage/lineage-marker /root/lineage-marker /cache/lineage-marker /dev/shm/lineage-marker; do echo '$stamp' >\"\$file\"; done"
        leaf="chain-leaf-$cycle-$step"
        owned_names+=("$leaf")
        machine branch --from "$source" --name "$leaf"
        check_markers "$leaf" "$stamp"
        machine exec --name "$leaf" -- sh -ec "for file in /storage/lineage-marker /root/lineage-marker /cache/lineage-marker /dev/shm/lineage-marker; do echo 'child-$cycle-$step' >\"\$file\"; done"
        check_markers "$source" "$stamp"
        if test "$step" -lt 9; then
            machine delete --name "$leaf" --force
            unset 'owned_names[${#owned_names[@]}-1]'
        fi
    done
    next="chain-golden-$cycle"
    owned_names+=("$next")
    machine branch --from "$source" --name "$next" --branchable "${golden_flags[@]}"
    check_markers "$next" "$stamp"
    source="$next"
done
for cycle in $(seq 1 4); do
    check_markers "chain-leaf-$cycle-9" "child-$cycle-9"
done
guest_port=$(python3 -c 'import socket; server = socket.socket(); server.bind(("127.0.0.1", 0)); print(server.getsockname()[1])')
"$binary" serve start --listen "unix://$root/api.sock" --guest-rollout-port "$guest_port" >"$root/server.log" 2>&1 &
server_pid=$!
for attempt in $(seq 1 1200); do
    if test -S "$root/api.sock"; then break; fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$root/server.log" >&2
        exit 1
    fi
    sleep .1
done
if ! test -S "$root/api.sock"; then
    printf 'API server did not become ready within 120 seconds\n' >&2
    cat "$root/server.log" >&2
    exit 1
fi
python3 - "$SMOLVM_DATA_DIR/.cache/smolvm/vms" "$root/api.sock" "${owned_names[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

disks = [disk for role in ("storage", "overlay", "cache") for disk in pathlib.Path(sys.argv[1]).glob(f"*/{role}.qcow2")]
assert disks, "no live storage chains found"
standalone_generation = False
maximum_depths = {}
for disk in disks:
    result = subprocess.run(
        ["qemu-img", "info", "--force-share", "--backing-chain", "--output=json", str(disk)],
        capture_output=True, text=True, check=True,
    )
    layers = json.loads(result.stdout)
    depth = len(layers) - 1
    assert depth < 32, (disk, depth)
    maximum_depths[disk.parent.name] = max(maximum_depths.get(disk.parent.name, 0), depth)
    standalone_generation |= any(
        "/d/" in layer["filename"] and "backing-filename" not in layer
        for layer in layers
    )
    print(f"{disk.parent.name}/{disk.name}: backingDepth={depth}")
assert standalone_generation, "inherited compaction did not produce a standalone generation"
for name in sys.argv[3:]:
    result = subprocess.check_output([
        "curl", "--silent", "--show-error", "--fail", "--unix-socket", sys.argv[2],
        f"http://localhost/api/v1/machines/{name}",
    ], text=True)
    response = json.loads(result)
    expected = maximum_depths[hashlib.sha256(name.encode()).hexdigest()[:16]]
    assert response["diskChainDepth"] == expected, (name, response, expected)
    print(f"GET {name}: diskChainDepth={expected}")
print("PASS: 40 live branches, four golden cycles; storage, overlay, cache and RAM isolated")
PY
