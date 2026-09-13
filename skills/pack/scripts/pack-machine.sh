#!/usr/bin/env bash
# Provision a machine, prove the state is in it, then pack it.
#
# usage: pack-machine.sh [<name>] [<output>] [<image>]
#   name    default smolskill-golden (the prefix cleanup.sh will delete)
#   output  default ./from-vm, naming the STUB
#   image   default python:3.12-alpine
#
# The marker written here is the whole point of the packet. A pack that lost its
# rootfs still boots, still prints a guest kernel and still exits zero, so the
# only assertion that separates a good artifact from an empty one is a value put
# into the source and read back out of the artifact. This script writes it and
# asserts it ON THE SOURCE before packing; verify-pack.sh reads it back.
#
# This path starts an exporter VM whose memory is hardcoded to 8192 MiB. If it
# fails with a ready timeout, run preflight.sh: that is the only place the
# failure gets a name.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-smolskill-golden}"
OUT="${2:-./from-vm}"
IMAGE="${3:-python:3.12-alpine}"
MARKER="PACKED_STATE_PRESENT"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

case "$NAME" in
    smolskill-*) ;;
    *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;;
esac
case "$OUT" in
    *.smolmachine) printf 'result=FAILED --output names the stub; pass %s\n' "${OUT%.smolmachine}"; exit 2 ;;
esac

# A workload that stays up, so exec does not race a relaunching container.
"$SMOLVM" machine create --name "$NAME" --net --image "$IMAGE" \
    -- sh -c 'while true; do sleep 3600; done' 2>&1 | sed 's/^/  /'
"$here/cleanup.sh" --record "$NAME"
"$SMOLVM" machine start --name "$NAME" 2>&1 | sed 's/^/  /'

# Wait for a value, not for an empty result or a zero exit code: an exec in the
# startup window answers with a message and still exits zero.
waited=0
while [ "$waited" -lt 120 ]; do
    probe="$("$SMOLVM" machine exec --name "$NAME" -- sh -c 'echo READY' 2>&1 | tr -d '\r')"
    [ "$probe" = "READY" ] && break
    sleep 1
    waited=$((waited + 1))
done
printf 'workload_ready_after_s=%s\n' "$waited"
if [ "$probe" != "READY" ]; then
    printf 'result=FAILED the machine never became usable, so there is nothing to pack\n'
    exit 1
fi

"$SMOLVM" machine exec --name "$NAME" -- sh -c "echo $MARKER > /marker.txt" >/dev/null 2>&1

# Assert on the SOURCE. Packing a machine that was never provisioned produces an
# artifact that runs fine and contains nothing, and that mistake is invisible
# until the artifact is read.
src_marker="$("$SMOLVM" machine exec --name "$NAME" -- cat /marker.txt 2>&1 | tr -d '\r')"
printf 'source_marker=%s\n' "$src_marker"
if [ "$src_marker" != "$MARKER" ]; then
    printf 'result=FAILED the source does not carry the marker, so packing it would produce an empty artifact\n'
    exit 1
fi

"$SMOLVM" machine stop --name "$NAME" 2>&1 | sed 's/^/  /'

start="$(date +%s)"
out="$("$SMOLVM" pack create --from-vm "$NAME" --output "$OUT" 2>&1)"
rc=$?
elapsed=$(( $(date +%s) - start ))
printf '%s\n' "$out" | sed 's/^/  /'
printf 'elapsed_s=%s\n' "$elapsed"

if [ ! -f "$OUT" ] || [ ! -f "$OUT.smolmachine" ]; then
    printf 'result=FAILED rc=%s\n' "$rc"
    case "$out" in
        *"did not become ready"*)
            printf 'diagnosis: the exporter VM did not come up. Its memory is hardcoded to 8192 MiB and the message never says so. Run scripts/preflight.sh and read free_memory_mib against exporter_memory_mib.\n' ;;
        *"fork clone"*)
            printf 'diagnosis: this machine is a branch child and its copy-on-write disks cannot be exported. Pack the golden it came from, or recreate the state in a machine that was never branched.\n' ;;
    esac
    exit 1
fi

printf 'sidecar_kb=%s\n' "$(( $(wc -c < "$OUT.smolmachine") / 1024 ))"
printf 'marker=%s\n' "$MARKER"
printf 'result=packed\n'
printf 'next: scripts/verify-pack.sh, which reads that marker back out of the artifact\n'
