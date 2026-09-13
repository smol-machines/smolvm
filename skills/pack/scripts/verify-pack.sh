#!/usr/bin/env bash
# Prove an artifact is worth shipping: that it runs a real VM, and for a machine
# pack that the state is inside it.
#
# usage: verify-pack.sh [--image <stub>] [--machine <stub>] [--marker <value>]
#   --image   <stub>  an artifact packed from an image   (default ./from-image)
#   --machine <stub>  an artifact packed from a machine  (default ./from-vm)
#   --marker  <value> what pack-machine.sh wrote         (default PACKED_STATE_PRESENT)
#
# Every check asserts a value. A pack that lost its rootfs still boots, still
# prints a guest kernel and still exits zero, so "it ran" proves nothing about
# what is inside it.

set -uo pipefail

IMAGE_STUB="./from-image"
MACHINE_STUB="./from-vm"
MARKER="PACKED_STATE_PRESENT"
while [ $# -gt 0 ]; do
    case "$1" in
        --image)   IMAGE_STUB="$2"; shift ;;
        --machine) MACHINE_STUB="$2"; shift ;;
        --marker)  MARKER="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
fail=0
checked=0
check() {
    if [ "$2" = "$3" ]; then
        printf '%s=ok (%s)\n' "$1" "$2"
    else
        printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"
        fail=1
    fi
}

# Where `pack run` keeps its extractions, one directory per artifact checksum.
case "$(uname -s)" in
    Darwin) PACK_CACHE="$HOME/Library/Caches/smolvm-pack" ;;
    *)      PACK_CACHE="${SMOLVM_DATA_DIR:-$HOME/.cache}/smolvm-pack" ;;
esac
cache_entries() { find "$PACK_CACHE" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' '; }

# --- the image pack: a real VM, and a cached second run ----------------------
if [ -f "$IMAGE_STUB" ]; then
    # The stub takes a subcommand. A bare `--` is rejected with a tip that does
    # not mention `run`.
    checked=$((checked + 1))
    kernel="$("$IMAGE_STUB" run -- uname -sr 2>&1 | tr -d '\r' | grep -m1 '^Linux ' | awk '{print $1}')"
    check image_pack_is_a_vm "${kernel:-none}" Linux

    # Count the cache after the first run, then again after the second. A reused
    # extraction adds nothing. Timing is not the test: wall clock on a loaded or
    # nested-virt host varies by more than the saving, so it reports a healthy
    # host as suspect.
    after_first="$(cache_entries)"
    marker2="$("$IMAGE_STUB" run -- sh -c 'echo SECOND_RUN_OK' 2>&1 | tr -d '\r' | tail -1)"
    check image_pack_second_run "$marker2" SECOND_RUN_OK
    after_second="$(cache_entries)"
    printf 'pack_cache_entries=%s\n' "$after_second"
    if [ "$after_first" -gt 0 ]; then
        check image_pack_reused_cache "$after_second" "$after_first"
    else
        printf 'image_pack_reused_cache=skipped (no pack cache at %s)\n' "$PACK_CACHE"
    fi
else
    printf 'image_pack=skipped (%s not present)\n' "$IMAGE_STUB"
fi

# --- the machine pack: the load-bearing assertion ----------------------------
if [ -f "$MACHINE_STUB" ]; then
    checked=$((checked + 1))
    got="$("$MACHINE_STUB" run -- cat /marker.txt 2>&1 | tr -d '\r' | tail -1)"
    check machine_pack_carried_rootfs "$got" "$MARKER"

    mkernel="$("$MACHINE_STUB" run -- uname -sr 2>&1 | tr -d '\r' | grep -m1 '^Linux ' | awk '{print $1}')"
    check machine_pack_is_a_vm "${mkernel:-none}" Linux

    if [ -n "$SMOLVM" ] && [ -f "$MACHINE_STUB.smolmachine" ]; then
        printf '%s\n' "--- what the artifact says it is ---"
        "$SMOLVM" pack run --sidecar "$MACHINE_STUB.smolmachine" --info 2>&1 \
            | grep -E '^(Mode|Image|Platform|CPUs|Memory|Checksum):' | sed 's/^/  /'
    fi
else
    printf 'machine_pack=skipped (%s not present)\n' "$MACHINE_STUB"
fi

# Verifying nothing is not a pass. Both stubs absent means the artifacts were
# written somewhere else, and a green line there would be the same false clean
# this packet exists to prevent.
if [ "$checked" -eq 0 ]; then
    printf 'result=nothing_verified\n'
    printf 'note=no artifact was found at %s or %s. If you packed to another path, pass --image and --machine, or this says nothing at all.\n' "$IMAGE_STUB" "$MACHINE_STUB"
    exit 2
fi

if [ "$fail" -eq 0 ]; then printf 'result=artifacts_good (%s of 2 artifacts)\n' "$checked"; else printf 'result=FAILED\n'; fi
exit "$fail"
