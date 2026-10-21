#!/usr/bin/env bash
# Pack an image into a portable artifact.
#
# usage: pack-image.sh [<image>] [<output>]
#   image   default alpine
#   output  default ./from-image, and it names the STUB, not the sidecar
#
# This path pulls the image in its own temporary VM, fixed at 4 vCPUs and
# 8192 MiB on every release read; --mem sets the artifact's memory, not that
# VM's. preflight.sh reports it as image_vm_memory_ok.

set -uo pipefail

IMAGE="${1:-alpine}"
OUT="${2:-./from-image}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

# `--output` names the stub. Passing a .smolmachine here fails immediately, and
# the error is good, but there is no reason to meet it.
case "$OUT" in
    *.smolmachine)
        printf 'output=%s\n' "$OUT"
        printf 'result=FAILED --output names the stub, not the sidecar. The sidecar is created for you as <output>.smolmachine, so pass --output %s instead.\n' "${OUT%.smolmachine}"
        exit 2
        ;;
esac

start="$(date +%s)"
out="$("$SMOLVM" pack create --image "$IMAGE" --output "$OUT" 2>&1)"
rc=$?
elapsed=$(( $(date +%s) - start ))
printf '%s\n' "$out" | sed 's/^/  /'

printf 'image=%s\n' "$IMAGE"
printf 'elapsed_s=%s\n' "$elapsed"

# Assert the exit code and the artifact: files an earlier run left at OUT pass
# the file tests on their own.
if [ "$rc" -ne 0 ] || [ ! -f "$OUT" ] || [ ! -f "$OUT.smolmachine" ]; then
    printf 'result=FAILED rc=%s (pack create failed, or the stub or sidecar is missing)\n' "$rc"
    exit 1
fi

reported_kb="$(printf '%s' "$out" | sed -n 's/.*stub: \([0-9]*\)KB.*/\1/p' | head -1)"
actual_kb=$(( $(wc -c < "$OUT") / 1024 ))
printf 'stub_reported_kb=%s\n' "${reported_kb:-unknown}"
printf 'stub_actual_kb=%s\n' "$actual_kb"
if [ -n "${reported_kb:-}" ] && [ "$actual_kb" -gt "$reported_kb" ]; then
    printf 'stub_understated_kb=%s\n' "$(( actual_kb - reported_kb ))"
    printf 'note=pack create prints its sizes before it signs the stub (macOS) and appends the compressed runtime libraries to it, so stub: and total: understate the file by that block. Size a disk budget or an upload from the file, not from the report.\n'
fi
printf 'sidecar_kb=%s\n' "$(( $(wc -c < "$OUT.smolmachine") / 1024 ))"
printf 'result=packed\n'
