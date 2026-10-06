#!/usr/bin/env bash
# Prove the install can actually boot a VM. This is the step that decides
# whether smolvm works here; `smolvm --version` printing a number does not.
#
# Runs one ephemeral alpine VM and asserts a marker the guest printed and that
# the guest kernel is not the host's. Run cleanup.sh afterwards.
#
# usage: verify-boot.sh [--image <ref>]   (default alpine)
#   --image <ref>  the image to boot, for example mirror.gcr.io/library/alpine
#                  or public.ecr.aws/docker/library/alpine when Docker Hub
#                  refuses with TOOMANYREQUESTS

set -uo pipefail

IMAGE="alpine"
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

host_kernel="$(uname -sr)"
marker="BOOTED_OK"

out="$("$SMOLVM" machine run --mem 2048 --net --image "$IMAGE" -- \
      sh -c "echo $marker && uname -srm" 2>&1)"
printf '%s\n' "$out" | sed 's/^/  /'

fail=0

# Assert the marker, not the exit code. smolvm exits zero on paths where the
# guest never ran the command.
if printf '%s' "$out" | grep -q "^$marker$"; then
    printf 'guest_ran=yes\n'
else
    printf 'guest_ran=no\n'
    fail=1
fi

guest_kernel="$(printf '%s' "$out" | grep -m1 '^Linux ' | awk '{print $1" "$2}')"
printf 'guest_kernel=%s\n' "${guest_kernel:-none}"
printf 'host_kernel=%s\n' "$host_kernel"
if [ -n "$guest_kernel" ] && [ "$guest_kernel" != "$host_kernel" ]; then
    printf 'is_a_vm=yes\n'
else
    printf 'is_a_vm=no\n'
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    printf 'result=boot_ok\n'
else
    printf 'result=boot_failed\n'
    printf 'next: read the failure before cleaning up, because the evidence is deleted with the VM directory.\n'
    if printf '%s' "$out" | grep -q 'TOOMANYREQUESTS'; then
        printf '  - "TOOMANYREQUESTS" is Docker Hub refusing anonymous pulls from this address, not the install. Boot the same image from a mirror: verify-boot.sh --image mirror.gcr.io/library/alpine, or public.ecr.aws/docker/library/alpine.\n'
    fi
    printf '  - "agent did not become ready within 30 seconds" is usually host load or a guest too large for this host, not the install. The 30s limit is fixed and no flag raises it for machine run or machine start; retry with a smaller --mem to tell the two apart.\n'
    printf '  - "krun_start_enter returned: -22" on macOS is almost always the socket path length, not the disks its text names. Run preflight.sh and read socket_path_status.\n'
    printf '  - the boot child sends its own output to /dev/null. To see the real failure, copy <vm-dir>/boot-config.json in a loop while a start is in flight (the child deletes it as soon as it reads it) and run: smolvm-bin _boot-vm <copy>\n'
fi

exit "$fail"
