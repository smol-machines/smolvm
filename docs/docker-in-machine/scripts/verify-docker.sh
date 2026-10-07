#!/usr/bin/env bash
# Prove Docker is usable AND on the right filesystem.
#
# usage: verify-docker.sh [<name>]
#
# The df assertion is the one that matters. `docker info` succeeds while
# /var/lib/docker sits on the rootfs overlay, and the failure that follows is
# confusing and much later: overlayfs rejects the ramfs-backed rootfs as an
# upper dir for Docker's nested overlay.

set -uo pipefail

NAME="${1:-smolskill-docker}"
SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '%s=ok (%s)\n' "$1" "$2"
    else
        printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"
        fail=1
    fi
}
exec_in() { "$SMOLVM" machine exec --name "$NAME" -- "$@" 2>&1 | tr -d '\r'; }

check storage_driver "$(exec_in docker info --format '{{.Driver}}')" overlay2

# The backing device, not the path. Both readings print /var/lib/docker.
# shellcheck disable=SC2016  # the awk field reference belongs to the guest shell
check docker_root_device "$(exec_in sh -c 'df /var/lib/docker | tail -1 | awk "{print \$1}"')" /dev/vda

# Pull first, and separately. A `docker run` that pulls interleaves the pull's
# progress with the container's output, and the two streams arrive in a
# different order on different hosts, so the marker is not reliably the last
# line. Pulling first leaves the run's output alone without discarding the
# stderr that would explain a real failure.
printf 'pull=%s\n' "$(exec_in docker pull -q alpine | tail -1)"
check nested_container "$(exec_in docker run --rm alpine echo NESTED_OK)" NESTED_OK
check host_network     "$(exec_in docker run --rm --network=host alpine echo HOSTNET_OK)" HOSTNET_OK

# docker_socket = true bridges the guest's /var/run/docker.sock to a host path.
sock="$("$SMOLVM" machine data-dir --name "$NAME" 2>/dev/null)/docker.sock"
if [ -S "$sock" ]; then
    printf 'host_socket=present (%s)\n' "$sock"
else
    printf 'host_socket=absent (%s)\n' "$sock"
fi

if [ "$fail" -eq 0 ]; then printf 'result=docker_ok\n'; else printf 'result=FAILED\n'; fi
exit "$fail"
