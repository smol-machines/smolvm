#!/usr/bin/env bash
# Create the machine and install Docker into it. The install happens on the
# first start, not on create.
#
# usage: create-docker-machine.sh [<name>] [<smolfile>]

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-smolskill-docker}"
SMOLFILE="${2:-$here/../assets/docker.smolfile}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

case "$NAME" in
    smolskill-*) ;;
    *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;;
esac

"$SMOLVM" machine create --name "$NAME" -s "$SMOLFILE" --net-backend virtio-net 2>&1 | sed 's/^/  /'
"$here/cleanup.sh" --record "$NAME"

start_out="$("$SMOLVM" machine start --name "$NAME" 2>&1)"
printf '%s\n' "$start_out" | sed 's/^/  /'

fail=0
if printf '%s' "$start_out" | grep -q "Machine '$NAME' running"; then
    printf 'machine_running=yes\n'
else
    printf 'machine_running=no\n'
    fail=1
fi

docker_version="$("$SMOLVM" machine exec --name "$NAME" -- docker --version 2>&1 | tr -d '\r')"
printf 'docker_version=%s\n' "$docker_version"
case "$docker_version" in
    "Docker version"*) ;;
    *) fail=1 ;;
esac

if [ "$fail" -eq 0 ]; then printf 'result=installed\n'; else printf 'result=failed\n'; fi
exit "$fail"
