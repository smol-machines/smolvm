#!/usr/bin/env bash
# Create a persistent dev machine and bring it up for the first time.
#
# usage: create-dev-machine.sh [<name>] [<smolfile>]
#   name      default smolskill-dev (the prefix cleanup.sh will delete)
#   smolfile  default ../assets/dev.smolfile
#
# `create` is configuration only: it returns in milliseconds, pulls nothing and
# reports no failure. The pull, the init commands and any of their failures all
# land on the first `start`, so a fast create is not evidence that anything works.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-smolskill-dev}"
SMOLFILE="${2:-$here/../assets/dev.smolfile}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

case "$NAME" in
    smolskill-*) ;;
    *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;;
esac

# The Smolfile mounts ./src, which is relative to the working directory.
mkdir -p ./src

# Give the machine a workload that stays up. Without a command, `create` launches
# the image's own ENTRYPOINT/CMD as the persistent workload; for an interpreter
# image such as python:3.12-alpine that command reads EOF and exits at once, the
# container is relaunched, and `exec` then intermittently answers "the container
# `smolvm-<hash>` is not running" instead of running your command. Measured on a
# nested-virt aarch64 host: 1 exec in 20 failed that way with no command, 0 in 20
# with this one, both on a fresh machine and immediately after a restart.
"$SMOLVM" machine create --name "$NAME" -s "$SMOLFILE" \
    -- sh -c 'while true; do sleep 3600; done' 2>&1 | sed 's/^/  /'
"$here/cleanup.sh" --record "$NAME"

start_out="$("$SMOLVM" machine start --name "$NAME" 2>&1)"
printf '%s\n' "$start_out" | sed 's/^/  /'

fail=0
if printf '%s' "$start_out" | grep -q 'Running .* init command'; then
    printf 'init_ran=yes\n'
else
    printf 'init_ran=no\n'
    fail=1
fi
if printf '%s' "$start_out" | grep -q "Machine '$NAME' running"; then
    printf 'machine_running=yes\n'
else
    printf 'machine_running=no\n'
    fail=1
fi

# `start` returns before the workload container is up. Wait for a VALUE: an empty
# result and a zero exit code both pass while the container is still coming up,
# so a probe that asserts either of those reports ready too early and the next
# three checks read a message as their answer.
wait_for_workload() {
    # 120 s: the slowest first start observed while building this packet was
    # under 20 s on a nested-virt aarch64 host, so this is six times the worst
    # case and still short enough that a real hang is reported, not waited on.
    waited=0
    while [ "$waited" -lt 120 ]; do
        out="$("$SMOLVM" machine exec --name "$1" -- sh -c 'echo WORKLOAD_READY' 2>&1 | tr -d '\r')"
        if [ "$out" = "WORKLOAD_READY" ]; then
            printf 'workload_ready_after_s=%s\n' "$waited"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    printf 'workload_ready_after_s=timeout last_probe=%s\n' "$out"
    return 1
}

if wait_for_workload "$NAME"; then
    printf 'workload_ready=yes\n'
else
    printf 'workload_ready=no\n'
    fail=1
fi

# init runs as root even with `user` set. Asserting the value rather than the
# absence of an error is the point: an exec that fails still leaves you guessing.
printf 'init_ran_as=%s\n' "$("$SMOLVM" machine exec --name "$NAME" --user root -- cat /init-ran-as.txt 2>&1 | tr -d '\r')"
printf 'exec_user=%s\n'   "$("$SMOLVM" machine exec --name "$NAME" -- id -un 2>&1 | tr -d '\r')"
printf 'workdir=%s\n'     "$("$SMOLVM" machine exec --name "$NAME" -- pwd 2>&1 | tr -d '\r')"

if [ "$fail" -eq 0 ]; then printf 'result=up\n'; else printf 'result=failed\n'; fi
exit "$fail"
