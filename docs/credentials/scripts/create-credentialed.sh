#!/usr/bin/env bash
# Create and start a machine whose workload can use a credential it never holds.
#
# usage: create-credentialed.sh --var <HOST_ENV_VAR> --host <api.example.com>
#                               [--name <smolskill-...>] [--binding <name>] [--image <img>]
#   --var      the host environment variable holding the value; the guest gets a
#              placeholder under the same name
#   --host     the one host the value may be sent to; repeat the binding by hand
#              for more (NAME=VAR@host1,host2)
#
# The value is read from THIS process's environment when the machine starts, and
# the interceptor keeps using that one: unsetting or changing the variable later
# changes nothing until the next start. Set it in the environment of this script.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
VAR=""
HOST=""
NAME="smolskill-cred"
BINDING=""
IMAGE="alpine"
while [ $# -gt 0 ]; do
    case "$1" in
        --var)     VAR="$2"; shift ;;
        --host)    HOST="$2"; shift ;;
        --name)    NAME="$2"; shift ;;
        --binding) BINDING="$2"; shift ;;
        --image)   IMAGE="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$VAR" ] || [ -z "$HOST" ]; then
    printf 'usage: create-credentialed.sh --var <HOST_ENV_VAR> --host <api.example.com> [--name <n>]\n' >&2
    exit 2
fi
case "$NAME" in smolskill-*) ;; *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;; esac
[ -n "$BINDING" ] || BINDING="$(printf '%s' "$VAR" | tr 'A-Z_' 'a-z-')"
if [ -z "$(printenv "$VAR" 2>/dev/null)" ]; then
    printf 'result=FAILED %s is not set here, so every substituted request would answer 502 credential unavailable\n' "$VAR"
    exit 1
fi

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
[ -n "$SMOLVM" ] || { printf 'smolvm not found; set SMOLVM to its path\n' >&2; exit 2; }

# A long-lived workload, so exec has a container to run in.
if ! "$SMOLVM" machine create --name "$NAME" --mem 1024 --image "$IMAGE" \
    --credential "$BINDING=$VAR@$HOST" -- sh -c 'while true; do sleep 3600; done' 2>&1 | sed 's/^/  /'; then
    printf 'result=FAILED the machine was not created; the lines above say why\n'
    exit 1
fi
"$here/cleanup.sh" --record "$NAME"
"$SMOLVM" machine start --name "$NAME" 2>&1 | sed 's/^/  /'

for i in $(seq 1 60); do
    seen="$("$SMOLVM" machine exec --name "$NAME" -- sh -c "printenv $VAR" 2>/dev/null)"
    case "$seen" in
        SMOL_PLACEHOLDER_*)
            printf 'workload_ready_after_s=%s\n' "$i"
            printf 'guest_sees=placeholder\n'
            printf 'binding=%s host=%s\n' "$BINDING" "$HOST"
            printf 'result=up\n'
            exit 0 ;;
        "") ;;
        *)
            printf 'guest_sees=NOT_A_PLACEHOLDER\n'
            printf 'result=FAILED the guest variable is not a placeholder; stop and do not use this machine\n'
            exit 1 ;;
    esac
    sleep 1
done
printf 'result=FAILED the workload never answered\n'
exit 1
