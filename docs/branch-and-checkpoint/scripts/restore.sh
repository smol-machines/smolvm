#!/usr/bin/env bash
# Restore a checkpoint, or an earlier generation it retains, into a new machine
# and start it.
#
# usage: restore.sh --from <checkpoint> --name <new> [--at <~N|id>]
#
# The restore path is `machine create --from`; there is no `machine restore`.
# The new machine is started --branchable so it can itself be checkpointed,
# paused and branched on every host.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
FROM=""
NAME=""
AT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="$2"; shift ;;
        --name) NAME="$2"; shift ;;
        --at)   AT="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$FROM" ] || [ -z "$NAME" ]; then
    printf 'usage: restore.sh --from <checkpoint> --name <new> [--at <~N|id>]\n' >&2
    exit 2
fi
case "$NAME" in smolskill-*) ;; *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;; esac

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
[ -n "$SMOLVM" ] || { printf 'smolvm not found; set SMOLVM to its path\n' >&2; exit 2; }

at=()
[ -n "$AT" ] && at=(--at "$AT")
# create refuses a name that exists, and the listing below would then find the
# old machine, so the create's own status decides; pipefail carries it.
if ! "$SMOLVM" machine create --name "$NAME" --from "$FROM" ${at[@]+"${at[@]}"} 2>&1 | sed 's/^/  /'; then
    printf 'result=FAILED machine create --from did not succeed, so nothing was restored\n'
    exit 1
fi
# Read the list first: under pipefail, grep -q closing the pipe early can fail
# the pipeline and report a machine missing that exists.
listing="$("$SMOLVM" machine list 2>/dev/null)"
if ! printf '%s\n' "$listing" | grep -q "^$NAME "; then
    printf 'result=FAILED no machine was created\n'
    exit 1
fi
"$here/cleanup.sh" --record "$NAME"
start="$(date +%s)"
"$SMOLVM" machine start --name "$NAME" --branchable 2>&1 | sed 's/^/  /'
printf 'start_s=%s\n' "$(( $(date +%s) - start ))"
state="$("$SMOLVM" machine list 2>/dev/null | awk -v n="$NAME" '$1==n{print $2}')"
printf 'state=%s\n' "$state"
[ "$state" = running ] && printf 'result=restored\n' || { printf 'result=FAILED\n'; exit 1; }
