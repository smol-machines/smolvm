#!/usr/bin/env bash
# Branch a machine and take a checkpoint of the same point, so the state the
# children started from outlives them. A branch's captured generation lives on
# this host only; the checkpoint is the copy you can keep, export and restore.
#
# usage: branch-point.sh --from <source> --store <dir> --count <N> --name-prefix <prefix>
#        branch-point.sh --from <source> --store <dir> --name <child>
#   --count/--name-prefix  a batch. The source's workload must park in
#                          smolvm-branch-ready; the checkpoint is taken while it
#                          is parked, so it is the exact state every child starts from.
#   --name                 one child. The checkpoint is taken first and the
#                          branch follows, a second or two later, so the two
#                          points differ by whatever the source did in between.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
FROM=""
STORE=""
COUNT=""
PREFIX=""
CHILD=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from)        FROM="$2"; shift ;;
        --store)       STORE="$2"; shift ;;
        --count)       COUNT="$2"; shift ;;
        --name-prefix) PREFIX="$2"; shift ;;
        --name)        CHILD="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$FROM" ] || [ -z "$STORE" ] || { [ -z "$CHILD" ] && { [ -z "$COUNT" ] || [ -z "$PREFIX" ]; }; }; then
    printf 'usage: branch-point.sh --from <source> --store <dir> (--count <N> --name-prefix <p> | --name <child>)\n' >&2
    exit 2
fi
case "${PREFIX}${CHILD}" in
    smolskill-*) ;;
    *) printf 'children must be named smolskill-... so cleanup.sh deletes them\n' >&2; exit 2 ;;
esac

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
[ -n "$SMOLVM" ] || { printf 'smolvm not found; set SMOLVM to its path\n' >&2; exit 2; }

if [ -n "$COUNT" ]; then
    # Parked means PID 1 of the workload is the helper. pgrep -f is not a test
    # for it: it matches the sh -c that runs the check, whose text names the helper.
    parked=no
    for i in $(seq 1 120); do
        if "$SMOLVM" machine exec --name "$FROM" -- sh -c 'tr "\0" " " < /proc/1/cmdline' 2>/dev/null | grep -q '^smolvm-branch-ready'; then
            parked=yes; printf 'source_parked_after_s=%s\n' "$i"; break
        fi
        sleep 1
    done
    if [ "$parked" != yes ]; then
        printf 'result=FAILED the source never parked in smolvm-branch-ready, so a batch branch would wait for a branch point that is not coming. Its workload has to run smolvm-branch-ready -- <program> after its setup (create-source.sh --branch-ready does), or branch one child with --name.\n'
        exit 1
    fi
fi

ck="$("$here/checkpoint.sh" --name "$FROM" --store "$STORE" --label branchpoint 2>&1)"
printf '%s\n' "$ck" | sed 's/^/  /'
checkpoint="$(printf '%s\n' "$ck" | sed -n 's/^output=//p')"
if ! printf '%s' "$ck" | grep -q '^result=captured'; then
    printf 'result=FAILED no checkpoint of the branch point, so no branch was taken\n'
    exit 1
fi
printf 'checkpoint=%s\n' "$checkpoint"

if [ -n "$COUNT" ]; then
    out="$("$SMOLVM" machine branch --from "$FROM" --count "$COUNT" --name-prefix "$PREFIX" 2>&1)"
    children="$(seq 0 $((COUNT - 1)) | sed "s/^/$PREFIX-/")"
else
    out="$("$SMOLVM" machine branch --from "$FROM" --name "$CHILD" 2>&1)"
    children="$CHILD"
fi
printf '%s\n' "$out" | sed 's/^/  /'
made=0
# Read the list once: under pipefail, grep -q closing the pipe early can fail
# the pipeline and report a child missing that exists.
listing="$("$SMOLVM" machine list 2>/dev/null)"
for c in $children; do
    "$here/cleanup.sh" --record "$c"
    if printf '%s\n' "$listing" | grep -q "^$c "; then made=$((made + 1)); printf 'child=%s\n' "$c"; fi
done
# The source is frozen on some hosts after a branch and running on others; read
# which, rather than assuming.
printf 'source_state=%s\n' "$(printf '%s\n' "$listing" | awk -v n="$FROM" '$1==n{print $2}')"
if [ "$made" -eq "$(printf '%s\n' "$children" | grep -c .)" ]; then
    printf 'result=branched\n'
else
    printf 'result=FAILED %s of the children exist\n' "$made"
    exit 1
fi
