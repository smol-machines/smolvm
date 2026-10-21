#!/usr/bin/env bash
# Create and start a machine to checkpoint and branch, with state in RAM and on
# disk that a restore or a child can be checked against.
#
# usage: create-source.sh [<name>] [--branch-ready]
#   <name>          default smolskill-src; must start with smolskill- so cleanup.sh deletes it
#   --branch-ready  the workload does its setup and then parks in smolvm-branch-ready,
#                   which a batch branch (branch-point.sh --count) needs
#
# The workload keeps a counter in /tmp, which is tmpfs and therefore RAM: a
# restore or a resume that brings the counter back proves memory came back, not
# only the disk. /root/setup.txt is the disk marker. The machine is started
# --branchable because on macOS a checkpoint is refused without it and the flag
# cannot be turned on for a running machine.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
NAME="smolskill-src"
READY=0
for a in "$@"; do
    case "$a" in
        --branch-ready) READY=1 ;;
        -*) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
        *) NAME="$a" ;;
    esac
done

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi
case "$NAME" in
    smolskill-*) ;;
    *) printf 'name must start with smolskill- so cleanup.sh will delete it\n' >&2; exit 2 ;;
esac

counter='i=0; while true; do i=$((i+1)); echo $i > /tmp/ram_counter; sleep 1; done'
if [ "$READY" -eq 1 ]; then
    # setup, then park; each child continues into the program after --
    workload="echo SETUP_DONE > /root/setup.txt; echo \$RANDOM > /tmp/ram_token; exec smolvm-branch-ready -- sh -c 'echo CHILD=\$SMOLVM_BRANCH_NAME > /root/child.txt; $counter'"
else
    workload="echo SETUP_DONE > /root/setup.txt; echo \$RANDOM > /tmp/ram_token; $counter"
fi

"$SMOLVM" machine create --name "$NAME" --net --mem 1024 --image alpine -- sh -c "$workload" 2>&1 | sed 's/^/  /'
"$here/cleanup.sh" --record "$NAME"
"$SMOLVM" machine start --name "$NAME" --branchable 2>&1 | sed 's/^/  /'

# Wait for a value from the workload, not for the start command to return.
for i in $(seq 1 60); do
    v="$("$SMOLVM" machine exec --name "$NAME" -- cat /root/setup.txt 2>/dev/null)"
    if [ "$v" = "SETUP_DONE" ]; then
        printf 'workload_ready_after_s=%s\n' "$i"
        printf 'ram_token=%s\n' "$("$SMOLVM" machine exec --name "$NAME" -- cat /tmp/ram_token 2>/dev/null)"
        printf 'result=up\n'
        exit 0
    fi
    sleep 1
done
printf 'result=FAILED the workload never wrote /root/setup.txt\n'
exit 1
