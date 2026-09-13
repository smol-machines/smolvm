#!/usr/bin/env bash
# Prove the machine is worth keeping: that a package installed in one session is
# still there in the next, that init does not run again, and that the parts of
# the filesystem people assume persist actually do.
#
# usage: verify-persistence.sh [<name>]     (default smolskill-dev)
#
# Every check asserts a value. Asserting that an import did not crash proves
# nothing here: a system copy of the package satisfies it and tells you nothing
# about whether your install survived.

set -uo pipefail

NAME="${1:-smolskill-dev}"
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

# `start` returns before the workload container is up, and an `exec` in that
# window answers "the container `smolvm-<hash>` is not running" on stdout while
# still exiting zero. Wait for a VALUE: an empty result or a zero exit code both
# pass while the container is still coming up, which is how this window gets
# missed. Observed on a nested-virt aarch64 host, where a probe that asserted
# only an empty result let three later checks read that message as their answer.
wait_for_workload() {
    # 120 s: six times the slowest start observed while building this packet.
    # Long enough to absorb a loaded host, short enough to report a real hang.
    waited=0
    while [ "$waited" -lt 120 ]; do
        probe="$(exec_in sh -c 'echo WORKLOAD_READY')"
        if [ "$probe" = "WORKLOAD_READY" ]; then
            printf 'workload_ready_after_s=%s\n' "$waited"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    printf 'workload_ready_after_s=timeout last_probe=%s\n' "$probe"
    return 1
}

if ! wait_for_workload; then
    printf 'result=FAILED (workload container never came up)\n'
    exit 1
fi

# 1. Install something and record its version, not its presence.
"$SMOLVM" machine exec --name "$NAME" -- pip install --quiet --user requests >/dev/null 2>&1
before="$(exec_in python3 -c 'import requests; print(requests.__version__)')"
printf 'installed_version=%s\n' "$before"

# 2. Seed one file per filesystem so the stop tells them apart.
# shellcheck disable=SC2016  # $HOME must expand inside the guest, not here
"$SMOLVM" machine exec --name "$NAME" -- sh -c 'echo SURVIVES > "$HOME/keep.txt"; echo GONE > /tmp/scratch.txt' >/dev/null 2>&1
"$SMOLVM" machine exec --name "$NAME" --user root -- sh -c 'mkdir -p /storage/keep && echo SURVIVES > /storage/keep/disk.txt' >/dev/null 2>&1

# 3. Stop and come back.
"$SMOLVM" machine stop --name "$NAME" >/dev/null 2>&1
restart_out="$("$SMOLVM" machine start --name "$NAME" 2>&1)"
printf '%s\n' "$restart_out" | sed 's/^/  /'

if ! wait_for_workload; then
    fail=1
fi

if printf '%s' "$restart_out" | grep -q 'Init already completed'; then
    check init_ran_once yes yes
else
    check init_ran_once no yes
fi

after="$(exec_in python3 -c 'import requests; print(requests.__version__)')"
check package_version "$after" "$before"

# shellcheck disable=SC2016  # same: the guest resolves $HOME
check home_file    "$(exec_in sh -c 'cat "$HOME/keep.txt" 2>/dev/null')" SURVIVES
check storage_file "$(exec_in cat /storage/keep/disk.txt)" SURVIVES

# /tmp is tmpfs and is wiped by a stop. Anything a provisioning step leaves
# there is gone on the next start, while the same step's writes to $HOME or /
# persist. This is the asymmetry that surprises people.
check tmp_file "$(exec_in sh -c 'cat /tmp/scratch.txt 2>/dev/null || echo WIPED')" WIPED

check exec_user "$(exec_in id -un)" app
check workdir   "$(exec_in pwd)" /app

if [ "$fail" -eq 0 ]; then printf 'result=persistent\n'; else printf 'result=FAILED\n'; fi
exit "$fail"
