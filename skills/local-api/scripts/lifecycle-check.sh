#!/usr/bin/env bash
# Drive one machine through its whole lifecycle over HTTP and assert every
# result from the response body.
#
# usage: lifecycle-check.sh [<name>]      (default smolskill-api)
#
# Reads the listen address serve-start.sh recorded. Two rules run through the
# whole script:
#
#   1. A failing guest command still returns HTTP 200. Assert exitCode from the
#      body, never the status line.
#   2. Upload files only AFTER the workload container is running. An upload
#      before that returns 200 with the path and byte count, is readable for a
#      moment, and is then gone for good.

set -uo pipefail

NAME="${1:-smolskill-api}"
here="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="${SMOLVM_SKILL_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/smolvm-skills}"

LISTEN="$(cat "$STATE_DIR/local-api.listen" 2>/dev/null)"
if [ -z "$LISTEN" ]; then
    printf 'no server recorded; run serve-start.sh first\n' >&2
    exit 2
fi

case "$LISTEN" in
    unix://*) CURLOPTS=(-s --unix-socket "${LISTEN#unix://}"); BASE="http://localhost" ;;
    *)        CURLOPTS=(-s); BASE="http://$LISTEN" ;;
esac
api() { curl "${CURLOPTS[@]}" "$@"; }

fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '%s=ok (%s)\n' "$1" "$2"
    else
        printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"
        fail=1
    fi
}
jget() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get(sys.argv[1],""))' "$1"; }

# 1. Create. The field names are the schema's, not the CLI's flags: `network`,
# not `net`; `memoryMb`, not `memory`. Unknown fields are accepted with 200 and
# silently ignored, and the machine then fails two calls later with a message
# about the image. Export the spec rather than guessing:
#   smolvm serve openapi -o ./openapi.json
# `cmd` gives the machine a workload that stays up. Without it the image's own
# CMD becomes the persistent workload, and for an interpreter image that exits
# at once: the container is relaunched and an exec can land in the gap, coming
# back as exitCode 1 with an empty stdout AND an empty stderr, which is quieter
# than the CLI's equivalent failure. Seen once in this packet's own run.
created="$(api -X POST "$BASE/api/v1/machines" -H 'content-type: application/json' \
    -d "{\"name\":\"$NAME\",\"image\":\"python:3.12-alpine\",\"network\":true,\"memoryMb\":2048,\"cmd\":[\"sh\",\"-c\",\"while true; do sleep 3600; done\"]}")"
check created_state "$(printf '%s' "$created" | jget state)" created
"$here/cleanup.sh" --record "$NAME"

# 2. Start.
started="$(api -X POST "$BASE/api/v1/machines/$NAME/start" -H 'content-type: application/json' -d '{}')"
check started_state "$(printf '%s' "$started" | jget state)" running

# 3. Wait for the workload container by asserting a value it produced. This is
# the gate the upload below depends on.
# 120 s: six times the slowest workload-container start observed while building
# this packet, on the slower of the two hosts.
ready=no
waited=0
while [ "$waited" -lt 120 ]; do
    out="$(api -X POST "$BASE/api/v1/machines/$NAME/exec" -H 'content-type: application/json' \
        -d '{"command":["sh","-c","echo WORKLOAD_READY"]}' | jget stdout)"
    case "$out" in WORKLOAD_READY*) ready=yes; break ;; esac
    sleep 1
    waited=$((waited + 1))
done
printf 'workload_ready_after_s=%s\n' "$waited"
check workload_ready "$ready" yes

# 4. Exec, asserting exitCode from the body.
execd="$(api -X POST "$BASE/api/v1/machines/$NAME/exec" -H 'content-type: application/json' \
    -d '{"command":["sh","-c","echo API_EXEC_OK; uname -s"]}')"
check exec_exit_code "$(printf '%s' "$execd" | jget exitCode)" 0
case "$(printf '%s' "$execd" | jget stdout)" in
    API_EXEC_OK*) printf 'exec_stdout=ok\n' ;;
    *) printf 'exec_stdout=FAIL actual=%s\n' "$(printf '%s' "$execd" | jget stdout)"; fail=1 ;;
esac

# A command that fails inside the guest is still HTTP 200. Prove the assertion
# that catches it actually catches it.
failing="$(api -X POST "$BASE/api/v1/machines/$NAME/exec" -H 'content-type: application/json' \
    -d '{"command":["sh","-c","exit 3"]}')"
check failing_exec_exit_code "$(printf '%s' "$failing" | jget exitCode)" 3

# 5. Stream. One event per line, then a terminal exit event.
# shellcheck disable=SC2016  # $i is the guest shell's loop variable
stream="$(api -N -X POST "$BASE/api/v1/machines/$NAME/exec/stream" -H 'content-type: application/json' \
    -d '{"command":["sh","-c","for i in 1 2 3; do echo line$i; sleep 1; done"]}')"
check stream_lines "$(printf '%s' "$stream" | grep -c '^data: line')" 3
case "$stream" in *'event: exit'*) printf 'stream_exit_event=ok\n' ;; *) printf 'stream_exit_event=FAIL\n'; fail=1 ;; esac

# 6. Files, now that the container is up. Absolute path, URL-encoded.
api -X PUT "$BASE/api/v1/machines/$NAME/files/%2Ftmp%2Fabs.txt" --data-binary 'PAYLOAD123' >/dev/null
check file_roundtrip "$(api "$BASE/api/v1/machines/$NAME/files/%2Ftmp%2Fabs.txt")" PAYLOAD123

# 7. Stop and delete. Delete machines BEFORE the server goes away: shutting the
# server down does not stop them, it orphans them.
api -X POST "$BASE/api/v1/machines/$NAME/stop" -H 'content-type: application/json' -d '{}' >/dev/null
api -X DELETE "$BASE/api/v1/machines/$NAME" >/dev/null
check machines_empty "$(api "$BASE/api/v1/machines")" '{"machines":[]}'

if [ "$fail" -eq 0 ]; then printf 'result=lifecycle_ok\n'; else printf 'result=FAILED\n'; fi
exit "$fail"
