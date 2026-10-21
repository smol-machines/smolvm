#!/usr/bin/env bash
# Run checkpoint.sh on an interval, in the foreground, and say whether the
# interval is long enough. For a test or a session an agent is watching; for a
# schedule that outlives the session, put checkpoint.sh under cron, a systemd
# timer or launchd instead (references/scheduling.md).
#
# usage: schedule.sh --name <machine> --store <dir> --every <seconds> --times <N>
#                    [--keep <K>] [--history <N>] [--out <dir>]

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
EVERY=""
TIMES=""
pass=()
while [ $# -gt 0 ]; do
    case "$1" in
        --every) EVERY="$2"; shift ;;
        --times) TIMES="$2"; shift ;;
        --name|--store|--keep|--history|--out|--label) pass+=("$1" "$2"); shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$EVERY" ] || [ -z "$TIMES" ]; then
    printf 'usage: schedule.sh --name <machine> --store <dir> --every <seconds> --times <N> [--keep <K>]\n' >&2
    exit 2
fi

ok=0
failed=0
longest=0
for run in $(seq 1 "$TIMES"); do
    start="$(date +%s)"
    out="$("$here/checkpoint.sh" ${pass[@]+"${pass[@]}"} 2>&1)"
    rc=$?
    took=$(( $(date +%s) - start ))
    [ "$took" -gt "$longest" ] && longest="$took"
    printf 'run=%s rc=%s took_s=%s %s\n' "$run" "$rc" "$took" "$(printf '%s\n' "$out" | grep -E '^(output|result|kept|store_size)=' | tr '\n' ' ')"
    if [ "$rc" -eq 0 ]; then ok=$((ok + 1)); else failed=$((failed + 1)); printf '%s\n' "$out" | sed 's/^/  /'; fi
    if [ "$took" -ge "$EVERY" ]; then
        printf 'note=this capture took %ss and the interval is %ss. Set the interval from the complete capture time, not the source pause.\n' "$took" "$EVERY"
    fi
    [ "$run" -lt "$TIMES" ] && sleep $(( EVERY > took ? EVERY - took : 0 ))
done
printf 'captures_ok=%s\n' "$ok"
printf 'captures_failed=%s\n' "$failed"
printf 'longest_capture_s=%s\n' "$longest"
if [ "$failed" -eq 0 ]; then printf 'result=schedule_ok\n'; else printf 'result=FAILED\n'; exit 1; fi
