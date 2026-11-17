#!/usr/bin/env bash
# One capture of a running machine into a checkpoint store, under a unique name,
# then optional retention. This is the command a timer runs: smolvm has no
# checkpoint scheduler and no retention of its own.
#
# usage: checkpoint.sh --name <machine> --store <dir> [--out <dir>] [--label <word>]
#                      [--keep <K>] [--history <N>]
#   --store <dir>    the checkpoint store, created if missing
#   --out <dir>      where the checkpoint directories go (default: the store's
#                    parent); must be on the same filesystem as the store
#   --label <word>   goes into the output name (default: ckpt)
#   --keep <K>       keep the K newest (K at least 1) checkpoints with this label
#                    in --out, delete the older ones, then run checkpoint-prune
#   --history <N>    earlier generations each new checkpoint retains (smolvm's
#                    default is 32). Retention frees space only for generations
#                    no kept checkpoint still retains, so bound this too.
#
# What it enforces, each from the engine's own documentation of periodic use:
#   - one capture at a time per source: a run that finds another in progress
#     exits 3 without capturing
#   - a unique output each time: <name>-<label>-<UTC timestamp>.smolcheckpoint
#   - the previous checkpoint stays until the new one is published, and
#     "published" is read back from checkpoint-log, not taken from the exit code
#   - retention removes whole checkpoint directories, then prunes the store

set -uo pipefail

NAME=""
STORE=""
OUT=""
LABEL="ckpt"
KEEP=""
HISTORY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --name)    NAME="$2"; shift ;;
        --store)   STORE="$2"; shift ;;
        --out)     OUT="$2"; shift ;;
        --label)   LABEL="$2"; shift ;;
        --keep)    KEEP="$2"; shift ;;
        --history) HISTORY="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$NAME" ] || [ -z "$STORE" ]; then
    printf 'usage: checkpoint.sh --name <machine> --store <dir> [--out <dir>] [--keep <K>] [--history <N>]\n' >&2
    exit 2
fi
if [ -n "$KEEP" ]; then
    case "$KEEP" in
        *[!0-9]*) printf 'result=FAILED --keep takes a whole number of at least 1, not %s\n' "$KEEP"; exit 2 ;;
    esac
    [ "$KEEP" -ge 1 ] || { printf 'result=FAILED --keep takes a whole number of at least 1, not %s\n' "$KEEP"; exit 2; }
fi
STAMP_GLOB='[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z'

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

mkdir -p "$STORE"
STORE="$(cd "$STORE" && pwd)"
[ -n "$OUT" ] || OUT="$(dirname "$STORE")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# One capture at a time per source. mkdir is atomic on every filesystem this
# runs on, and macOS has no flock(1). A lock whose owner is gone is taken over.
LOCK="$STORE/.smolskill-capture-$NAME.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
    owner="$(cat "$LOCK/pid" 2>/dev/null)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
        printf 'result=skipped\n'
        printf 'note=a capture of %s is still running (pid %s). Run one capture at a time per source: overlapping captures compete for memory and I/O and finish no sooner. Lengthen the interval.\n' "$NAME" "$owner"
        exit 3
    fi
    rm -rf "$LOCK"
    mkdir "$LOCK" || { printf 'result=FAILED could not take the capture lock %s\n' "$LOCK"; exit 1; }
fi
printf '%s\n' "$$" > "$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="$OUT/$NAME-$LABEL-$stamp.smolcheckpoint"
if [ -e "$output" ]; then
    printf 'result=FAILED %s already exists; smolvm never overwrites an output, and two captures in one second collide on this name\n' "$output"
    exit 1
fi

hist=()
[ -n "$HISTORY" ] && hist=(--history "$HISTORY")

start="$(date +%s)"
out="$("$SMOLVM" machine checkpoint --name "$NAME" --store "$STORE" --output "$output" ${hist[@]+"${hist[@]}"} 2>&1)"
rc=$?
end="$(date +%s)"
printf '%s\n' "$out" | sed 's/^/  /'
printf 'output=%s\n' "$output"
printf 'capture_s=%s\n' "$((end - start))"

# The exit code is not the assertion. A checkpoint is usable once the store
# lists it as its own generation, so read that back.
log="$("$SMOLVM" machine checkpoint-log "$output" 2>&1)"
if [ "$rc" -ne 0 ] || ! printf '%s' "$log" | grep -q '(this checkpoint)'; then
    printf 'published=no\n'
    printf 'result=FAILED the capture did not publish; the previous checkpoint is untouched\n'
    case "$out" in
        *"no file-backed regions"*|*"requires file-backed guest RAM"*)
            printf 'note=on macOS a stored checkpoint needs the machine started with machine start --branchable, and this one was not. The flag cannot be turned on for a running machine.\n' ;;
        *"No space left"*)
            printf 'note=the disk is full. A failed capture publishes nothing, so delete old checkpoints and run machine checkpoint-prune before the next attempt.\n' ;;
    esac
    exit 1
fi
printf 'published=yes\n'
printf 'generation=%s\n' "$(printf '%s\n' "$log" | awk '$1=="~0"{print $2}')"
printf 'generations_retained=%s\n' "$(printf '%s\n' "$log" | grep -c '^~')"

# Retention: only after the new checkpoint is published, and by whole
# directory. Output names sort by time because the stamp is UTC and fixed width,
# and a glob expands sorted and unsplit, so the oldest come first and a space in
# the path stays inside one name. Matching the stamp's shape keeps another label
# that starts with this one, such as ckpt-daily, out of the count.
if [ -n "$KEEP" ]; then
    set -- "$OUT/$NAME-$LABEL"-$STAMP_GLOB.smolcheckpoint
    [ -e "$1" ] || set --
    while [ "$#" -gt "$KEEP" ]; do
        rm -rf -- "$1" && printf 'deleted=%s\n' "$1"
        shift
    done
    "$SMOLVM" machine checkpoint-prune --store "$STORE" 2>&1 | sed 's/^/  /'
    set -- "$OUT/$NAME-$LABEL"-$STAMP_GLOB.smolcheckpoint
    [ -e "$1" ] || set --
    printf 'kept=%s\n' "$#"
fi

printf 'store_size=%s\n' "$(du -sh "$STORE" 2>/dev/null | cut -f1)"
printf 'result=captured\n'
