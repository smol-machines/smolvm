#!/usr/bin/env bash
# Prove the host is clean after a teardown. Every check asserts a value rather
# than an exit code, because the commands teardown runs report success while
# leaving state behind.
#
# usage: verify-clean.sh [--protected <dir>]... [--since <date>]
#   --protected <dir>  assert nothing under <dir> was written on or after --since.
#                      Repeatable. Point it at the prefix, data and cache directories
#                      of a real installation you ran beside: that is how you show a
#                      test under an isolated HOME did not reach it.
#                      Omitted, the check is reported as not run rather than passed.
#   --since <date>     the cutoff for --protected (default: today)

set -uo pipefail

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
since="$(date +%F)"
protected=()
while [ $# -gt 0 ]; do
    case "$1" in
        --protected) protected+=("$2"); shift ;;
        --since)     since="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf '%s=ok\n' "$1"
    else
        printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"
        fail=1
    fi
}

if [ -n "$SMOLVM" ]; then
    if "$SMOLVM" machine list 2>&1 | grep -q 'No machines found'; then
        check machines clean clean
    else
        check machines dirty clean
    fi
else
    printf 'machines=skipped (smolvm not on PATH; it may already be uninstalled)\n'
fi

case "$(uname -s)" in
    Darwin) cache_dir="$HOME/Library/Caches/smolvm" ;;
    *)      cache_root="${SMOLVM_DATA_DIR:+$SMOLVM_DATA_DIR/.cache}"
            cache_dir="${cache_root:-${XDG_CACHE_HOME:-$HOME/.cache}}/smolvm" ;;
esac
VMS_DIR="${SMOLVM_VMS_DIR:-$cache_dir/vms}"
SMOLVM_PREFIX="${SMOLVM_PREFIX:-$HOME/.smolvm}"
if [ -n "${SMOLVM:-}" ]; then
    case "$(readlink "$SMOLVM" 2>/dev/null || printf '%s' "$SMOLVM")" in
        "$SMOLVM_PREFIX"/*) ;;
        *) printf 'note=%s is not under %s, so the process scan cannot see its forked VMs (all of its VMs on macOS); set SMOLVM_PREFIX to its directory\n' "$SMOLVM" "$SMOLVM_PREFIX" ;;
    esac
fi

# List this HOME's VM processes as "pid marker". The plain run path execs a
# `_boot-vm` child that carries its boot config; the pack-run path forks one that
# carries none. Linux names both `libkrun VM`, or `VM:<hostname>` when HOSTNAME
# is exported; on macOS the executable path and the parent chain scope the
# search. The teardown packet's traps have the why.
list_vm_processes() {
    case "$(uname -s)" in
        Linux)
            for p in /proc/[0-9]*; do
                case "$(cat "$p/comm" 2>/dev/null)" in "libkrun VM"|VM:*) ;; *) continue ;; esac
                pid="${p#/proc/}"
                cfg="$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | sed -n '3p')"
                case "$cfg" in
                    "$VMS_DIR"/*) printf '%s %s\n' "$pid" "$cfg"; continue ;;
                esac
                case "$(readlink "$p/exe" 2>/dev/null)" in
                    "$SMOLVM_PREFIX"/*) printf '%s forked-under %s\n' "$pid" "$SMOLVM_PREFIX" ;;
                esac
            done
            ;;
        Darwin)
            # shellcheck disable=SC2009  # pgrep -f would match this script.
            procs="$(ps -axo pid=,ppid=,command= 2>/dev/null)"
            printf '%s\n' "$procs" | while read -r pid ppid rest; do
                case "$rest" in "$SMOLVM_PREFIX"/smolvm-bin*) ;; *) continue ;; esac
                case "$rest" in
                    *" _boot-vm "*) printf '%s %s\n' "$pid" "${rest#* _boot-vm }"; continue ;;
                esac
                # An orphan counts only if it is a run; a fork has its parent's command line.
                if [ "$ppid" = 1 ]; then
                    case "$rest" in
                        *" machine run "*|*" vm run "*|*" pack run "*)
                            printf '%s orphaned-under %s\n' "$pid" "$SMOLVM_PREFIX" ;;
                    esac
                else
                    parent="$(printf '%s\n' "$procs" | while read -r q qp qrest; do [ "$q" = "$ppid" ] && { printf '%s' "$qrest"; break; }; done)"
                    [ "$parent" = "$rest" ] && printf '%s forked-under %s\n' "$pid" "$SMOLVM_PREFIX"
                fi
            done
            ;;
    esac
}

# _shared is the Linux shared pack store, _restore-base the clone of the last
# restored checkpoint, _restore-checkpoints the cache of recent restores that
# replaced it in v1.22.0, and checkpoint-unpack their scratch area, none of them a
# machine. Excluding them is what makes this a leak check rather than a false
# alarm; the two restore caches are reported, since they hold guest memory and disks.
# An empty directory holds no state and is reported apart from the check.
if [ -d "$cache_dir/vms" ]; then
    left="$(find "$cache_dir/vms" -mindepth 1 -maxdepth 1 -type d ! -empty ! -name _shared ! -name _restore-base ! -name _restore-checkpoints ! -name checkpoint-unpack 2>/dev/null | wc -l | tr -d ' ')"
    empty="$(find "$cache_dir/vms" -mindepth 1 -maxdepth 1 -type d -empty ! -name checkpoint-unpack 2>/dev/null | wc -l | tr -d ' ')"
    [ "$empty" != 0 ] && printf 'empty_vm_dirs=%s (no state in them; not counted)\n' "$empty"
else
    left=0
fi
if [ -d "$cache_dir/vms/_restore-checkpoints" ]; then
    printf 'restore_cache=present %s (recently restored checkpoints'"'"' memory and disks; machine create --from --restore-cache-entries 0 turns it off)\n' "$(du -sh "$cache_dir/vms/_restore-checkpoints" 2>/dev/null | cut -f1)"
fi
if [ -d "$cache_dir/vms/_restore-base" ]; then
    printf 'restore_base=present %s (the last restored checkpoint'"'"'s memory and disks; rm -rf it once no restore is running)\n' "$(du -sh "$cache_dir/vms/_restore-base" 2>/dev/null | cut -f1)"
fi
check vm_dirs "$left" 0
if [ "$left" != 0 ]; then
    printf 'note=a boot that timed out or was killed leaves its VM directory; run smolvm serve start once to reclaim it, then check again\n'
fi

procs="$(list_vm_processes | grep -c . )"
check vm_processes "$procs" 0

# Proof that a run under an isolated HOME left a real installation alone. Silence
# here would read as a pass, so an unchecked run says so.
for dir in ${protected[@]+"${protected[@]}"}; do
    if [ ! -d "$dir" ]; then
        printf 'protected_untouched_since_%s:%s=FAIL not a directory\n' "$since" "$dir"; fail=1; continue
    fi
    touched="$(find "$dir" -newermt "$since" 2>/dev/null | wc -l | tr -d ' ')"
    check "protected_untouched_since_$since:$dir" "$touched" 0
done
[ "${#protected[@]}" -eq 0 ] && printf 'protected=not_checked (pass --protected <dir> to assert a real install was untouched)\n'

# Every check above is scoped to this HOME. Name it, so a result read later says
# which profile it describes and cannot be mistaken for a statement about the host.
printf 'audited_home=%s\n' "$HOME"
printf 'scanned_prefix=%s\n' "$SMOLVM_PREFIX"
if [ "$fail" -eq 0 ]; then printf 'result=clean\n'; else printf 'result=dirty\n'; fi
exit "$fail"
