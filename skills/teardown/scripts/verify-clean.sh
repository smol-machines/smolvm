#!/usr/bin/env bash
# Prove the host is clean after a teardown. Every check asserts a value rather
# than an exit code, because the commands teardown runs report success while
# leaving state behind.
#
# usage: verify-clean.sh [--protected <dir>] [--since <date>]
#   --protected <dir>  assert nothing under <dir> was written on or after --since.
#                      Point it at a real installation you ran beside: that is how
#                      you show a test under an isolated HOME did not reach it.
#                      Omitted, the check is reported as not run rather than passed.
#   --since <date>     the cutoff for --protected (default: today)

set -uo pipefail

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
since="$(date +%F)"
protected=""
while [ $# -gt 0 ]; do
    case "$1" in
        --protected) protected="$2"; shift ;;
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
    *)      cache_dir="${SMOLVM_DATA_DIR:-$HOME/.cache/smolvm}" ;;
esac
VMS_DIR="${SMOLVM_VMS_DIR:-$cache_dir/vms}"
SMOLVM_PREFIX="${SMOLVM_PREFIX:-$HOME/.smolvm}"

# List this HOME's smolvm VM processes, as "pid marker".
#
# Two process shapes exist and a reaper has to catch both. The plain
# `machine run` path EXECS a child whose argv[1] is `_boot-vm` and whose argv[2]
# is its boot-config path. The pack-run path, which is `--oci-cache` or any
# `init`, FORKS without execing, so the child inherits the parent's argv and
# carries no boot-config at all. Matching `_boot-vm` alone is therefore blind to
# exactly the path whose child survives an interrupt
# (smol-machines/smolvm#1193): measured on v1.14.6, it reported "none" while two
# orphaned VMs held 234 MB each.
#
# On Linux both shapes rename themselves to `libkrun VM`, the one marker that
# covers both and that no shell can hold. macOS exposes no rename, so there the
# executable path scopes the search to this HOME and the parent chain separates
# a VM from the CLI that started it.
#
# `pgrep -f _boot-vm` is not an alternative: it matches any shell whose text
# contains that string, including this script.
list_vm_processes() {
    case "$(uname -s)" in
        Linux)
            for p in /proc/[0-9]*; do
                [ "$(cat "$p/comm" 2>/dev/null)" = "libkrun VM" ] || continue
                pid="${p#/proc/}"
                cfg="$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | sed -n '3p')"
                case "$cfg" in
                    "$VMS_DIR"/*) printf '%s %s\n' "$pid" "$cfg"; continue ;;
                esac
                # Forked shape: nothing in argv identifies it, so scope by the
                # binary it is running.
                case "$(readlink "$p/exe" 2>/dev/null)" in
                    "$SMOLVM_PREFIX"/*) printf '%s forked-under %s\n' "$pid" "$SMOLVM_PREFIX" ;;
                esac
            done
            ;;
        Darwin)
            # shellcheck disable=SC2009  # pgrep cannot return ppid and the full
            # command together, and pgrep -f matches this script's own text.
            own=" $(ps -axo pid=,command= 2>/dev/null | grep -F "$SMOLVM_PREFIX/smolvm-bin" | awk '{print $1}' | tr '\n' ' ') "
            ps -axo pid=,ppid=,command= 2>/dev/null | while read -r pid ppid rest; do
                case "$rest" in "$SMOLVM_PREFIX"/smolvm-bin*) ;; *) continue ;; esac
                case "$rest" in
                    *" _boot-vm "*) printf '%s %s\n' "$pid" "${rest#* _boot-vm }"; continue ;;
                esac
                # Forked shape: its parent is the CLI that started it, or init
                # once that CLI is gone.
                if [ "$ppid" = 1 ]; then
                    printf '%s orphaned-under %s\n' "$pid" "$SMOLVM_PREFIX"
                else
                    case "$own" in *" $ppid "*) printf '%s forked-under %s\n' "$pid" "$SMOLVM_PREFIX" ;; esac
                fi
            done
            ;;
    esac
}

# _shared is the --oci-cache image store, not residue. Excluding it is what
# makes this a leak check rather than a false alarm.
if [ -d "$cache_dir/vms" ]; then
    left="$(find "$cache_dir/vms" -mindepth 1 -maxdepth 1 -type d ! -name _shared 2>/dev/null | wc -l | tr -d ' ')"
else
    left=0
fi
check vm_dirs "$left" 0

procs="$(list_vm_processes | grep -c . )"
check vm_processes "$procs" 0

# Proof that a run under an isolated HOME left a real installation alone. Silence
# here would read as a pass, so an unchecked run says so.
if [ -n "$protected" ]; then
    touched="$(find "$protected" -newermt "$since" 2>/dev/null | wc -l | tr -d ' ')"
    check "protected_untouched_since_$since" "$touched" 0
else
    printf 'protected=not_checked (pass --protected <dir> to assert a real install was untouched)\n'
fi

if [ "$fail" -eq 0 ]; then printf 'result=clean\n'; else printf 'result=dirty\n'; fi
exit "$fail"
