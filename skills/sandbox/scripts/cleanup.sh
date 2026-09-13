#!/usr/bin/env bash
# Cancel or clean up a sandbox run, then prove nothing is left running.
#
# usage: cleanup.sh [--cancel] [--purge]
#   --cancel   kill the VMs run.sh recorded. THIS IS THE SANDBOX'S CANCEL.
#              Ctrl-C is not: it returns the shell to you and leaves the VM
#              running, invisible to `machine list`, until the untrusted
#              workload finishes on its own (smol-machines/smolvm#1193).
#   --purge    remove the recorded-pid file once nothing is left
#
# With no flags it waits, asserts the machine list is empty, and reports any VM
# process still alive under this HOME's state.

set -uo pipefail

PACKET="sandbox"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
STATE_DIR="${SMOLVM_SKILL_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/smolvm-skills}"
PIDFILE="$STATE_DIR/$PACKET.vmpids"

cancel=0
purge=0
while [ $# -gt 0 ]; do
    case "$1" in
        --cancel) cancel=1 ;;
        --purge)  purge=1 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

case "$(uname -s)" in
    Darwin) VMS_DIR="$HOME/Library/Caches/smolvm/vms" ;;
    *)      VMS_DIR="${SMOLVM_DATA_DIR:-$HOME/.cache/smolvm}/vms" ;;
esac
VMS_DIR="${SMOLVM_VMS_DIR:-$VMS_DIR}"
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

# 1. Cancel: kill exactly the VMs run.sh recorded, and only those.
if [ "$cancel" -eq 1 ]; then
    if [ -s "$PIDFILE" ]; then
        while read -r pid cfg; do
            [ -n "$pid" ] || continue
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null && printf 'cancelled=%s config=%s\n' "$pid" "$cfg"
            else
                printf 'already_gone=%s\n' "$pid"
            fi
        done < "$PIDFILE"
    else
        printf 'cancelled=none_recorded\n'
    fi
fi

# 2. An ephemeral machine's entry retires after the run returns, not with it, so
# an immediate assertion fails on a healthy host. This is the single most likely
# false failure in a scripted sandbox.
sleep 20

# 3. Assert values.
listing="$("$SMOLVM" machine list 2>&1)"
if printf '%s' "$listing" | grep -q 'No machines found'; then
    printf 'machines=clean\n'
else
    printf 'machines=remaining\n'
    printf '%s\n' "$listing" | sed 's/^/  /'
fi

# `_shared` is the image store bake.sh writes into. It is the cache, not
# residue, so counting it as a leak gives a false positive on every host that
# has ever baked.
if [ -d "$VMS_DIR" ]; then
    left="$(find "$VMS_DIR" -mindepth 1 -maxdepth 1 -type d ! -name _shared 2>/dev/null | wc -l | tr -d ' ')"
else
    left=0
fi
printf 'vm_dirs=%s\n' "$left"
if [ "$left" -gt 0 ]; then
    printf 'note=leftover VM directories are not necessarily a leak: smolvm serve start prints "Reclaimed N dangling VM data dir(es)" on startup and clears them.\n'
fi

# What a bake leaves behind is cache, not residue, and deleting it costs you the
# offline route. Report both places it can live: `_shared` under the VM state,
# and the pack cache, which is where a v1.14.2 bake actually landed on macOS.
case "$(uname -s)" in
    Darwin) PACK_CACHE="$HOME/Library/Caches/smolvm-pack" ;;
    *)      PACK_CACHE="$HOME/.cache/smolvm-pack" ;;
esac
if [ -d "$VMS_DIR/_shared" ]; then
    printf 'image_cache_shared=%s\n' "$(du -sk "$VMS_DIR/_shared" 2>/dev/null | awk '{printf "%dMB", $1/1024}')"
else
    printf 'image_cache_shared=absent\n'
fi
if [ -d "$PACK_CACHE" ]; then
    printf 'image_cache_pack=%s\n' "$(du -sk "$PACK_CACHE" 2>/dev/null | awk '{printf "%dMB", $1/1024}')"
else
    printf 'image_cache_pack=absent\n'
fi
printf 'note=both caches are kept on purpose. Removing them costs you the offline route and the next bake pays for it again.\n'

# 4. Verify: after a cancel, this is the assertion that the cancel worked.
found=0
while read -r pid cfg; do
    [ -n "$pid" ] || continue
    found=1
    printf 'vm_process=%s config=%s\n' "$pid" "$cfg"
done <<EOF
$(list_vm_processes)
EOF

if [ "$found" -eq 0 ]; then
    printf 'vm_processes=none\n'
    [ "$purge" -eq 1 ] && rm -f "$PIDFILE"
    printf 'result=clean\n'
    exit 0
fi

printf 'result=vms_still_running\n'
printf 'rerun with --cancel, after checking none of the above belongs to another session.\n'
exit 1
