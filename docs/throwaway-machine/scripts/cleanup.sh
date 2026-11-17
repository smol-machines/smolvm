#!/usr/bin/env bash
# Cancel or clean up a run, then prove nothing is left running.
#
# usage: cleanup.sh [--cancel] [--purge]
#   --cancel   kill the VMs run.sh recorded. THIS IS THE PACKET'S CANCEL.
#              Ctrl-C on run.sh is not: it returns the shell to you and leaves
#              the CLI and its VM running until the untrusted workload finishes
#              on its own. Before v1.20.2 Ctrl-C on the CLI itself leaves a
#              cached run's VM running too, invisible to `machine list`
#              (smol-machines/smolvm#1193).
#   --purge    remove the recorded-pid file once nothing is left
#
# With no flags it waits, asserts the machine list is empty, and reports any VM
# process still alive under this HOME's state.

set -uo pipefail

PACKET="throwaway-machine"

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

# With SMOLVM_DATA_DIR set, smolvm runs with HOME there on Linux, so its cache
# is under .cache in it.
case "$(uname -s)" in
    Darwin) VMS_DIR="$HOME/Library/Caches/smolvm/vms" ;;
    *)      cache_root="${SMOLVM_DATA_DIR:+$SMOLVM_DATA_DIR/.cache}"
            VMS_DIR="${cache_root:-${XDG_CACHE_HOME:-$HOME/.cache}}/smolvm/vms" ;;
esac
VMS_DIR="${SMOLVM_VMS_DIR:-$VMS_DIR}"
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

# 1. Cancel: kill exactly the VMs run.sh recorded, and only those.
if [ "$cancel" -eq 1 ]; then
    if [ -s "$PIDFILE" ]; then
        # A recorded pid is killed only while it is still a VM process.
        live=" $(list_vm_processes | awk '{print $1}' | tr '\n' ' ') "
        while read -r pid cfg; do
            [ -n "$pid" ] || continue
            case "$live" in
                *" $pid "*) kill -9 "$pid" 2>/dev/null && printf 'cancelled=%s config=%s\n' "$pid" "$cfg" ;;
                *) printf 'already_gone=%s\n' "$pid" ;;
            esac
        done < "$PIDFILE"
    else
        printf 'cancelled=none_recorded\n'
    fi
fi

# 2. An ephemeral machine's entry retires after the run returns, not with it, so
# an immediate assertion fails on a healthy host. This is the single most likely
# false failure in a scripted run.
printf 'waiting=up to 20s for ephemeral entries to retire before asserting\n'
waited=0
listing="$("$SMOLVM" machine list 2>&1)"
while ! grep -q 'No machines found' <<<"$listing" && [ "$waited" -lt 20 ]; do
    sleep 1; waited=$((waited + 1))
    listing="$("$SMOLVM" machine list 2>&1)"
done
printf 'waited=%ss\n' "$waited"

# 3. Assert values.
if grep -q 'No machines found' <<<"$listing"; then
    printf 'machines=clean\n'
else
    printf 'machines=remaining\n'
    printf '%s\n' "$listing" | sed 's/^/  /'
    printf 'note=this packet did not create these, so it will not delete them. By name:\n'
    printf '  smolvm machine stop --name <NAME> && smolvm machine delete --name <NAME> --force\n'
    printf '  add --cascade for a machine that was branched from another\n'
fi

# `_shared` is the Linux shared pack store, written by machine create --from and
# checkpoint restores. It is cache, not residue, so counting it as a leak gives
# a false positive.
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
# offline route. Report both places it can live: `init-layers` beside the VM
# state, and the pack cache, which is where a v1.14.2 bake landed on macOS.
case "$(uname -s)" in
    Darwin) PACK_CACHE="$HOME/Library/Caches/smolvm-pack" ;;
    *)      cache_root="${SMOLVM_DATA_DIR:+$SMOLVM_DATA_DIR/.cache}"
            PACK_CACHE="${cache_root:-${XDG_CACHE_HOME:-$HOME/.cache}}/smolvm-pack" ;;
esac
INIT_LAYERS="$(dirname "$VMS_DIR")/init-layers"
if [ -d "$INIT_LAYERS" ]; then
    printf 'image_cache_init_layers=%s\n' "$(du -sk "$INIT_LAYERS" 2>/dev/null | awk '{printf "%dMB", $1/1024}')"
else
    printf 'image_cache_init_layers=absent\n'
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
