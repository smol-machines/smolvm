#!/usr/bin/env bash
# Run an untrusted command against a repo it must not modify, with no network,
# and collect its artifacts.
#
# usage: run.sh [--repo <dir>] [--repo-path <path>] [--out <dir>] [--image <img>]
#               [--allow-host <h>]... -- <command...>
#   --repo <dir>        mounted read-only at --repo-path (default ./repo)
#   --repo-path <path>  where the repo appears in the guest (default /workspace)
#   --out  <dir>        mounted writable at /out        (default ./out)
#   --image <img>       must already be baked; see bake.sh (default python:3.12-alpine)
#   --allow-host <h>    grant egress to one host. Repeatable. Weakens the isolation
#                       and the script says so; --allow-host implies --net.
#   --route <r>         offline (default) or network-on.
#                       offline    bake once, then run with no network at all.
#                       network-on no --oci-cache, the run pulls its own image and
#                       therefore has egress for the whole run. Use it only where
#                       offline does not work: macOS before v1.20.2, where
#                       --oci-cache with any mount never boots
#                       (smol-machines/smolvm#1192), and any host that cannot give
#                       the bake helper its 8192 MiB.
#
# The VM's pid is recorded before the workload finishes, because Ctrl-C on this
# script does not stop the machine. The CLI runs in the background below, and a
# background command in a script ignores SIGINT, so the CLI and its VM keep
# running. Before v1.20.2 an interrupted CLI also leaves a cached run's VM
# behind, invisible to `machine list` (smol-machines/smolvm#1193). Cancel with
# `scripts/cleanup.sh --cancel`, never with Ctrl-C. Image seeding is off for the
# run, so the first VM process is the workload's.

set -uo pipefail

REPO="./repo"
REPO_PATH="/workspace"
OUT="./out"
IMAGE="python:3.12-alpine"
ROUTE="offline"
allow=()

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)       REPO="$2"; shift ;;
        --repo-path)  REPO_PATH="$2"; shift ;;
        --out)        OUT="$2"; shift ;;
        --image)      IMAGE="$2"; shift ;;
        --allow-host) allow+=(--allow-host "$2"); shift ;;
        --route)      ROUTE="$2"; shift ;;
        --) shift; break ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

case "$ROUTE" in
    offline|network-on) ;;
    *) printf 'unknown route: %s (offline or network-on)\n' "$ROUTE" >&2; exit 2 ;;
esac

if [ $# -eq 0 ]; then
    printf 'no command given; everything after -- is run inside the machine\n' >&2
    exit 2
fi

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

if [ ! -d "$REPO" ]; then
    printf 'repo directory not found: %s\n' "$REPO" >&2
    exit 2
fi
mkdir -p "$OUT"
REPO="$(cd "$REPO" && pwd)"
OUT="$(cd "$OUT" && pwd)"

STATE_DIR="${SMOLVM_SKILL_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/smolvm-skills}"
mkdir -p "$STATE_DIR"
PIDFILE="$STATE_DIR/throwaway-machine.vmpids"

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

before="$(list_vm_processes | awk '{print $1}' | sort)"

printf 'route=%s\n' "$ROUTE"
cache=(--oci-cache)
if [ "$ROUTE" = "network-on" ]; then
    # No host cache, so the run pulls its own image and needs the network for
    # the whole run. Say what that costs rather than letting it look equivalent.
    cache=()
    if [ "${#allow[@]}" -eq 0 ]; then
        allow=(--net)
        printf 'egress=all\n'
        printf 'note=network-on with no --allow-host gives the untrusted workload unrestricted egress for the whole run. Name the hosts it needs with --allow-host to narrow it.\n'
    else
        printf 'egress=granted %s\n' "${allow[*]}"
        printf 'note=the run also needs to reach the registry to pull its image, so the policy must include the registry hosts or the run will not start.\n'
    fi
    printf 'note=this is the weaker isolation. The offline route gives the workload no network at all; this one is open for as long as the workload runs.\n'
elif [ "${#allow[@]}" -gt 0 ]; then
    printf 'egress=granted %s\n' "${allow[*]}"
    printf 'note=--allow-host implies --net. The workload can now reach the named hosts, and a denial looks like a DNS failure rather than a policy denial.\n'
else
    printf 'egress=none\n'
fi

logfile="$STATE_DIR/throwaway-machine.lastrun.log"
SMOLVM_IMAGE_SEEDS=0 "$SMOLVM" machine run --mem 2048 ${cache[@]+"${cache[@]}"} --image "$IMAGE" \
    --volume "$REPO:$REPO_PATH:ro" \
    --volume "$OUT:/out" \
    ${allow[@]+"${allow[@]}"} \
    -- "$@" > "$logfile" 2>&1 &
cli_pid=$!

# Record the VM before waiting on it. If the caller kills this script, the pid
# in that file is the only route back to the machine.
# 90 s: long enough to see the VM appear on a host that is pulling an image,
# and bounded so a workload that finishes instantly does not stall the script.
recorded=""
waited=0
# Keep only recorded pids that are still VM processes, so --cancel never reaches a recycled one.
if [ -s "$PIDFILE" ]; then
    while read -r pid cfg; do
        [ -n "$pid" ] && grep -qx -- "$pid" <<<"$before" && printf '%s %s\n' "$pid" "$cfg"
    done < "$PIDFILE" > "$PIDFILE.tmp"
    mv "$PIDFILE.tmp" "$PIDFILE"
fi
while [ "$waited" -lt 90 ]; do
    while read -r pid cfg; do
        [ -n "$pid" ] || continue
        case "$(printf '%s\n' "$before" | grep -c "^$pid$")" in
            0) printf '%s %s\n' "$pid" "$cfg" >> "$PIDFILE"; recorded="$pid" ;;
        esac
    done <<EOF
$(list_vm_processes)
EOF
    [ -n "$recorded" ] && break
    kill -0 "$cli_pid" 2>/dev/null || break
    sleep 1
    waited=$((waited + 1))
done

if [ -n "$recorded" ]; then
    printf 'vm_pid=%s\n' "$recorded"
    printf 'vm_pid_recorded_in=%s\n' "$PIDFILE"
else
    printf 'vm_pid=not_observed\n'
    printf 'note=the VM was not seen before the run ended, which is normal for a command that finishes in under a second. Nothing to cancel.\n'
fi

wait "$cli_pid"
rc=$?
sed 's/^/  /' "$logfile"

# On the offline route the cache-hit line is the assertion that the bake worked
# and that this run's machine pulled nothing. Without it the guest pulled, which
# means it had network, which means it was not the isolation you asked for.
if [ "$ROUTE" = "offline" ]; then
    if grep -q 'host cache hit' "$logfile"; then
        printf 'used_host_cache=yes\n'
    else
        printf 'used_host_cache=no\n'
        printf 'note=no host cache hit on the offline route. Run bake.sh first: an ordinary earlier pull does not make a later run offline-capable, because the runtime still resolves the tag through the registry.\n'
    fi
else
    printf 'used_host_cache=n_a_on_this_route\n'
fi

printf 'cli_exit=%s\n' "$rc"
printf 'next: scripts/verify.sh, then scripts/cleanup.sh --purge\n'
exit "$rc"
