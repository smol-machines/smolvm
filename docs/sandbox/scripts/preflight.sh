#!/usr/bin/env bash
# Report whether this host can run the offline sandbox shape, and whether the
# machine you are planning fits the guest's device budget.
#
# usage: preflight.sh [--mounts N] [--ports N]
#   --mounts N  how many -v mounts your run will pass (default 2: repo plus out)
#   --ports N   how many -p publishes it will pass (default 0)
#
# Read-only: starts no VM, bakes nothing, writes no smolvm state.
# Output is one key=value per line. The last line is result=ready or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.14.6"

# The guest gets eleven IRQs. Four -v mounts boot and five fail with "no more
# IRQs are available", and any published port costs one of those slots, so the
# budget is mounts plus ports. Measured on Windows Hypervisor Platform and the
# same budget on Linux.
DEVICE_BUDGET=4

emit() { printf '%s=%s\n' "$1" "$2"; }
note() { printf 'note=%s\n' "$1"; }

mounts=2
ports=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mounts) mounts="$2"; shift ;;
        --ports)  ports="$2";  shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

blocked=0

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    emit smolvm_installed no
    blocked=1
else
    emit smolvm_installed yes
    version="$("$SMOLVM" --version 2>/dev/null | awk '{print $NF}')"
    emit smolvm_version "${version:-unknown}"
fi

emit verified_version "$VERIFIED_VERSION"
if [ -n "${version:-}" ] && [ "$version" != "unknown" ]; then
    if [ "$version" = "$VERIFIED_VERSION" ]; then
        emit version_status match
    else
        newest="$(printf '%s\n%s\n' "$version" "$VERIFIED_VERSION" | sort -V | tail -1)"
        if [ "$newest" = "$version" ]; then
            emit version_status newer
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version; a sandbox is exactly where a silently changed flag matters, so check each step's output against the binary before trusting it"
        else
            emit version_status older
        fi
    fi
else
    emit version_status unknown
fi

kernel="$(uname -s)"
arch="$(uname -m)"
case "$arch" in aarch64|arm64) arch=aarch64 ;; esac

case "$kernel" in
    Darwin)
        emit platform "darwin-$arch"
        emit accel hypervisor_framework
        if [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ]; then
            emit accel_access ok
        else
            emit accel_access denied
            blocked=1
        fi
        # The offline shape is bake with --oci-cache, then run with mounts and
        # no network. On macOS that combination never boots.
        emit offline_shape unavailable
        emit offline_shape_blocker "smol-machines/smolvm#1192"
        blocked=1
        note "on macOS --oci-cache with any -v mount times out the boot, deterministically, so the offline shape this packet is built on cannot run here. Use references/macos.md, which gives a route that works and says what it costs you."
        for b in docker crane podman nerdctl; do
            if command -v "$b" >/dev/null 2>&1; then emit image_archive_tool "$b"; break; fi
        done
        ;;
    Linux)
        emit platform "linux-$arch"
        emit accel kvm
        if [ ! -e /dev/kvm ]; then
            emit accel_access missing
            blocked=1
            note "/dev/kvm does not exist; this host has no KVM"
        elif [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
            emit accel_access ok
        else
            emit accel_access denied
            blocked=1
            note "your user cannot open /dev/kvm. Fix without logging out: sudo usermod -aG kvm \$USER, then run the next command through sg kvm -c '...'"
        fi
        emit offline_shape available
        ;;
    *)
        emit platform "unsupported-$kernel"
        emit accel unknown
        emit accel_access unknown
        emit offline_shape unavailable
        blocked=1
        note "this script covers macOS and Linux. On Windows the --oci-cache bake never completes, so the offline shape is unavailable there too; see references/windows.md, written from a run and not re-run by this packet."
        ;;
esac

# The devices your planned run needs, against the budget.
emit planned_mounts "$mounts"
emit planned_ports "$ports"
emit device_budget "$DEVICE_BUDGET"
emit devices_requested "$((mounts + ports))"
if [ "$((mounts + ports))" -le "$DEVICE_BUDGET" ]; then
    emit device_budget_ok yes
else
    emit device_budget_ok no
    blocked=1
    note "mounts plus published ports exceeds the guest's device budget; the boot fails with 'no more IRQs are available'. Combine directories under one mount, or drop a port."
fi

# Ctrl-C does not stop a sandbox. Say so before anything is started, not after.
emit cancel_route "scripts/cleanup.sh --cancel"
emit interrupt_orphans_vm yes
emit interrupt_blocker "smol-machines/smolvm#1193"

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
