#!/usr/bin/env bash
# Report whether this host can run the offline shape, and whether the
# machine you are planning fits the guest's device budget.
#
# usage: preflight.sh [--mounts N] [--ports N]
#   --mounts N  how many -v mounts your run will pass (default 2: repo plus out)
#   --ports N   how many -p publishes it will pass (default 0); any number is one device,
#               and so is any --allow-host or --allow-cidr: pass --ports 1 for those
#
# Read-only: starts no VM, bakes nothing, writes no smolvm state.
# Output is one key=value per line. The last line is result=ready or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.23.0"

# v1.20.2 fixed both issues this packet was built around (#1467): a cached run
# with a mount boots on macOS (#1192), and a cached run's VM ends with its CLI
# (#1193). Older releases still have both.
FIXED_IN="1.20.2"
at_least() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# x86_64 guests through v1.22.2 have eleven IRQs (libkrun IRQ_BASE 5 to
# IRQ_MAX 15): four -v mounts boot and five fail with "no more IRQs are
# available". Any -p, --allow-host or --allow-cidr adds one virtio-net device,
# however many ports. Measured on Windows Hypervisor Platform. v1.23.0 ships
# libkrun with IRQ_MAX 23 (#1521) and its ceiling was not measured, so the check
# applies to x86_64 through v1.22.2 only. arm64 guests have 128 IRQs.
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
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version; isolation is exactly where a silently changed flag matters, so check each step's output against the binary before trusting it"
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
        # no network. Before v1.20.2 that combination never boots on macOS.
        if [ -n "${version:-}" ] && [ "$version" != "unknown" ] && at_least "$version" "$FIXED_IN"; then
            emit offline_shape available
        else
            emit offline_shape unavailable
            emit offline_shape_blocker "smol-machines/smolvm#1192, fixed in v$FIXED_IN"
            blocked=1
            note "before v$FIXED_IN, on macOS --oci-cache with any -v mount times out the boot, deterministically, so the offline shape this packet is built on cannot run here. Upgrade, or use references/macos.md, which gives a route that works on older releases and says what it costs you."
            for b in docker crane podman nerdctl; do
                if command -v "$b" >/dev/null 2>&1; then emit image_archive_tool "$b"; break; fi
            done
        fi
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
        note "this script covers macOS and Linux. On Windows the --oci-cache bake did not complete on v1.22.2, so the offline shape is unavailable there too; see references/windows.md."
        ;;
esac

# The devices your planned run needs, against the budget. Any number of ports
# shares one network device.
net_devices=0
[ "$ports" -gt 0 ] && net_devices=1
emit planned_mounts "$mounts"
emit planned_ports "$ports"
emit devices_requested "$((mounts + net_devices))"
if [ "$arch" = "x86_64" ] && [ -n "${version:-}" ] && [ "$version" != "unknown" ] && ! at_least "$version" "1.22.3"; then
    emit device_budget "$DEVICE_BUDGET"
    if [ "$((mounts + net_devices))" -le "$DEVICE_BUDGET" ]; then
        emit device_budget_ok yes
    else
        emit device_budget_ok no
        blocked=1
        note "on x86_64 through v1.22.2 more than four devices beyond the base set fail with 'no more IRQs are available'; a published port or an --allow-host grant is one. Combine directories under one mount."
    fi
else
    emit device_budget_ok not_limiting
fi

# Ctrl-C does not stop a run started by run.sh on any release: it backgrounds
# the CLI, and a background command in a script ignores SIGINT. Before v1.20.2
# an interrupted CLI also leaves a cached run's VM behind. Say so before
# anything is started, not after.
emit cancel_route "scripts/cleanup.sh --cancel"
if [ -n "${version:-}" ] && [ "$version" != "unknown" ] && at_least "$version" "$FIXED_IN"; then
    emit interrupt_orphans_vm wrapper_only
else
    emit interrupt_orphans_vm yes
    emit interrupt_blocker "smol-machines/smolvm#1193, fixed in v$FIXED_IN"
fi

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
