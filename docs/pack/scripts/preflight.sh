#!/usr/bin/env bash
# Report whether this host can pack a machine into a portable artifact.
# Read-only: starts no VM, packs nothing, writes no smolvm state.
#
# The memory lines are the reason this script exists. Both pack paths boot a
# helper VM before they write anything:
#   --image    pulls the image in a VM fixed at 4 vCPUs and 8192 MiB on every
#              release read (src/cli/pack.rs:730-742 at v1.22.2); --mem does
#              not reach it.
#   --from-vm  boots an export helper. Through v1.16.1 it was fixed at 8192 MiB
#              and a host that could not seat it failed as "agent did not become
#              ready within 30 seconds", naming nothing. From v1.16.2 it asks for
#              4096 MiB (on Linux half of the available memory when that is
#              less, never under 1024), SMOLVM_EXPORT_HELPER_MEMORY_MIB sets it,
#              and a failed start names the figure and the variable
#              (src/pack_export.rs:289-335 and :514-522 at v1.22.2).
#
# Output is one key=value per line so a caller can parse it. The last line is
# always result=ready or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.22.2"

emit() { printf '%s=%s\n' "$1" "$2"; }

blocked=0
note() { printf 'note=%s\n' "$1"; }

# --- the binary --------------------------------------------------------------

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    emit smolvm_installed no
    emit smolvm_version ""
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
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version; flags and messages move every release, so check the output against the binary before trusting a step here"
        else
            emit version_status older
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version"
        fi
    fi
else
    emit version_status unknown
fi

# --- platform ----------------------------------------------------------------

kernel="$(uname -s)"
arch="$(uname -m)"
case "$arch" in aarch64|arm64) arch=aarch64 ;; esac

case "$kernel" in
    Darwin)
        emit platform "darwin-$arch"
        emit accel hvf
        emit macos_version "$(sw_vers -productVersion)"
        hv="$(sysctl -n kern.hv_support 2>/dev/null)"
        if [ "$hv" = "1" ]; then emit accel_access ok; else emit accel_access denied; blocked=1; fi
        if [ "$arch" != "aarch64" ]; then
            emit hardware_verified no
            note "Intel Mac is not verified by this packet; the installer accepts it and nothing here was run on one"
        else
            emit hardware_verified yes
        fi
        # A VM's agent socket lives under the cache directory. macOS sockaddr_un
        # holds 104 bytes including the terminator.
        sock="$HOME/Library/Caches/smolvm/vms/0123456789abcdef/agent.sock"
        len=${#sock}
        emit socket_path_bytes "$len"
        if [ "$len" -gt 100 ]; then
            emit socket_path_status too_long
            blocked=1
            note "HOME is too deep: every VM start will fail with krun_start_enter -22, whose text blames disks and device options. Install under a shorter HOME."
        else
            emit socket_path_status ok
        fi
        emit unsupported "cuda"
        ;;
    Linux)
        emit platform "linux-$arch"
        emit accel kvm
        emit socket_path_status n_a
        if [ ! -e /dev/kvm ]; then
            emit accel_access missing
            blocked=1
            note "/dev/kvm does not exist; this host has no KVM"
        elif [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
            emit accel_access ok
        else
            emit accel_access denied
            blocked=1
            note "your user cannot open /dev/kvm. The installer warns and continues, so a successful install says nothing about whether a VM will start. Fix: sudo usermod -aG kvm \$USER, then run the next command through sg kvm -c '...' rather than logging out."
        fi
        ;;
    *)
        emit platform "unsupported-$kernel"
        emit accel unknown
        emit accel_access unknown
        blocked=1
        note "this script covers macOS and Linux. On Windows v1.22.2 packs both ways but no artifact runs there (os error 123), and the stub is written without .exe; see references/windows.md."
        ;;
esac

# --- the helper VMs' memory --------------------------------------------------
#
# Read free memory the way the kernel reports it. MemAvailable is the honest
# number for "could a new process get this". On Linux smolvm also caps it by the
# cgroup's headroom, which this does not read.
case "$kernel" in
    Darwin)
        # Free alone is meaningless on macOS, which keeps almost nothing free.
        # Inactive and purgeable pages are reclaimable, which is what Activity
        # Monitor calls available.
        avail_mib="$(vm_stat 2>/dev/null | awk -v page="$(sysctl -n hw.pagesize 2>/dev/null || echo 16384)" '
            /Pages free/        {gsub(/\./,"",$3); f=$3}
            /Pages inactive/    {gsub(/\./,"",$3); i=$3}
            /Pages speculative/ {gsub(/\./,"",$3); s=$3}
            /Pages purgeable/   {gsub(/\./,"",$3); p=$3}
            END {printf "%d", (f+i+s+p)*page/1048576}')"
        ;;
    Linux)
        avail_mib="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
        ;;
    *) avail_mib="" ;;
esac

# What this binary's export helper will ask for (src/pack_export.rs:318-335).
IMAGE_VM_MIB=8192
override="${SMOLVM_EXPORT_HELPER_MEMORY_MIB:-}"
if [ -n "${version:-}" ] && [ "$version" != "unknown" ] &&
   [ "$(printf '%s\n%s\n' "$version" 1.16.2 | sort -V | head -1)" != "1.16.2" ]; then
    EXPORTER_MIB=8192; exporter_basis=fixed_before_1.16.2
elif [ -n "$override" ] && [ "$override" -gt 0 ] 2>/dev/null; then
    EXPORTER_MIB="$override"; exporter_basis=SMOLVM_EXPORT_HELPER_MEMORY_MIB
elif [ "$kernel" = Linux ] && [ "${avail_mib:-0}" -gt 0 ]; then
    EXPORTER_MIB=$(( avail_mib / 2 ))
    [ "$EXPORTER_MIB" -gt 4096 ] && EXPORTER_MIB=4096
    [ "$EXPORTER_MIB" -lt 1024 ] && EXPORTER_MIB=1024
    exporter_basis=half_of_available
else
    EXPORTER_MIB=4096; exporter_basis=default
fi
emit exporter_memory_mib "$EXPORTER_MIB"
emit exporter_memory_basis "$exporter_basis"
emit image_vm_memory_mib "$IMAGE_VM_MIB"

if [ -n "${avail_mib:-}" ] && [ "${avail_mib:-0}" -gt 0 ]; then
    emit free_memory_mib "$avail_mib"
    # Warnings, not blocks. smolvm memory is a cap and not a reservation, so a
    # helper can still come up under the figure; what these lines buy you is
    # the name of the failure if it does not.
    if [ "$avail_mib" -ge "$EXPORTER_MIB" ]; then
        emit exporter_memory_ok yes
    else
        emit exporter_memory_ok no
        if [ "$exporter_basis" = fixed_before_1.16.2 ]; then
            note "free memory is below the export helper's fixed 8192 MiB on this release. If pack create --from-vm fails with 'agent did not become ready within 30 seconds', that is this; the message does not mention memory, and nothing changes the figure before v1.16.2."
        else
            note "free memory is below the $EXPORTER_MIB MiB the export helper will ask for. If pack create --from-vm fails, its message names the figure; set SMOLVM_EXPORT_HELPER_MEMORY_MIB=<MiB> lower and retry."
        fi
    fi
    if [ "$avail_mib" -ge "$IMAGE_VM_MIB" ]; then
        emit image_vm_memory_ok yes
    else
        emit image_vm_memory_ok no
        note "free memory is below the 8192 MiB pack create --image gives the VM that pulls the image. If it fails with 'agent did not become ready within 30 seconds', that is this; no flag or variable changes that VM, and --mem sets the artifact's memory, not its."
    fi
else
    emit free_memory_mib unknown
    emit exporter_memory_ok unknown
    emit image_vm_memory_ok unknown
    note "could not read free memory; the export helper asks for $EXPORTER_MIB MiB and the image pull VM for $IMAGE_VM_MIB MiB"
fi

# An isolated data root on Linux does not carry the agent rootfs: the variable
# moves where it is looked up and the installer does not write it there.
if [ "$kernel" = "Linux" ] && [ -n "${SMOLVM_DATA_DIR:-}" ]; then
    if [ -d "$SMOLVM_DATA_DIR/.local/share/smolvm/agent-rootfs" ]; then
        emit data_root_rootfs present
    else
        emit data_root_rootfs missing
        blocked=1
        note "SMOLVM_DATA_DIR is set and holds no agent-rootfs, so the first boot fails with 'agent rootfs not found'. Copy the installer's agent-rootfs into \$SMOLVM_DATA_DIR/.local/share/smolvm/ first."
    fi
fi

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
