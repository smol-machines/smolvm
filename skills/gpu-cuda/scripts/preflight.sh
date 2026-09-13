#!/usr/bin/env bash
# Report whether this host can run CUDA workloads inside a smolvm machine.
# Read-only: starts no VM, touches no NVIDIA state, changes no group membership.
#
# Output is one key=value per line. The last line is always result=ready or
# result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.14.6"

emit() { printf '%s=%s\n' "$1" "$2"; }
note() { printf 'note=%s\n' "$1"; }

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
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version; the GPU path was last exercised on an A10 on $VERIFIED_VERSION, so check each step's output against the binary"
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
emit platform "$(printf '%s' "$kernel" | tr '[:upper:]' '[:lower:]')-$arch"

case "$kernel" in
    Darwin)
        emit accel hvf
        if [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ]; then emit accel_access ok; else emit accel_access denied; fi
        emit gpu_present no
        emit unsupported "cuda,vulkan"
        blocked=1
        note "no Apple Silicon or Intel Mac has an NVIDIA GPU, so --cuda has nothing to reach here. This is a hardware fact, not a smolvm limitation."
        ;;
    Linux)
        emit accel kvm
        # A fresh cloud GPU instance fails this, and the installer warns and
        # continues, so the install succeeds and the first VM fails.
        if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
            emit accel_access ok
        else
            emit accel_access denied
            blocked=1
            note "your user cannot open /dev/kvm. Fix without logging out: sudo usermod -aG kvm \$USER, then run the next command through sg kvm -c '...'"
        fi
        emit unsupported "vulkan"
        ;;
    *)
        emit accel unknown
        emit accel_access unknown
        note "this script covers macOS and Linux. CUDA does work on Windows, against the documentation; see references/windows.md, written from a run and not re-run by this packet."
        blocked=1
        ;;
esac

if command -v nvidia-smi >/dev/null 2>&1; then
    gpu="$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>/dev/null | head -1)"
    if [ -n "$gpu" ]; then
        emit gpu_present yes
        emit gpu "$gpu"
    else
        emit gpu_present no
        blocked=1
        note "nvidia-smi is installed but reported no device"
    fi
elif [ "$kernel" = "Linux" ]; then
    emit gpu_present no
    blocked=1
    note "no nvidia-smi on this host, so there is no GPU for the remoting daemon to own"
fi

# The host's own libcuda is what the remoting daemon forwards to. The guest gets
# none, and that is the design.
if command -v ldconfig >/dev/null 2>&1; then
    emit host_libcuda "$(ldconfig -p 2>/dev/null | grep -c 'libcuda\.so\.1')"
fi

emit guest_needs_glibc_image yes
emit guest_shim_path /opt/smolvm-cuda/libcuda.so.1

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
