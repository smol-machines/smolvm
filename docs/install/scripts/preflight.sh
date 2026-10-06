#!/usr/bin/env bash
# Report whether this host can install and boot smolvm. Read-only: starts no VM,
# writes no smolvm state, changes no group membership.
#
# Output is one key=value per line so a caller can parse it. The last line is
# always result=ready, result=not_installed or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.23.0"

emit() { printf '%s=%s\n' "$1" "$2"; }

blocked=0
note() { printf 'note=%s\n' "$1"; }

# --- the binary --------------------------------------------------------------

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
missing=0
if [ -z "$SMOLVM" ]; then
    emit smolvm_installed no
    emit smolvm_version ""
    missing=1
else
    emit smolvm_installed yes
    emit smolvm_path "$SMOLVM"
    version="$("$SMOLVM" --version 2>/dev/null | awk '{print $NF}')"
    emit smolvm_version "${version:-unknown}"
    # A HOME set aside for a test install still finds whatever smolvm is first on
    # PATH, so say when that binary belongs to another HOME.
    case "$SMOLVM" in
        "$HOME"/*) ;;
        *) note "the smolvm on PATH, $SMOLVM, is not under this HOME ($HOME); the lines below describe that binary, not an install in this HOME. Put \$HOME/.local/bin first on PATH, or set SMOLVM, to check the one you mean" ;;
    esac
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
            blocked=1
            note "no darwin-x86_64 archive is published for v1.23.0, so the installer accepts an Intel Mac and then stops at the download"
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
        note "this script covers macOS and Linux. On Windows use references/windows.md, run there by hand on v1.22.2."
        ;;
esac

# Not installed yet is not a fault of the host, and reading it as one stopped a
# first install that had nothing wrong with it.
if [ "$blocked" -ne 0 ]; then
    emit result blocked
elif [ "$missing" -ne 0 ]; then
    note "smolvm is not installed yet and nothing else blocks this host: install it (step 2), then run this again"
    emit result not_installed
else
    emit result ready
fi
