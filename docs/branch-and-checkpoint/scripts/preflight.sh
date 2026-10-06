#!/usr/bin/env bash
# Report whether this host can checkpoint, restore, pause and branch smolvm
# machines, and whether the place the checkpoints will go has room. Read-only:
# starts no VM, writes no smolvm state, changes no group membership.
#
# usage: preflight.sh [--store <dir>]   (default: the current directory)
#
# Output is one key=value per line so a caller can parse it. The last line is
# always result=ready or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.23.0"

emit() { printf '%s=%s\n' "$1" "$2"; }

blocked=0
note() { printf 'note=%s\n' "$1"; }

STORE_DIR="."
while [ $# -gt 0 ]; do
    case "$1" in
        --store) STORE_DIR="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

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
        # v1.20.0 lifted the flag for a checkpoint file and for pause; a stored
        # capture, which is what these scripts take, still needs it on v1.22.2.
        emit checkpoint_needs_branchable yes
        if [ -n "${version:-}" ] && [ "$(printf '%s\n%s\n' "$version" 1.20.0 | sort -V | head -1)" = "1.20.0" ]; then
            note "on macOS machine checkpoint --store refuses a machine that was not started with machine start --branchable, with deferred durable save requires file-backed guest RAM, which names neither. A checkpoint file and a pause do not need it from v1.20.0. The flag cannot be added to a running machine; the scripts here always start with it."
        else
            note "on macOS machine checkpoint and machine pause refuse a machine that was not started with machine start --branchable, and the error, guest RAM has no file-backed regions, names neither. The flag cannot be added to a running machine; the scripts here always start with it."
        fi
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
        emit checkpoint_needs_branchable no
        ;;
    *)
        emit platform "unsupported-$kernel"
        emit accel unknown
        emit accel_access unknown
        blocked=1
        note "this script covers macOS and Linux. On Windows v1.22.2 checkpoints to a file, pauses, and branches with --freeze-source on every branch, and refuses --store, so checkpoint.sh cannot run there; see references/platforms.md."
        ;;
esac

# --- the checkpoint surface this packet uses -----------------------------------

if [ -n "$SMOLVM" ]; then
    ckhelp="$("$SMOLVM" machine checkpoint --help 2>&1)"
    for flag in --store --history --export-from; do
        k="has_$(printf %s "${flag#--}" | tr - _)"
        if grep -q -- "$flag" <<<"$ckhelp"; then emit "$k" yes; else emit "$k" no; blocked=1; fi
    done
    if "$SMOLVM" machine checkpoint-log --help >/dev/null 2>&1; then emit has_checkpoint_log yes; else emit has_checkpoint_log no; blocked=1; fi
    if "$SMOLVM" machine pause --help >/dev/null 2>&1; then emit has_pause yes; else emit has_pause no; fi
    createhelp="$("$SMOLVM" machine create --help 2>&1)"
    if grep -q -- '--at <GENERATION>' <<<"$createhelp"; then emit restore_any_generation yes; else emit restore_any_generation no; blocked=1; fi
    emit scheduler builtin_none
    emit retention builtin_none
fi

# --- memory and disk ---------------------------------------------------------

# The scripts start every machine with --mem 1024. A host that cannot boot that
# inside smolvm's fixed 30 s readiness window fails with "agent did not become
# ready", which names neither memory nor the host.
emit memory_required_mib 1024
mkdir -p "$STORE_DIR" 2>/dev/null
free_kb="$(df -Pk "$STORE_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$free_kb" ]; then
    emit store_free_mib "$((free_kb / 1024))"
    # A capture of a 1 GiB alpine machine wrote about 55 MiB the first time and
    # about 19 MiB after that; restores, the restore base and the capture
    # staging need more. 2 GiB is headroom, not a measurement of any one step.
    if [ "$((free_kb / 1024))" -lt 2048 ]; then
        emit store_space_ok no
        blocked=1
        note "less than 2 GiB free where the checkpoints go. A capture into a full disk publishes nothing, and a machine restored or resumed while the disk is full can be left with guest I/O errors that stop it from being deleted normally (references/traps.md)."
    else
        emit store_space_ok yes
    fi
fi

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
