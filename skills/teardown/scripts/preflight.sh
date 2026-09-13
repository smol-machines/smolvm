#!/usr/bin/env bash
# Report what smolvm state exists on this host, so you know what teardown has to
# remove before you remove it. Read-only: deletes nothing, starts no VM.
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
            note "this packet was verified on $VERIFIED_VERSION and the binary is $version; check each path below still exists before trusting a removal step"
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
        emit accel hvf
        if [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ]; then emit accel_access ok; else emit accel_access denied; fi
        data_dir="$HOME/Library/Application Support/smolvm"
        cache_dir="$HOME/Library/Caches/smolvm"
        pack_dir="$HOME/Library/Caches/smolvm-pack"
        libs_dir="$HOME/Library/Caches/smolvm-libs"
        emit unsupported "vulkan,cuda"
        # There is no SMOLVM_DATA_DIR on macOS (it is Linux-only), but every path
        # below is derived from HOME, so an install under a scratch HOME is
        # self-contained. Windows is the platform where neither route works.
        emit state_relocatable via_home
        ;;
    Linux)
        emit platform "linux-$arch"
        emit accel kvm
        if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then emit accel_access ok; else emit accel_access denied; fi
        data_dir="$HOME/.local/share/smolvm"
        cache_dir="$HOME/.cache/smolvm"
        pack_dir="$HOME/.cache/smolvm-pack"
        libs_dir="$HOME/.cache/smolvm-libs"
        emit unsupported "vulkan"
        emit state_relocatable via_home_or_data_dir
        ;;
    *)
        emit platform "unsupported-$kernel"
        emit accel unknown
        emit accel_access unknown
        blocked=1
        note "this script covers macOS and Linux. The Windows removal sequence is references/windows.md and was not re-run by this packet."
        exit_now=1
        ;;
esac

if [ "${exit_now:-0}" = "1" ]; then
    emit result blocked
    exit 0
fi

report_dir() {
    if [ -d "$2" ]; then
        emit "$1" "$(du -sk "$2" 2>/dev/null | awk '{printf "%d", $1/1024}')MB"
    else
        emit "$1" absent
    fi
}

report_dir install_prefix "$HOME/.smolvm"
report_dir agent_rootfs   "$data_dir"
report_dir vm_state       "$cache_dir"
report_dir pack_cache     "$pack_dir"
report_dir packed_libs    "$libs_dir"
report_dir credentials    "$HOME/.config/smolvm"

if [ -L "$HOME/.local/bin/smolvm" ]; then emit launcher_symlink present; else emit launcher_symlink absent; fi

# `_shared` is the image store --oci-cache bakes into. It is the cache, not
# residue, so counting it as a leak gives a false positive.
if [ -d "$cache_dir/vms" ]; then
    total="$(find "$cache_dir/vms" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    shared=0
    [ -d "$cache_dir/vms/_shared" ] && shared=1
    emit vm_dirs "$((total - shared))"
    if [ "$shared" = 1 ]; then emit oci_cache_present yes; else emit oci_cache_present no; fi
else
    emit vm_dirs 0
    emit oci_cache_present no
fi

if grep -rqs 'smolvm' "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile" 2>/dev/null; then
    emit path_block present
    note "the uninstaller deliberately leaves the PATH block and \$HOME/.config/smolvm; remove them by hand if you want them gone"
else
    emit path_block absent
fi

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
