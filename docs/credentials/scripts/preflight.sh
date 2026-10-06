#!/usr/bin/env bash
# Report whether this host can give a machine a credential it can use but not
# read: the flag, the network backend the interceptor needs, and whether the host
# variable that holds the value is set. Read-only: starts no VM, writes no smolvm
# state, and never prints the value.
#
# usage: preflight.sh --var <HOST_ENV_VAR> --host <api.example.com>
#
# Output is one key=value per line so a caller can parse it. The last line is
# always result=ready or result=blocked.

set -uo pipefail

VERIFIED_VERSION="1.22.2"

emit() { printf '%s=%s\n' "$1" "$2"; }

blocked=0
note() { printf 'note=%s\n' "$1"; }

VAR=""
HOST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --var)  VAR="$2"; shift ;;
        --host) HOST="$2"; shift ;;
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
        note "this script covers macOS and Linux; Windows was not run for this packet."
        ;;
esac

# --- the feature ---------------------------------------------------------------

if [ -n "$SMOLVM" ]; then
    createhelp="$("$SMOLVM" machine create --help 2>&1)"
    if grep -q -- '--credential <NAME=ENV_VAR@HOST>' <<<"$createhelp"; then
        emit has_credential_flag yes
    else
        emit has_credential_flag no
        blocked=1
        note "this smolvm has no --credential; credential substitution arrived in v1.18.0"
    fi
fi

# The interceptor sits on the machine's network path. A credential binding
# selects the virtio-net backend by default, which needs nothing more. TSI works
# only when libkrun exports krun_set_stream_intercept; otherwise a machine asked
# for --net-backend tsi fails at start. Read the bundled library's symbols
# rather than starting a VM to find out.
emit default_backend virtio-net
libdir="${SMOLVM_LIB_DIR:-$HOME/.smolvm/lib}"
lib="$(ls "$libdir"/libkrun.dylib "$libdir"/libkrun.so 2>/dev/null | head -1)"
if [ -z "$lib" ]; then
    emit tsi_stream_intercept unknown
    note "no libkrun found under $libdir; set SMOLVM_LIB_DIR to check whether --net-backend tsi can carry a credential"
elif command -v nm >/dev/null 2>&1; then
    case "$kernel" in Darwin) syms="$(nm -gU "$lib" 2>/dev/null)" ;; *) syms="$(nm -D --defined-only "$lib" 2>/dev/null)" ;; esac
    if grep -q 'krun_set_stream_intercept' <<<"$syms"; then emit tsi_stream_intercept yes; else
        emit tsi_stream_intercept no
        note "this libkrun cannot intercept TSI streams: leave the backend at its default, virtio-net, or a start with --net-backend tsi fails"
    fi
else
    emit tsi_stream_intercept unknown
fi

# The value itself: set or not, never shown. Its length is not shown either.
if [ -n "$VAR" ]; then
    if [ -n "$(printenv "$VAR" 2>/dev/null)" ]; then emit host_var_set yes; else
        emit host_var_set no
        blocked=1
        note "$VAR is not set in this environment. The value is read from the environment of the machine start, so set it there; a machine started without it answers every substituted request with 502 credential unavailable."
    fi
fi
if [ -n "$HOST" ]; then
    case "$HOST" in
        *[!a-z0-9.-]*|*..*|.*|*.|[0-9]*[0-9]) emit host_form rejected; blocked=1
            note "a credential host must be an exact lowercase DNS name: no wildcard, scheme, port or IP address" ;;
        *) emit host_form ok ;;
    esac
fi

emit memory_required_mib 1024

if [ "$blocked" -eq 0 ]; then emit result ready; else emit result blocked; fi
