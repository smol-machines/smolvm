#!/bin/bash
# smolvm - OCI-native microVM runtime
# This wrapper sets up the library path and runs the smolvm binary.

set -e

# Resolve symlinks to get the actual script location
resolve_symlink() {
    local target="$1"
    while [[ -L "$target" ]]; do
        local link_dir
        link_dir="$(cd "$(dirname "$target")" && pwd)"
        target="$(readlink "$target")"
        # Handle relative symlinks
        if [[ "$target" != /* ]]; then
            target="$link_dir/$target"
        fi
    done
    echo "$target"
}

# Get the directory where the actual script lives (resolving symlinks)
SCRIPT_PATH="$(resolve_symlink "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

# The actual binary and libraries are in the same directory
SMOLVM_BIN="$SCRIPT_DIR/smolvm-bin"
SMOLVM_LIB="$SCRIPT_DIR/lib"
SMOLVM_BUNDLED_ROOTFS="$SCRIPT_DIR/agent-rootfs"

if [[ -d "$SMOLVM_BUNDLED_ROOTFS" ]]; then
    export SMOLVM_AGENT_ROOTFS="${SMOLVM_AGENT_ROOTFS:-$SMOLVM_BUNDLED_ROOTFS}"
fi

# Check if binary exists
if [[ ! -x "$SMOLVM_BIN" ]]; then
    echo "Error: smolvm binary not found at $SMOLVM_BIN" >&2
    echo "Make sure you extracted the full distribution." >&2
    exit 1
fi

# Check GLIBC compatibility on Linux
if [[ "$(uname -s)" == "Linux" ]]; then
    # Extract the maximum required GLIBC version from the binary
    REQUIRED_GLIBC=$(objdump -T "$SMOLVM_BIN" 2>/dev/null | grep -oP 'GLIBC_\d+\.\d+' | sort -V | tail -1 | sed 's/GLIBC_//')
    if [[ -n "$REQUIRED_GLIBC" ]]; then
        # Get the system GLIBC version
        SYSTEM_GLIBC=$(ldd --version 2>&1 | head -1 | grep -oP '\d+\.\d+' | head -1)
        if [[ -n "$SYSTEM_GLIBC" ]]; then
            # Compare versions
            if [[ "$(printf '%s\n' "$REQUIRED_GLIBC" "$SYSTEM_GLIBC" | sort -V | tail -1)" != "$SYSTEM_GLIBC" ]]; then
                echo "Error: smolvm requires GLIBC >= $REQUIRED_GLIBC but your system has GLIBC $SYSTEM_GLIBC" >&2
                echo "" >&2
                echo "This typically happens on older Linux distributions (e.g., Ubuntu 22.04)." >&2
                echo "To resolve:" >&2
                echo "  1. Upgrade to Ubuntu 24.04 or newer, or" >&2
                echo "  2. Build smolvm from source: https://github.com/smol-machines/smolvm#building-from-source" >&2
                echo "  3. Use the smolvm Docker image: docker run --rm -it --privileged smolmachines/smolvm" >&2
                exit 1
            fi
        fi
    fi
fi

# Check if libraries exist
if [[ ! -d "$SMOLVM_LIB" ]]; then
    echo "Error: library directory not found at $SMOLVM_LIB" >&2
    echo "Make sure you extracted the full distribution." >&2
    exit 1
fi

# Set library path based on OS and run
if [[ "$(uname -s)" == "Darwin" ]]; then
    export DYLD_LIBRARY_PATH="$SMOLVM_LIB${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="$SMOLVM_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
exec "$SMOLVM_BIN" "$@"
