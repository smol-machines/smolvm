#!/bin/bash
# smol - the unified Smol Machines CLI (local microVMs + cloud)
# This wrapper sets up the library path and runs the smol binary.
#
# It mirrors smolvm-wrapper.sh: the `smol` binary embeds the same engine, so it
# discovers libkrun/libkrunfw and the agent rootfs the same way (relative to its
# own install directory), making the distribution relocatable.

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
SMOL_BIN="$SCRIPT_DIR/smol-bin"
SMOL_LIB="$SCRIPT_DIR/lib"
SMOL_BUNDLED_ROOTFS="$SCRIPT_DIR/agent-rootfs"

if [[ -d "$SMOL_BUNDLED_ROOTFS" ]]; then
    export SMOLVM_AGENT_ROOTFS="${SMOLVM_AGENT_ROOTFS:-$SMOL_BUNDLED_ROOTFS}"
fi

# Check if binary exists
if [[ ! -x "$SMOL_BIN" ]]; then
    echo "Error: smol binary not found at $SMOL_BIN" >&2
    echo "Make sure you extracted the full distribution." >&2
    exit 1
fi

# Check if libraries exist
if [[ ! -d "$SMOL_LIB" ]]; then
    echo "Error: library directory not found at $SMOL_LIB" >&2
    echo "Make sure you extracted the full distribution." >&2
    exit 1
fi

# Set library path based on OS and run
if [[ "$(uname -s)" == "Darwin" ]]; then
    export DYLD_LIBRARY_PATH="$SMOL_LIB${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="$SMOL_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
exec "$SMOL_BIN" "$@"
