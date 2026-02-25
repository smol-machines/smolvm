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

# Check if binary exists
if [[ ! -x "$SMOLVM_BIN" ]]; then
    echo "Error: smolvm binary not found at $SMOLVM_BIN" >&2
    echo "Make sure you extracted the full distribution." >&2
    exit 1
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
