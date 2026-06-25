#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DYLD_LIBRARY_PATH="$SCRIPT_DIR/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

if [ -d "$SCRIPT_DIR/agent-rootfs" ]; then
    export SMOLVM_AGENT_ROOTFS="${SMOLVM_AGENT_ROOTFS:-$SCRIPT_DIR/agent-rootfs}"
fi

exec "$SCRIPT_DIR/smolvm-bin" "$@"
