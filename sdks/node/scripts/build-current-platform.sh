#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$WORKSPACE_DIR/node_modules" ]]; then
    echo "Error: Node workspace dependencies are not installed." >&2
    echo "Run 'cd $WORKSPACE_DIR && npm install' first." >&2
    exit 1
fi

(
    cd "$WORKSPACE_DIR"
    npm run build:platform
    npm run build:public
)
