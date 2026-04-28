#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

(
    cd "$REPO_ROOT/sdks/python"
    ./scripts/build-current-platform.sh
)

cat <<'EOF'

Built the current Python embedded SDK environment.

Useful follow-ups:
  - cd sdks/python && python3 examples/basic.py
  - cd sdks/python && python3 examples/create_and_start.py
EOF
