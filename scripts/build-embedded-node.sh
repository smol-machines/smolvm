#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

detect_lib_bundle() {
    if [[ "$(uname -s)" == "Linux" ]]; then
        echo "$REPO_ROOT/lib/linux-$(uname -m)"
    else
        echo "$REPO_ROOT/lib"
    fi
}

require_match() {
    local dir="$1"
    local pattern="$2"

    if ! compgen -G "$dir/$pattern" > /dev/null; then
        echo "Error: expected '$pattern' in $dir" >&2
        exit 1
    fi
}

LIBKRUN_BUNDLE="$(detect_lib_bundle)"

if [[ ! -d "$LIBKRUN_BUNDLE" ]]; then
    echo "Error: embedded library bundle not found: $LIBKRUN_BUNDLE" >&2
    exit 1
fi

if [[ "$(uname -s)" == "Linux" ]]; then
    require_match "$LIBKRUN_BUNDLE" "libkrun.so*"
    require_match "$LIBKRUN_BUNDLE" "libkrunfw.so*"
else
    require_match "$LIBKRUN_BUNDLE" "libkrun*.dylib"
    require_match "$LIBKRUN_BUNDLE" "libkrunfw*.dylib"
fi

echo "Using embedded lib bundle: $LIBKRUN_BUNDLE"
echo "Building smolvm-napi..."

# TODO(release): add CI/release automation for publishing the public package
#   and internal platform packages.
# TODO(multi-language): add the python/go/c embedded SDK workspaces that reuse
#   the same bundled lib staging model.

(
    cd "$REPO_ROOT"
    LIBKRUN_BUNDLE="$LIBKRUN_BUNDLE" cargo build --release -p smolvm-napi
)

if [[ -f "$REPO_ROOT/sdks/node/package.json" ]]; then
    echo "Building embedded Node workspace..."
    (
        cd "$REPO_ROOT/sdks/node"
        npm run build
    )
fi

cat <<'EOF'

Built smolvm-napi and the current-host smolvm-embedded Node packages.

Useful follow-ups:
  - cd sdks/node && npm test
  - cd sdks/node && npm run smoke
  - cd sdks/node && npm exec --workspace smolvm-embedded tsx examples/basic.ts
EOF
