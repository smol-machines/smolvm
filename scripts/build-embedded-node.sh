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
echo "Building smolvm-napi (part 1)..."

# TODO(part-3): Add the sdks/node npm workspace inside this repository.
# TODO(part-4): Detect the current host platform package name (for example
#   darwin-arm64 or linux-x64-gnu).
# TODO(part-4): Build the matching internal platform package.
# TODO(part-5): Copy the built .node artifact into that internal platform
#   package.
# TODO(part-5): Copy libkrun and libkrunfw into that package's local lib/
#   directory.
# TODO(part-6): Build the public smolvm-embedded package that depends on the
#   internal platform packages.
# TODO(part-7): Run embedded Node tests/examples from the in-repo sdk
#   workspace.
# TODO(part-7): Add npm pack smoke tests for the public package and
#   current-host platform package.

(
    cd "$REPO_ROOT"
    LIBKRUN_BUNDLE="$LIBKRUN_BUNDLE" cargo build --release -p smolvm-napi
)

cat <<'EOF'

Part 1 complete: built the smolvm-napi crate against the bundled libkrun/libkrunfw.

TODO(next parts):
  1. Add the sdks/node npm workspace inside this repository.
  2. Detect the current host platform package name (for example darwin-arm64 or linux-x64-gnu).
  3. Build the matching internal platform package.
  4. Copy the built .node artifact into that internal platform package.
  5. Copy libkrun and libkrunfw into that package's local lib/ directory.
  6. Build the public smolvm-embedded package that depends on the internal platform packages.
  7. Run embedded Node tests/examples from the in-repo sdk workspace.
  8. Add npm pack smoke tests for the public package and current-host platform package.
EOF
