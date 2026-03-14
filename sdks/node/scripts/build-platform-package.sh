#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKSPACE_DIR/../.." && pwd)"

detect_lib_bundle() {
    if [[ -n "${SMOLVM_EMBEDDED_LIB_BUNDLE:-}" ]]; then
        echo "$SMOLVM_EMBEDDED_LIB_BUNDLE"
        return 0
    fi

    if [[ "$(uname -s)" == "Linux" ]]; then
        echo "$REPO_ROOT/lib/linux-$(uname -m)"
    else
        echo "$REPO_ROOT/lib"
    fi
}

detect_platform_package() {
    case "$(uname -s):$(uname -m)" in
        Darwin:arm64)
            echo "smolvm-embedded-darwin-arm64"
            ;;
        Darwin:x86_64)
            echo "smolvm-embedded-darwin-x64"
            ;;
        Linux:aarch64)
            echo "smolvm-embedded-linux-arm64-gnu"
            ;;
        Linux:x86_64)
            echo "smolvm-embedded-linux-x64-gnu"
            ;;
        *)
            echo "Unsupported platform: $(uname -s) $(uname -m)" >&2
            exit 1
            ;;
    esac
}

PACKAGE_NAME="$(detect_platform_package)"
PACKAGE_DIR="$WORKSPACE_DIR/$PACKAGE_NAME"
LIBKRUN_BUNDLE="$(detect_lib_bundle)"

echo "Building embedded Node platform package: $PACKAGE_NAME"

(
    cd "$PACKAGE_DIR"
    LIBKRUN_BUNDLE="$LIBKRUN_BUNDLE" napi build --platform --release --cargo-cwd ../../../crates/smolvm-napi native
)

"$REPO_ROOT/sdks/scripts/stage-embedded-libs.sh" "$PACKAGE_DIR/lib"

cat <<EOF

Built platform package: $PACKAGE_NAME
Package directory: $PACKAGE_DIR

Next useful commands:
  - cd $WORKSPACE_DIR && npm run build
  - cd $WORKSPACE_DIR && npm test
  - cd $WORKSPACE_DIR && npm run smoke
EOF
