#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SDK_DIR/../.." && pwd)"
TARGET_LIB_DIR="$SDK_DIR/python/smolvm_embedded/lib"
TARGET_BOOT_BIN="$SDK_DIR/python/smolvm_embedded/smolvm-bin"
TARGET_BOOT_WRAPPER="$SDK_DIR/python/smolvm_embedded/smolvm"

if ! python3 -m pip show maturin >/dev/null 2>&1; then
    echo "Error: maturin is not installed in the active Python environment." >&2
    echo "Create or activate a virtualenv, then run 'python -m pip install --upgrade pip maturin'." >&2
    exit 1
fi

"$REPO_ROOT/sdks/scripts/stage-embedded-libs.sh" "$TARGET_LIB_DIR"

(
    cd "$REPO_ROOT"
    LIBKRUN_BUNDLE="$TARGET_LIB_DIR" cargo build --release --bin smolvm >/dev/null
)

cp "$REPO_ROOT/target/release/smolvm" "$TARGET_BOOT_BIN"
chmod +x "$TARGET_BOOT_BIN"
cp "$REPO_ROOT/scripts/smolvm-wrapper.sh" "$TARGET_BOOT_WRAPPER"
chmod +x "$TARGET_BOOT_WRAPPER"

if [[ "$(uname -s)" == "Darwin" ]]; then
    IDENTITY="${CODESIGN_IDENTITY:--}"
    codesign --force --sign "$IDENTITY" \
        --entitlements "$REPO_ROOT/smolvm.entitlements" \
        "$TARGET_BOOT_BIN" >/dev/null
fi

(
    cd "$SDK_DIR"
    LIBKRUN_BUNDLE="$TARGET_LIB_DIR" python3 -m maturin develop --release
)
