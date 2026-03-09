#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

copy_matching_libraries() {
    local src_dir="$1"
    local pattern="$2"
    local dst_dir="$3"

    if compgen -G "$src_dir/$pattern" > /dev/null; then
        cp -a "$src_dir"/$pattern "$dst_dir"/
    fi
}

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

usage() {
    cat <<'EOF'
Usage:
  ./sdks/scripts/stage-embedded-libs.sh <target-lib-dir>

Environment:
  SMOLVM_EMBEDDED_LIB_BUNDLE  Override the bundled library source directory.
EOF
}

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 1
fi

TARGET_LIB_DIR="$1"
SOURCE_LIB_DIR="$(detect_lib_bundle)"

if [[ ! -d "$SOURCE_LIB_DIR" ]]; then
    echo "Error: bundled library directory not found: $SOURCE_LIB_DIR" >&2
    exit 1
fi

rm -rf "$TARGET_LIB_DIR"
mkdir -p "$TARGET_LIB_DIR"

if [[ "$(uname -s)" == "Linux" ]]; then
    copy_matching_libraries "$SOURCE_LIB_DIR" "libkrun.so*" "$TARGET_LIB_DIR"
    copy_matching_libraries "$SOURCE_LIB_DIR" "libkrunfw.so*" "$TARGET_LIB_DIR"
else
    copy_matching_libraries "$SOURCE_LIB_DIR" "libkrun*.dylib" "$TARGET_LIB_DIR"
    copy_matching_libraries "$SOURCE_LIB_DIR" "libkrunfw*.dylib" "$TARGET_LIB_DIR"
fi

echo "Staged embedded SDK libraries from $SOURCE_LIB_DIR into $TARGET_LIB_DIR"
