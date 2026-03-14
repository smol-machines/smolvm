#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACK_DIR="$(mktemp -d /tmp/smolvm-embedded-pack.XXXXXX)"
PROJECT_DIR="$(mktemp -d /tmp/smolvm-embedded-smoke.XXXXXX)"
NPM_CACHE_DIR="$(mktemp -d /tmp/smolvm-embedded-npm-cache.XXXXXX)"

cleanup() {
    rm -rf "$PACK_DIR" "$PROJECT_DIR" "$NPM_CACHE_DIR"
}
trap cleanup EXIT

export npm_config_cache="$NPM_CACHE_DIR"

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

if [[ ! -d "$WORKSPACE_DIR/node_modules" ]]; then
    echo "Error: Node workspace dependencies are not installed." >&2
    echo "Run 'cd $WORKSPACE_DIR && npm install' first." >&2
    exit 1
fi

PLATFORM_PACKAGE="$(detect_platform_package)"

(
    cd "$WORKSPACE_DIR"
    npm run build
)

PUBLIC_TARBALL="$(
    cd "$WORKSPACE_DIR/smolvm-embedded" &&
    npm pack --pack-destination "$PACK_DIR" | tail -n 1
)"
PLATFORM_TARBALL="$(
    cd "$WORKSPACE_DIR/$PLATFORM_PACKAGE" &&
    npm pack --pack-destination "$PACK_DIR" | tail -n 1
)"

cat > "$PROJECT_DIR/package.json" <<'EOF'
{
  "name": "smolvm-embedded-smoke",
  "private": true
}
EOF

(
    cd "$PROJECT_DIR"
    npm install --offline --no-audit --no-fund \
      "$PACK_DIR/$PLATFORM_TARBALL" "$PACK_DIR/$PUBLIC_TARBALL" >/dev/null
    node - <<'EOF'
const embedded = require("smolvm-embedded");
if (typeof embedded.quickExec !== "function") {
  throw new Error("smolvm-embedded smoke install failed: quickExec export missing");
}
console.log("smolvm-embedded smoke install OK");
EOF
)
