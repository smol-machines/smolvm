#!/bin/bash
# Pack a local Docker image into a .smolmachine by routing through a temporary
# local OCI registry.
#
# Why this script exists:
# - `smolvm pack create --image ...` expects an OCI registry reference.
# - Today it does not import directly from the local Docker daemon image store.
# - The supported bridge is:
#     local Docker image -> temporary local registry -> `smolvm pack create`
#
# What this script does:
# 1. Validate that Docker and smolvm are available.
# 2. Start a temporary local registry on `localhost:$REGISTRY_PORT`.
# 3. Tag the local image into that registry namespace.
# 4. Push the image to the local registry.
# 5. Run `smolvm pack create` against the local-registry reference.
# 6. Verify that the expected packed artifacts were created.
# 7. Clean up the temporary registry and temporary registry tag.
#
# Example:
#   ./scripts/pack-local-image.sh --image myapp:dev --output ./dist/myapp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LOCAL_IMAGE=""
OUTPUT_PATH=""
REGISTRY_PORT=5051
REGISTRY_NAME="smolvm-local-registry-$$"
SMOLVM_BIN="smolvm"

REGISTRY_IMAGE=""

usage() {
    cat <<'EOF'
Pack a local Docker image into a .smolmachine through a temporary local registry.

Usage:
  ./scripts/pack-local-image.sh --image IMAGE --output PATH

Required:
  --image IMAGE           Existing local Docker image to pack.
                          Example: myapp:dev
  --output PATH           Base output path for `smolvm pack create -o`.
                          Example: --output ./dist/myapp
                          Produces:
                            ./dist/myapp
                            ./dist/myapp.smolmachine

Optional:
  -h, --help              Show this help.

Examples:
  ./scripts/pack-local-image.sh --image myapp:dev --output ./dist/myapp
EOF
}

step() {
    echo ""
    echo "==> $1"
}

info() {
    echo "    $1"
}

fail() {
    echo "Error: $1" >&2
    exit 1
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
}

cleanup() {
    if [[ -n "$REGISTRY_NAME" ]]; then
        docker stop "$REGISTRY_NAME" >/dev/null 2>&1 || true
        docker rm "$REGISTRY_NAME" >/dev/null 2>&1 || true
    fi

    if [[ -n "$REGISTRY_IMAGE" ]]; then
        docker rmi "$REGISTRY_IMAGE" >/dev/null 2>&1 || true
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            [[ -n "${2:-}" ]] || fail "--image requires a value"
            LOCAL_IMAGE="$2"
            shift 2
            ;;
        --output)
            [[ -n "${2:-}" ]] || fail "--output requires a value"
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

trap cleanup EXIT

[[ -n "$LOCAL_IMAGE" ]] || fail "--image is required"
[[ -n "$OUTPUT_PATH" ]] || fail "--output is required"

if [[ "$LOCAL_IMAGE" == *"@"* ]]; then
    fail "digest image references are not supported by this helper; use a tag reference"
fi

require_command docker
require_command "$SMOLVM_BIN"

step "Input validation"
info "This flow works by pushing a local Docker image into a temporary local registry on your local host."
info "smolvm will then pack from that registry reference, because pack create expects OCI registry input."
info "Project root: $PROJECT_ROOT"
info "Output base path: $OUTPUT_PATH"
info "Registry container: $REGISTRY_NAME"
info "Registry port: $REGISTRY_PORT"
info "smolvm command: $SMOLVM_BIN"

step "Check the local source image"
info "The source image must already exist in the local Docker daemon image store."
docker image inspect "$LOCAL_IMAGE" >/dev/null
info "Found local image: $LOCAL_IMAGE"

REGISTRY_IMAGE="localhost:${REGISTRY_PORT}/${LOCAL_IMAGE}"

step "Start a temporary local registry"
info "This registry is the bridge between the local Docker image store and smolvm pack."
if docker ps -a --format '{{.Names}}' | grep -Fxq "$REGISTRY_NAME"; then
    fail "a container named '$REGISTRY_NAME' already exists; remove it or use --registry-name"
fi
docker run -d -p "${REGISTRY_PORT}:5000" --name "$REGISTRY_NAME" registry:2 >/dev/null
info "Registry is listening at: localhost:${REGISTRY_PORT}"

step "Tag the local image into the local registry namespace"
info "Docker cannot push a plain local-only tag to a registry."
info "So this step creates a second tag that points at localhost:${REGISTRY_PORT}/..."
docker tag "$LOCAL_IMAGE" "$REGISTRY_IMAGE"
info "Registry-scoped image tag: $REGISTRY_IMAGE"

step "Push the image into the local registry"
info "After this push, smolvm can resolve and pull the image through the standard OCI registry path."
docker push "$REGISTRY_IMAGE"

step "Pack the image into a .smolmachine artifact"
info "This runs: $SMOLVM_BIN pack create --image $REGISTRY_IMAGE -o $OUTPUT_PATH"
"$SMOLVM_BIN" pack create --image "$REGISTRY_IMAGE" -o "$OUTPUT_PATH"

step "Verify the expected output artifacts"
[[ -f "$OUTPUT_PATH" ]] || fail "expected packed launcher was not created: $OUTPUT_PATH"
[[ -f "$OUTPUT_PATH.smolmachine" ]] || fail "expected sidecar was not created: $OUTPUT_PATH.smolmachine"
info "Created launcher: $OUTPUT_PATH"
info "Created sidecar: $OUTPUT_PATH.smolmachine"

step "Next steps"
info "Run the packed artifact directly:"
info "  $OUTPUT_PATH run -- echo hello"
info "Or create a managed machine from the sidecar:"
info "  $SMOLVM_BIN machine create my-vm --from $OUTPUT_PATH.smolmachine"

step "Cleanup"
info "The temporary registry container and temporary registry tag will be removed on exit."
