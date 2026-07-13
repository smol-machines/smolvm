#!/usr/bin/env bash
#
# Install the smolvm Kubernetes runtime (containerd shim v2) on a node.
#
# Lays down the shim binary and the runtime artifacts smolvm's embedded engine
# needs (libkrun, the guest kernel init, the agent rootfs, the VM monitor), then
# prints the containerd runtime-class registration to add. It deliberately does
# NOT edit /etc/containerd/config.toml or restart containerd — those are shown so
# an operator (or a config-management tool) applies them deliberately.
#
# Usage:
#   sudo ./scripts/install-k8s-runtime.sh [--shim PATH] [--runtime-dir DIR]
#
#   --shim PATH          The built containerd-shim-smolvm-v2 binary
#                        (default: target/release/containerd-shim-smolvm-v2).
#   --runtime-dir DIR    A directory holding the smolvm runtime artifacts to
#                        install into /var/lib/smolvm: lib/ (libkrun*.so),
#                        init.krun, smolvm-vmm, agent-rootfs/. A smolvm Linux
#                        distribution directory has these. If omitted, the
#                        artifacts already under /var/lib/smolvm are kept and
#                        only the shim is (re)installed.
#
set -euo pipefail

SHIM_SRC="target/release/containerd-shim-smolvm-v2"
RUNTIME_SRC=""
DATA_DIR="/var/lib/smolvm"
BIN_DIR="/usr/local/bin"
SHIM_DST="$BIN_DIR/containerd-shim-smolvm-v2"
RUNTIME_ARTIFACTS=(lib init.krun smolvm-vmm agent-rootfs)

while [ $# -gt 0 ]; do
    case "$1" in
        --shim) SHIM_SRC="$2"; shift 2 ;;
        --runtime-dir) RUNTIME_SRC="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "error: run as root (sudo)" >&2; exit 1; }
[ -f "$SHIM_SRC" ] || { echo "error: shim binary not found: $SHIM_SRC (build with: cargo build --release -p smolvm-shim)" >&2; exit 1; }

echo "==> Installing runtime artifacts into $DATA_DIR"
mkdir -p "$DATA_DIR"
if [ -n "$RUNTIME_SRC" ]; then
    [ -d "$RUNTIME_SRC" ] || { echo "error: --runtime-dir not a directory: $RUNTIME_SRC" >&2; exit 1; }
    for a in "${RUNTIME_ARTIFACTS[@]}"; do
        if [ -e "$RUNTIME_SRC/$a" ]; then
            echo "    $a"
            rm -rf "${DATA_DIR:?}/$a"
            cp -a "$RUNTIME_SRC/$a" "$DATA_DIR/"   # -a preserves the agent-rootfs symlinks
        else
            echo "    warning: $a not found in $RUNTIME_SRC — leaving existing" >&2
        fi
    done
else
    echo "    (no --runtime-dir; keeping existing artifacts)"
fi

# Sanity-check the artifacts the shim will need at runtime are present.
missing=0
for a in lib/libkrun.so agent-rootfs smolvm-vmm; do
    [ -e "$DATA_DIR/$a" ] || { echo "error: required artifact missing: $DATA_DIR/$a" >&2; missing=1; }
done
[ "$missing" = 0 ] || { echo "install incomplete — supply --runtime-dir with a smolvm distribution" >&2; exit 1; }

echo "==> Installing shim: $SHIM_SRC -> $SHIM_DST"
install -Dm755 "$SHIM_SRC" "$SHIM_DST.tmp"
mv -f "$SHIM_DST.tmp" "$SHIM_DST"   # atomic swap: tolerates a running/busy shim binary

echo "==> Verifying the shim binary runs"
if "$SHIM_DST" -v >/dev/null 2>&1 || "$SHIM_DST" --help >/dev/null 2>&1; then
    echo "    ok"
else
    echo "    (shim has no version flag; binary installed)"
fi

CONF="/etc/containerd/config.toml"
echo
echo "==> containerd registration"
if grep -q 'io.containerd.smolvm.v2' "$CONF" 2>/dev/null; then
    echo "    already registered in $CONF — nothing to change."
else
    cat <<'EOF'
    Add the smolvm runtime class to /etc/containerd/config.toml under the CRI
    runtimes table (path shown for containerd 2.x; for 1.x use
    plugins."io.containerd.grpc.v1.cri".containerd.runtimes.smolvm):

      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.smolvm]
        runtime_type = 'io.containerd.smolvm.v2'
        sandboxer = 'podsandbox'

    Then restart containerd:

      systemctl restart containerd

    and create the RuntimeClass in the cluster:

      kubectl apply -f - <<'YAML'
      apiVersion: node.k8s.io/v1
      kind: RuntimeClass
      metadata:
        name: smolvm
      handler: smolvm
      YAML
EOF
fi
echo
echo "Done. Run pods with runtimeClassName: smolvm (VM-grade isolation)."
