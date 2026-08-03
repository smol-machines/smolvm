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
#   sudo ./scripts/install-k8s-runtime.sh [--shim PATH] [--runtime-dir DIR] [--smolvm PATH]
#
#   --shim PATH          The built containerd-shim-smolvm-v2 binary
#                        (default: target/release/containerd-shim-smolvm-v2).
#   --runtime-dir DIR    A directory holding the smolvm runtime artifacts to
#                        install into /var/lib/smolvm: lib/ (libkrun*.so),
#                        init.krun, agent-rootfs/, and the smolvm binary
#                        (smolvm-bin in a distribution directory). If omitted,
#                        the artifacts already under /var/lib/smolvm are kept
#                        and only the shim is (re)installed.
#   --smolvm PATH        The smolvm binary to install as the VM boot helper
#                        /var/lib/smolvm/smolvm-vmm. Defaults to smolvm-bin (or
#                        smolvm) inside --runtime-dir, else target/release/smolvm.
#                        The engine boots each pod VM as a subprocess
#                        `<boot helper> _boot-vm <config.json>`; the shim binary
#                        cannot serve that, so this helper is REQUIRED — without
#                        it no pod sandbox boots.
#
set -euo pipefail

SHIM_SRC="target/release/containerd-shim-smolvm-v2"
RUNTIME_SRC=""
SMOLVM_SRC=""
DATA_DIR="/var/lib/smolvm"
BIN_DIR="/usr/local/bin"
SHIM_DST="$BIN_DIR/containerd-shim-smolvm-v2"
BOOT_DST="$DATA_DIR/smolvm-vmm"
RUNTIME_ARTIFACTS=(lib init.krun agent-rootfs)

while [ $# -gt 0 ]; do
    case "$1" in
        --shim) SHIM_SRC="$2"; shift 2 ;;
        --runtime-dir) RUNTIME_SRC="$2"; shift 2 ;;
        --smolvm) SMOLVM_SRC="$2"; shift 2 ;;
        -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
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

# The VM boot helper. The engine spawns `<boot helper> _boot-vm <config.json>`
# per VM (see agent::manager), pointed at $SMOLVM_BOOT_BINARY, which the shim
# defaults to $DATA_DIR/smolvm-vmm. A distribution ships the real binary as
# smolvm-bin (plain `smolvm` there is a wrapper script, no good as a boot exec).
if [ -z "$SMOLVM_SRC" ] && [ -n "$RUNTIME_SRC" ]; then
    for c in smolvm-bin smolvm; do
        if [ -f "$RUNTIME_SRC/$c" ] && [ -x "$RUNTIME_SRC/$c" ]; then SMOLVM_SRC="$RUNTIME_SRC/$c"; break; fi
    done
fi
[ -n "$SMOLVM_SRC" ] || SMOLVM_SRC="target/release/smolvm"
if [ -f "$SMOLVM_SRC" ]; then
    echo "==> Installing VM boot helper: $SMOLVM_SRC -> $BOOT_DST"
    install -Dm755 "$SMOLVM_SRC" "$BOOT_DST.tmp"
    mv -f "$BOOT_DST.tmp" "$BOOT_DST"
elif [ ! -x "$BOOT_DST" ]; then
    echo "error: no smolvm binary to install as the boot helper ($SMOLVM_SRC not found)" >&2
    echo "       build it with: cargo build --release  (or pass --smolvm PATH)" >&2
    exit 1
else
    echo "==> Keeping existing VM boot helper: $BOOT_DST"
fi

# Pre-formatted disk templates. Without them every VM's storage/overlay disk is
# built with mkfs.ext4 at boot instead of a hole-preserving copy (or a qcow2
# overlay off the template), which is markedly slower per pod. The engine looks
# them up at $HOME/.smolvm/, and the shim roots HOME at $DATA_DIR — so they go in
# $DATA_DIR/.smolvm. Sizing to the default virtual size here is what lets the fast
# overlay path be used at boot (mirrors scripts/install.sh).
if [ -n "$RUNTIME_SRC" ]; then
    mkdir -p "$DATA_DIR/.smolvm"
    for t in storage-template.ext4:20G overlay-template.ext4:10G; do
        name="${t%%:*}"; size="${t##*:}"
        if [ -f "$RUNTIME_SRC/$name" ]; then
            echo "==> Installing disk template: $name (sized $size)"
            cp --sparse=always "$RUNTIME_SRC/$name" "$DATA_DIR/.smolvm/$name" 2>/dev/null \
                || cp "$RUNTIME_SRC/$name" "$DATA_DIR/.smolvm/$name"
            truncate -s "$size" "$DATA_DIR/.smolvm/$name"
        else
            echo "    note: $name not in $RUNTIME_SRC — disks will be mkfs'd per VM (slower)" >&2
        fi
    done
fi

# Sanity-check the artifacts the shim will need at runtime are present.
missing=0
for a in lib/libkrun.so agent-rootfs smolvm-vmm; do
    [ -e "$DATA_DIR/$a" ] || { echo "error: required artifact missing: $DATA_DIR/$a" >&2; missing=1; }
done
[ "$missing" = 0 ] || { echo "install incomplete — supply --runtime-dir with a smolvm distribution" >&2; exit 1; }

# The boot helper must actually serve `_boot-vm` — installing the wrong binary
# here (the shim, a wrapper script) fails at the first pod, not at install time.
if ! "$BOOT_DST" _boot-vm --help >/dev/null 2>&1; then
    echo "error: $BOOT_DST does not serve '_boot-vm' — it is not a smolvm binary." >&2
    echo "       Pod sandboxes cannot boot without it. Pass --smolvm PATH." >&2
    exit 1
fi

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
