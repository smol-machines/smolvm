#!/usr/bin/env bash
# Install smolvm as a k3s container runtime (RuntimeClass "smolvm").
#
# Wires the smolvm containerd shim v2 into k3s's embedded containerd so pods with
# `runtimeClassName: smolvm` boot as per-workload microVMs. Version-robust: it
# reads k3s's *generated* containerd config to find the exact CRI plugin path
# (containerd 1.x and 2.x differ) instead of hardcoding it.
#
# Prereqs: k3s installed, and the smolvm runtime payload present under
# $SMOLVM_DATA_DIR (agent-rootfs, smolvm-vmm boot helper, lib/, and the shim
# binary on PATH). See docs/kubernetes-runtime.md for building the payload.
#
#   sudo ./install-smolvm-k3s.sh
#   sudo k3s kubectl apply -f ../kubernetes/example-pod.yaml   # e2e smoke test
set -euo pipefail

SMOLVM_DATA_DIR=${SMOLVM_DATA_DIR:-/var/lib/smolvm}
SHIM=${SHIM:-/usr/local/bin/containerd-shim-smolvm-v2}
K3S_CTD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
command -v k3s >/dev/null || { echo "k3s not found on PATH"; exit 1; }

echo "==> verifying smolvm runtime payload"
for f in "$SHIM" "$SMOLVM_DATA_DIR/agent-rootfs" "$SMOLVM_DATA_DIR/smolvm-vmm" "$SMOLVM_DATA_DIR/lib"; do
  [ -e "$f" ] || { echo "  MISSING: $f — install the smolvm runtime payload first"; exit 1; }
done

echo "==> exporting the shim's env to k3s (the shim inherits k3s -> containerd env)"
mkdir -p /etc/systemd/system/k3s.service.d
cat > /etc/systemd/system/k3s.service.d/smolvm.conf <<EOF
[Service]
Environment=SMOLVM_DATA_DIR=$SMOLVM_DATA_DIR
Environment=SMOLVM_AGENT_ROOTFS=$SMOLVM_DATA_DIR/agent-rootfs
Environment=SMOLVM_BOOT_BINARY=$SMOLVM_DATA_DIR/smolvm-vmm
Environment=SMOLVM_LIB_DIR=$SMOLVM_DATA_DIR/lib
EOF
systemctl daemon-reload

echo "==> ensuring k3s is up and has generated its base containerd config"
systemctl enable --now k3s
for _ in $(seq 1 60); do [ -f "$K3S_CTD_DIR/config.toml" ] && break; sleep 2; done
CFG="$K3S_CTD_DIR/config.toml"
[ -f "$CFG" ] || { echo "  k3s did not generate $CFG"; exit 1; }

echo "==> detecting the CRI runtimes plugin path k3s uses"
# e.g. [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]  (ctd 2.x)
#  or  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]     (ctd 1.x)
RUNC_HDR=$(grep -E '\.containerd\.runtimes\.runc\]\s*$' "$CFG" | head -1)
[ -n "$RUNC_HDR" ] || { echo "  couldn't find the runc runtimes block in $CFG"; exit 1; }
SMOLVM_HDR=${RUNC_HDR/.runtimes.runc]/.runtimes.smolvm]}
echo "    runc:   $RUNC_HDR"
echo "    smolvm: $SMOLVM_HDR"

echo "==> writing k3s containerd template (base + smolvm runtime, no [options])"
# NB: we deliberately omit the runc-style [...options] sub-table — those options
# (BinaryName/SystemdCgroup) crash our shim; the smolvm shim takes none.
cat > "$K3S_CTD_DIR/config.toml.tmpl" <<EOF
{{ template "base" . }}

$SMOLVM_HDR
  runtime_type = "io.containerd.smolvm.v2"
EOF

echo "==> putting the shim on k3s containerd's PATH"
if [ -d /var/lib/rancher/k3s/data/current/bin ]; then
  ln -sf "$SHIM" /var/lib/rancher/k3s/data/current/bin/containerd-shim-smolvm-v2
fi

echo "==> restarting k3s to apply the template"
systemctl restart k3s
for _ in $(seq 1 60); do k3s kubectl get --raw='/readyz' >/dev/null 2>&1 && break; sleep 2; done

echo "==> labelling nodes + applying the smolvm RuntimeClass"
k3s kubectl label node --all smolvm-runtime=true --overwrite
k3s kubectl apply -f "$HERE/../kubernetes/runtimeclass.yaml"

cat <<EOF

smolvm is installed as a k3s runtime.
  Smoke test:  sudo k3s kubectl apply -f $HERE/../kubernetes/example-pod.yaml
               sudo k3s kubectl wait --for=condition=Ready pod/smolvm-hello --timeout=120s
               sudo k3s kubectl logs smolvm-hello   # expect SMOLVM_K8S_E2E_OK + a VM kernel
EOF
