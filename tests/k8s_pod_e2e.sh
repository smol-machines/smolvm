#!/usr/bin/env bash
#
# End-to-end check for the Kubernetes runtime (containerd-shim-smolvm-v2).
#
# Run ON THE NODE, as root, after scripts/install-k8s-runtime.sh and the
# containerd + RuntimeClass registration it prints. Two phases:
#
#   preflight  Host and install checks that touch nothing (KVM, containerd
#              registration, runtime artifacts, boot helper, reflink support).
#   pod        Creates one pod through the smolvm RuntimeClass and asserts it
#              really is a VM (own kernel, own CPU count), that logs/exec/pod-IP
#              work, and that teardown leaves nothing behind.
#
# Usage:
#   sudo ./tests/k8s_pod_e2e.sh [--preflight-only] [--image IMG] [--keep]
#
#   --preflight-only  Stop after the host checks; never touches the cluster.
#   --image IMG       Pod image (default: nginx:1.27-alpine; must serve :80).
#   --keep            Leave the pod running (for manual poking / a demo).
#
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
ok()   { echo -e "  ${GREEN}PASS${NC}  $*"; PASS=$((PASS+1)); }
bad()  { echo -e "  ${RED}FAIL${NC}  $*"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $*"; WARN=$((WARN+1)); }
phase(){ echo -e "\n${BLUE}==> $*${NC}"; }

IMAGE="nginx:1.27-alpine"
PREFLIGHT_ONLY=0
KEEP=0
DATA_DIR="/var/lib/smolvm"
SHARE_ROOT="/var/lib/containerd-shim-smolvm"
POD="smolvm-e2e-$$"

while [ $# -gt 0 ]; do
    case "$1" in
        --preflight-only) PREFLIGHT_ONLY=1; shift ;;
        --image) IMAGE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ============================== preflight ==============================

phase "Preflight: host"

[ "$(id -u)" = 0 ] && ok "running as root" || bad "not root — rerun with sudo"

if [ -e /dev/kvm ]; then
    [ -r /dev/kvm ] && [ -w /dev/kvm ] && ok "/dev/kvm present and writable" \
        || bad "/dev/kvm exists but is not writable by this user"
else
    bad "/dev/kvm missing — no hardware virtualization (nested virt off?). Pods cannot boot."
fi

if command -v containerd >/dev/null 2>&1; then
    CTD_VER="$(containerd --version 2>/dev/null | awk '{print $3}')"
    case "$CTD_VER" in
        v2.*) ok "containerd $CTD_VER" ;;
        v1.*) warn "containerd $CTD_VER — the shim targets 2.x; 1.x needs the legacy CRI config path and lacks the sandbox grouping this shim relies on" ;;
        *)    warn "containerd version not parsed: ${CTD_VER:-unknown}" ;;
    esac
else
    bad "containerd not on PATH"
fi

phase "Preflight: install"

SHIM="$(command -v containerd-shim-smolvm-v2 || echo /usr/local/bin/containerd-shim-smolvm-v2)"
if [ -x "$SHIM" ]; then
    ok "shim installed: $SHIM"
    SHIM_ARCH="$(file -b "$SHIM" 2>/dev/null | grep -o 'x86-64\|aarch64\|ARM aarch64' | head -1)"
    HOST_ARCH="$(uname -m)"
    case "$HOST_ARCH:$SHIM_ARCH" in
        x86_64:x86-64|aarch64:aarch64|aarch64:"ARM aarch64") ok "shim arch matches host ($HOST_ARCH)" ;;
        *:"") warn "could not determine shim arch (file(1) unavailable?)" ;;
        *) bad "shim arch '$SHIM_ARCH' does not match host $HOST_ARCH — built on the wrong machine" ;;
    esac
else
    bad "shim not found at $SHIM (build: cargo build --release -p smolvm-shim, then scripts/install-k8s-runtime.sh)"
fi

for a in lib/libkrun.so agent-rootfs smolvm-vmm; do
    [ -e "$DATA_DIR/$a" ] && ok "artifact present: $DATA_DIR/$a" \
        || bad "artifact MISSING: $DATA_DIR/$a"
done

# The engine boots each pod VM as `<boot helper> _boot-vm <config.json>`. The
# shim binary cannot serve that, so a wrong/absent helper means no pod ever boots.
if [ -x "$DATA_DIR/smolvm-vmm" ]; then
    if "$DATA_DIR/smolvm-vmm" _boot-vm --help >/dev/null 2>&1; then
        ok "boot helper serves _boot-vm"
    else
        bad "$DATA_DIR/smolvm-vmm does not serve _boot-vm — not a smolvm binary. No pod will boot."
    fi
fi

if containerd config dump 2>/dev/null | grep -q 'io.containerd.smolvm.v2'; then
    ok "containerd registers io.containerd.smolvm.v2"
    containerd config dump 2>/dev/null | grep -q "sandboxer = 'podsandbox'\|sandboxer = \"podsandbox\"" \
        && ok "sandboxer = podsandbox" \
        || warn "runtime registered without sandboxer='podsandbox' — container tasks may not reach the pod's shim"
else
    bad "containerd config has no io.containerd.smolvm.v2 runtime (add it and restart containerd)"
fi

phase "Preflight: filesystem (pod start cost)"

mkdir -p "$SHARE_ROOT"
SHARE_FS="$(stat -f -c %T "$SHARE_ROOT" 2>/dev/null)"
CTD_ROOT="/var/lib/containerd"
CTD_FS="$(stat -f -c %T "$CTD_ROOT" 2>/dev/null || echo unknown)"
echo "      pod share:  $SHARE_ROOT ($SHARE_FS)"
echo "      snapshots:  $CTD_ROOT ($CTD_FS)"

SHARE_DEV="$(stat -c %d "$SHARE_ROOT" 2>/dev/null)"
CTD_DEV="$(stat -c %d "$CTD_ROOT" 2>/dev/null || echo none)"
[ "$SHARE_DEV" = "$CTD_DEV" ] && ok "pod share and snapshotter are on the same filesystem" \
    || warn "pod share and snapshotter are on DIFFERENT filesystems — every container rootfs is a full byte copy"

# Empirical, not by filesystem name: does a reflink actually succeed here?
RT="$SHARE_ROOT/.reflink-probe"
rm -rf "$RT"; mkdir -p "$RT"
head -c 1048576 /dev/urandom > "$RT/src" 2>/dev/null
if cp --reflink=always "$RT/src" "$RT/dst" 2>/dev/null; then
    ok "reflink works on the pod share — container rootfs copies are near-free"
else
    warn "reflink NOT supported here (ext4?) — each container start copies the whole image. Expect slow pod starts; use XFS (reflink=1) or Btrfs."
fi
rm -rf "$RT"

if [ "$PREFLIGHT_ONLY" = 1 ]; then
    phase "Preflight summary"
    echo -e "  ${GREEN}$PASS passed${NC}, ${YELLOW}$WARN warnings${NC}, ${RED}$FAIL failed${NC}"
    [ "$FAIL" = 0 ] && exit 0 || exit 1
fi

if [ "$FAIL" != 0 ]; then
    echo -e "\n${RED}Preflight failed — not starting a pod. Fix the above first.${NC}"
    exit 1
fi

# ================================ pod ==================================

command -v kubectl >/dev/null 2>&1 || { echo -e "${RED}kubectl not on PATH${NC}"; exit 1; }

cleanup() {
    if [ "$KEEP" = 1 ]; then
        echo -e "\n${YELLOW}--keep: leaving pod/$POD running${NC}"
        return
    fi
    kubectl delete pod "$POD" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1
}
trap cleanup EXIT

phase "Pod: RuntimeClass"
if kubectl get runtimeclass smolvm >/dev/null 2>&1; then
    ok "RuntimeClass smolvm exists"
else
    kubectl apply -f - >/dev/null <<'YAML' && ok "RuntimeClass smolvm created" || bad "could not create RuntimeClass"
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: smolvm
handler: smolvm
YAML
fi

phase "Pod: create $POD ($IMAGE)"
kubectl apply -f - >/dev/null <<YAML || bad "kubectl apply failed"
apiVersion: v1
kind: Pod
metadata:
  name: $POD
spec:
  runtimeClassName: smolvm
  containers:
    - name: app
      image: $IMAGE
      ports: [{containerPort: 80}]
YAML

START=$(date +%s)
if kubectl wait --for=condition=Ready "pod/$POD" --timeout=180s >/dev/null 2>&1; then
    ok "pod Ready in $(( $(date +%s) - START ))s"
else
    bad "pod never became Ready (180s)"
    echo -e "\n${YELLOW}--- kubectl describe ---${NC}"
    kubectl describe "pod/$POD" 2>&1 | tail -30
    echo -e "\n${YELLOW}--- containerd log (last 40) ---${NC}"
    journalctl -u containerd --no-pager -n 40 2>/dev/null | tail -40
    echo -e "\n${RED}$PASS passed, $WARN warnings, $FAIL failed${NC}"
    exit 1
fi

phase "Pod: is it actually a VM?"

HOST_KERNEL="$(uname -r)"
GUEST_KERNEL="$(kubectl exec "$POD" -- uname -r 2>/dev/null | tr -d '\r\n')"
if [ -n "$GUEST_KERNEL" ] && [ "$GUEST_KERNEL" != "$HOST_KERNEL" ]; then
    ok "guest kernel $GUEST_KERNEL != host kernel $HOST_KERNEL (real VM boundary)"
elif [ -z "$GUEST_KERNEL" ]; then
    bad "kubectl exec returned nothing — exec path broken"
else
    bad "guest kernel == host kernel ($HOST_KERNEL) — this is NOT running in a VM"
fi

CPUS="$(kubectl exec "$POD" -- sh -c 'grep -c ^processor /proc/cpuinfo' 2>/dev/null | tr -d '\r\n')"
[ "$CPUS" = "2" ] && ok "guest sees 2 vCPUs (the sandbox VM's fixed sizing)" \
    || warn "guest sees ${CPUS:-?} CPUs (expected 2 — the shim's hardcoded SANDBOX_CPUS)"

# Match the running executable, not a command line — a pgrep pattern matches this
# script's own argv (and any ssh wrapper carrying it) and reports false positives.
VMPROCS="$(ls -l /proc/*/exe 2>/dev/null | grep -c 'smolvm-vmm' || true)"
[ "${VMPROCS:-0}" -gt 0 ] && ok "$VMPROCS VM process(es) running on the node" \
    || warn "no smolvm-vmm process found — the pod may not be VM-backed"

phase "Pod: networking, logs, exec"

POD_IP="$(kubectl get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null)"
if [ -n "$POD_IP" ]; then
    ok "pod has a CNI IP: $POD_IP"
    if curl -sS --max-time 8 "http://$POD_IP" >/dev/null 2>&1; then
        ok "node reached $POD_IP:80 (netns-tap L2 bridge works)"
    else
        bad "could not reach $POD_IP:80 from the node — pod networking is not wired through"
    fi
else
    bad "pod has no IP — netns bridging failed (VM would only have NAT egress)"
fi

# The curl above is the request nginx should have logged.
if [ -n "$(kubectl logs "$POD" 2>/dev/null | head -c 1)" ]; then
    ok "kubectl logs streams container output"
else
    bad "kubectl logs is empty — the stdio pump is not delivering to containerd fifos"
fi

MARK="e2e-$RANDOM"
ECHOED="$(kubectl exec "$POD" -- sh -c "echo $MARK > /tmp/probe && cat /tmp/probe" 2>/dev/null | tr -d '\r\n')"
[ "$ECHOED" = "$MARK" ] && ok "exec round-trip (write + read in guest)" \
    || bad "exec round-trip failed (got '${ECHOED:-<empty>}')"

phase "Pod: teardown"
if [ "$KEEP" = 1 ]; then
    warn "--keep set; skipping teardown assertions"
else
    # What matters is BYTES reclaimed, not directory count: the rootfs copy is the
    # only thing with real size, and an empty <sandbox-id>/podshare skeleton left
    # behind costs ~4 KB. Counting dirs reports a scary leak that isn't one.
    KB_BEFORE="$(du -sk "$SHARE_ROOT" 2>/dev/null | cut -f1)"
    kubectl delete pod "$POD" --wait=true --timeout=90s >/dev/null 2>&1 \
        && ok "pod deleted" || bad "pod delete timed out"
    sleep 3
    KB_AFTER="$(du -sk "$SHARE_ROOT" 2>/dev/null | cut -f1)"
    if [ "${KB_AFTER:-0}" -lt 1024 ]; then
        ok "pod share reclaimed (${KB_BEFORE}KB -> ${KB_AFTER}KB; empty skeleton dirs are harmless)"
    else
        warn "$((KB_AFTER/1024))MB still under $SHARE_ROOT after delete — rootfs copies are not being reclaimed"
    fi
    VMPROCS_AFTER="$(ls -l /proc/*/exe 2>/dev/null | grep -c 'smolvm-vmm' || true)"
    [ "${VMPROCS_AFTER:-0}" = 0 ] && ok "no VM processes left behind" \
        || warn "$VMPROCS_AFTER smolvm-vmm process(es) still running after pod delete — orphaned VMs hold their full RAM"
fi

phase "Summary"
echo -e "  ${GREEN}$PASS passed${NC}, ${YELLOW}$WARN warnings${NC}, ${RED}$FAIL failed${NC}"
[ "$FAIL" = 0 ] || exit 1
