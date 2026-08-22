#!/usr/bin/env bash
# End-to-end validation: a Pod scheduled onto the smolvm runtime boots as a
# microVM, runs, streams logs, and accepts exec — through the real k3s/k8s API.
# Run AFTER install-smolvm-k3s.sh.
#
#   sudo ./e2e-test.sh
#
# Exits non-zero (and prints why) on any failure, so it can gate CI / a demo.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
K="k3s kubectl"
POD=smolvm-hello

fail() { echo "E2E FAIL: $*" >&2; $K describe pod "$POD" 2>/dev/null | tail -20 >&2 || true; exit 1; }

echo "==> RuntimeClass 'smolvm' registered?"
$K get runtimeclass smolvm >/dev/null 2>&1 || fail "RuntimeClass smolvm missing (run install-smolvm-k3s.sh)"

echo "==> deploying the smolvm pod"
$K delete pod "$POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
$K apply -f "$HERE/../kubernetes/example-pod.yaml" >/dev/null

echo "==> waiting for Ready (microVM boot)"
$K wait --for=condition=Ready "pod/$POD" --timeout=150s || fail "pod never became Ready"

echo "==> the pod really runs on the smolvm runtime handler"
RC=$($K get "pod/$POD" -o jsonpath='{.spec.runtimeClassName}')
[ "$RC" = smolvm ] || fail "pod runtimeClassName is '$RC', expected smolvm"

echo "==> logs show the workload ran inside a VM kernel"
LOGS=$($K logs "$POD")
echo "$LOGS" | sed 's/^/    /'
echo "$LOGS" | grep -q SMOLVM_K8S_E2E_OK || fail "expected marker not in logs"

# The assertion that can actually fail. A microVM boots its own kernel, so the
# guest's `uname -sr` differs from the node's; under runc the container shares
# the host kernel and the two strings are identical. Grepping for the "kernel:"
# prefix only matched the echo in example-pod.yaml, which any runtime prints.
GUEST_KERNEL=$(printf '%s\n' "$LOGS" | sed -n 's/^kernel: //p' | head -1)
[ -n "$GUEST_KERNEL" ] || fail "no kernel line in logs"
HOST_KERNEL=$(uname -sr)
echo "    guest kernel: $GUEST_KERNEL"
echo "    host kernel:  $HOST_KERNEL"
[ "$GUEST_KERNEL" != "$HOST_KERNEL" ] \
    || fail "guest kernel '$GUEST_KERNEL' is the node's own — the workload is not in a microVM"

echo "==> exec into the running microVM"
UID_OUT=$($K exec "$POD" -- id 2>/dev/null) || fail "kubectl exec failed"
echo "    exec id -> $UID_OUT"
echo "$UID_OUT" | grep -q "uid=" || fail "exec did not return a valid id"

echo "==> tearing the pod (microVM) down"
$K delete pod "$POD" --wait=true >/dev/null

echo
echo "E2E PASS: smolvm pod booted as a microVM, ran, logged, exec'd, and tore down cleanly via k3s."
