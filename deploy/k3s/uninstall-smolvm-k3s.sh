#!/usr/bin/env bash
# Remove smolvm as a k3s container runtime — the inverse of
# install-smolvm-k3s.sh.
#
# The installer touches five places (systemd drop-in, containerd template, a shim
# symlink, node labels, the RuntimeClass). Undoing that by hand is easy to get
# wrong, and the two pieces most likely to be forgotten — the drop-in and the
# template — are exactly the ones that break a later k3s reconfigure.
#
#   sudo ./uninstall-smolvm-k3s.sh
#
# Leaves the runtime payload under $SMOLVM_DATA_DIR and the shim binary alone;
# this only unwires them from k3s.
set -euo pipefail

K3S_CTD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
TMPL="$K3S_CTD_DIR/config.toml.tmpl"
DROPIN=/etc/systemd/system/k3s.service.d/smolvm.conf

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

echo "==> removing the RuntimeClass and node labels"
if command -v k3s >/dev/null && k3s kubectl get --raw='/readyz' >/dev/null 2>&1; then
  k3s kubectl delete runtimeclass smolvm --ignore-not-found >/dev/null || true
  k3s kubectl label node --all smolvm-runtime- >/dev/null 2>&1 || true
else
  echo "    k3s not reachable — skipping cluster objects"
fi

echo "==> removing the smolvm runtime block from the containerd template"
if [ -f "$TMPL" ]; then
  # Always strip just our block, never restore the install-time backup over the
  # live file. The installer states the rule this follows: config.toml.tmpl is
  # where operators put registry mirrors and private-registry auth, "so it is NOT
  # ours to overwrite", and "a lost mirror config breaks image pulls cluster-wide
  # and the cause is hard to trace". Restoring a snapshot taken at install time
  # discards everything the operator added since, which can be months of edits.
  if grep -q 'runtimes\.smolvm\]' "$TMPL"; then
    # Drop the smolvm table header and its runtime_type line.
    sed -i '/runtimes\.smolvm\]/,+1d' "$TMPL"
    # A template that is now nothing but the base include is what k3s generates
    # by default, so remove it rather than leave a no-op file behind.
    if [ "$(grep -cvE '^[[:space:]]*($|\{\{ template "base" \. \}\})' "$TMPL")" = 0 ]; then
      rm -f "$TMPL"
      echo "    template held only the base include — removed"
    fi
  else
    # Our block is absent, so there is nothing to strip. This is the one case the
    # backup is for: a template edited between our header and its runtime_type
    # line, which sed cannot match. Leave both files alone and say so, rather
    # than overwriting the operator's file on a guess.
    echo "    no smolvm runtime block found in $TMPL — leaving it untouched"
    BACKUP=$(ls -1t "$TMPL".pre-smolvm.* 2>/dev/null | head -1 || true)
    if [ -n "$BACKUP" ]; then
      echo "    if it was hand-edited, the install-time copy is at $BACKUP"
    fi
  fi
fi

echo "==> removing the shim symlink and systemd drop-in"
rm -f /var/lib/rancher/k3s/data/current/bin/containerd-shim-smolvm-v2
rm -f "$DROPIN"
rmdir /etc/systemd/system/k3s.service.d 2>/dev/null || true
systemctl daemon-reload

echo "==> restarting k3s to drop the runtime"
if systemctl is-active --quiet k3s; then
  systemctl restart k3s
  for _ in $(seq 1 60); do k3s kubectl get --raw='/readyz' >/dev/null 2>&1 && break; sleep 2; done
fi

echo
echo "smolvm unwired from k3s. The payload under /var/lib/smolvm and the shim binary were left in place."
