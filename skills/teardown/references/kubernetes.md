# Tearing down the Kubernetes runtime

Only relevant if you installed the smolvm containerd shim on a node. Deleting the pod is not the
whole job: the runtime install is system-wide, the uninstaller does not know about it, and every
command below reports success while leaving state behind.

Verified on Ubuntu 22.04 x86_64 with k3s.

```bash
kubectl delete pod <name> --wait=true
kubectl get pods                                  # No resources found

# then, if you installed the runtime:
sudo rm -f /usr/local/bin/containerd-shim-smolvm-v2 /usr/local/bin/containerd-shim-smolvm-v2.real
sudo rm -rf /var/lib/smolvm /etc/systemd/system/k3s.service.d
sudo /usr/local/bin/k3s-uninstall.sh              # if you installed k3s
sudo rm -rf /var/lib/rancher                      # k3s-uninstall can leave this behind

# the shim runs as root, so its VM state is in root's home, not yours:
sudo rm -rf /var/lib/containerd-shim-smolvm /root/.cache/smolvm /root/.local/share/smolvm
sudo rm -rf /var/log/pods/*smolvm* /var/log/containers/*smolvm*
```

Then prove it:

```bash
sudo find / -iname '*smolvm*' -not -path '/proc/*' -not -path '/sys/*'    # expect nothing
```

**Why the last two removal lines exist.** After `k3s-uninstall.sh` plus removing the shim and
`/var/lib/smolvm`, which is everything the docs and the obvious reading describe, a filesystem
sweep still found five more locations: `/var/lib/containerd-shim-smolvm` (4.5 MB),
`/root/.cache/smolvm` (9.0 MB), `/root/.local/share/smolvm` (312 KB), and pod logs under
`/var/log/pods` and `/var/log/containers`. **The shim runs as root, so its VM state lands in
root's home rather than the operator's**, which is why a teardown run as the operator misses it.
Only after removing those did the sweep come back empty.

A GPU on the node is unaffected throughout: `nvidia-smi` still reported the device after the full
sequence.
