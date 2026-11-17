# Tearing down the Kubernetes runtime

Only relevant if you installed the smolvm containerd shim on a node. Deleting the pod is not the
whole job: the runtime install is system-wide, the uninstaller does not know about it, and every
command below reports success while leaving state behind.

The sweep and the root-owned state below were verified on Ubuntu 22.04 x86_64 with k3s on
v1.14.2. The lines for the `RuntimeClass`, the node label and the systemd drop-in are read from the
repository's `deploy/k3s/install-smolvm-k3s.sh` and `deploy/k3s/uninstall-smolvm-k3s.sh` at v1.22.2
and were not run on a node. [Kubernetes](../../kubernetes.md) is the install side.

```bash
kubectl delete pod <name> --wait=true
kubectl get pods                                  # No resources found

# then, if you installed the runtime with deploy/k3s/install-smolvm-k3s.sh:
sudo k3s kubectl delete runtimeclass smolvm --ignore-not-found
sudo k3s kubectl label node --all smolvm-runtime-
sudo rm -f /etc/systemd/system/k3s.service.d/smolvm.conf   # smolvm's own drop-in only
sudo rmdir /etc/systemd/system/k3s.service.d                # refuses if anything else is in it
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/containerd-shim-smolvm-v2
sudo rm -f /usr/local/bin/containerd-shim-smolvm-v2.real    # only where the shim was wrapped by hand
sudo rm -rf /var/lib/smolvm
sudo /usr/local/bin/k3s-uninstall.sh              # if you installed k3s
sudo rm -rf /var/lib/rancher                      # k3s-uninstall can leave this behind

# the shim runs as root, so its VM state is in root's home, not yours:
sudo rm -rf /var/lib/containerd-shim-smolvm /root/.cache/smolvm /root/.local/share/smolvm
sudo rm -rf /var/log/pods/*smolvm* /var/log/containers/*smolvm*
```

`deploy/k3s/uninstall-smolvm-k3s.sh` at v1.22.2 does the first five of those lines and also removes
two things the lines above leave behind: smolvm's block in k3s's containerd template and the shim
symlink under `/var/lib/rancher/k3s/data/current/bin/`. On a node that keeps k3s, use the script
for that reason. Like the lines above, this is read from the script and was not run. The
`.real` file exists only where the shim was replaced by a hand-made wrapper that runs it with
standard input from `/dev/null` (the workaround for #889); the repository's scripts do not create
it.

Then prove it:

```bash
sudo find / -iname '*smolvm*' -not -path '/proc/*' -not -path '/sys/*'    # expect nothing
```

**Why the last two removal lines exist.** After `k3s-uninstall.sh` plus removing the shim and
`/var/lib/smolvm`, a filesystem sweep still found five more locations: `/var/lib/containerd-shim-smolvm` (4.5 MB),
`/root/.cache/smolvm` (9.0 MB), `/root/.local/share/smolvm` (312 KB), and pod logs under
`/var/log/pods` and `/var/log/containers`. **The shim runs as root, so its VM state lands in
root's home rather than the operator's**, which is why a teardown run as the operator misses it.
Only after removing those did the sweep come back empty.

A GPU on the node is unaffected throughout: `nvidia-smi` still reported the device after the full
sequence.
