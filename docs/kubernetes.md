# Kubernetes

smolvm ships a **containerd shim v2**, so Kubernetes runs a pod as its own microVM
through a `RuntimeClass`, the same integration point Kata uses. The Linux release
carries the shim and the manifests; there is nothing to build.

On each node that should run microVM pods (requires KVM):

```bash
# 1. install the shim + runtime artifacts, then apply the containerd config it prints
sudo ./kubernetes/install-k8s-runtime.sh
sudo systemctl restart containerd

# 2. label the node so the RuntimeClass will schedule to it
kubectl label node <node> smolvm-runtime=true
```

Then register the class and run a pod:

```bash
kubectl apply -f kubernetes/runtimeclass.yaml
kubectl apply -f kubernetes/example-pod.yaml
kubectl logs smolvm-hello    # prints the guest's own kernel, so it is a real VM
```

Any pod opts in with `runtimeClassName: smolvm`.

## Shim child-process ownership

The embedded engine waits for foreground helpers such as `cp`, `chmod` and
image-extraction tools through their own `Child` handles. The shim configures
containerd-shim without its process-wide reaper: an independent `waitpid(-1)`
can otherwise consume a helper's exit first and make its real owner report
`ECHILD` (`No child processes`), even after a successful copy.

Detached VM boot processes remain registered with the engine's per-PID reaper.
The shim sweeps that registry in the background, preserving exit status even
when no client performs a liveness query. It does not become a subreaper for
unregistered grandchildren; their supervising ancestor remains responsible.
Guest task exits still use the existing guest event/watch path.

The Linux regression uses the real containerd-shim bootstrap and SIGCHLD loop in
separate fixture processes. It demonstrates the old competing wait and checks
helper results, cancellation signals, copies, detached VM exits and orphan
ownership without requiring KVM or a containerd daemon:

```bash
cargo test --locked -p smolvm-shim
```
