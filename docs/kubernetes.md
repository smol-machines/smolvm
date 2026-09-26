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
