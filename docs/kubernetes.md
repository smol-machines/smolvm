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

## Sizing a pod's VM

A pod's VM gets 2 vCPUs and 1 GiB of memory, whatever its containers' resources say. To ask for another size, annotate the pod:

```yaml
metadata:
  annotations:
    smolvm.io/cpus: "4"
    smolvm.io/memory-mib: "4096"
```

Either can be set alone. `smolvm.io/cpus` takes 1 to 16 and `smolvm.io/memory-mib` takes 64 or more. A value outside that, or that is not a number (`4Gi`), logs a warning and leaves the default.

containerd only passes on annotations the runtime allows, so the runtime's table needs `pod_annotations = ['smolvm.io/*']`, as the install scripts now print. Without it the annotations are ignored, with no warning, and an existing install has to add the line and restart containerd.

Memory is a ceiling rather than a reservation: the host only uses what the guest does. The VM runs outside the pod's cgroup, so neither the kubelet nor a container's memory limit bounds it on the host.
