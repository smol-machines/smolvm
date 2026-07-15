# Deploying smolvm as a Kubernetes runtime

smolvm is a **containerd shim v2** CRI runtime (`io.containerd.smolvm.v2`): every
pod sandbox boots as its own microVM (the Kata/Firecracker model), so workloads
get hardware-level isolation instead of a shared kernel.

## Conformance status

`critest` (cri-tools v1.31.1) on the reference node: **82 Passed / 7 Failed /
24 Skipped** of 113 — at or above the runc baseline (79 passed) on the same host.

The 7 remaining failures are the boundary of *any* VM-based runtime and fail for
Kata / Firecracker / gVisor too:

| failing test(s) | why a microVM can't pass it |
| --- | --- |
| `portforward` ×2 | containerd's portforward dials `127.0.0.1` in the pod netns; the workload listens inside the VM at the pod IP. Needs a sandbox-controller portforward path (planned). |
| `HostNetwork`, `HostIpc` | a microVM has its own kernel — it cannot share the host's network / IPC namespace. |
| mount propagation `rprivate` / `rshared` / `rslave` | bidirectional mount propagation across the VM boundary is not possible with a separate guest kernel. |

These are intentional isolation trade-offs, not defects.

## Quick start (k3s)

```sh
# 1. install the runtime into k3s (idempotent, version-robust)
sudo deploy/k3s/install-smolvm-k3s.sh

# 2. prove it end-to-end (deploy a pod as a microVM, check logs + exec)
sudo deploy/k3s/e2e-test.sh
```

`install-smolvm-k3s.sh` wires the shim into k3s's embedded containerd by reading
k3s's *generated* config to find the exact CRI plugin path, exports the shim's
runtime env to k3s, drops the shim onto containerd's PATH, writes a
`config.toml.tmpl`, registers the `smolvm` RuntimeClass, and labels nodes.

## Manifests

- [`kubernetes/runtimeclass.yaml`](kubernetes/runtimeclass.yaml) — the `smolvm` RuntimeClass.
- [`kubernetes/example-pod.yaml`](kubernetes/example-pod.yaml) — a smoke pod (`runtimeClassName: smolvm`).

## Prerequisites

The smolvm runtime payload must be installed on each node under
`$SMOLVM_DATA_DIR` (default `/var/lib/smolvm`): the musl `agent-rootfs`, the
`smolvm-vmm` boot helper, `lib/` (libkrun), and the `containerd-shim-smolvm-v2`
binary on `PATH`. A Linux host with KVM (`/dev/kvm`) is required.
