# Nested virtualization

`--nested` exposes the host's virtualization extensions, so the machine has
`/dev/kvm` and can run smolvm, QEMU or another hypervisor inside it. Nested
guests run much slower than first-level ones, so it is off by default.

```sh
smolvm machine run --nested --image alpine -- ls -l /dev/kvm
```

The host needs nested KVM on Linux (`/sys/module/kvm_intel/parameters/nested`
or `kvm_amd`, `1` or `Y`), or an M3 or newer Mac on macOS 15 or later;
otherwise the machine fails to start. Over the API, `nestedVirt` is refused
unless the server was started with `serve start --allow-nested-virt`. A
Smolfile cannot turn it on.
