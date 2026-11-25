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

## Guest memory on a Mac

On a Mac, back a nested guest's memory with 2 MiB pages. With ordinary 4 KiB
pages the host maps that memory slowly: a Windows 11 guest with 6 GiB of RAM
took over 12 minutes to boot instead of about 75 seconds. Reserve the pages in
the machine and point the hypervisor at them:

```sh
echo 3072 > /proc/sys/vm/nr_hugepages    # 3072 x 2 MiB = 6 GiB
mkdir -p /dev/hugepages
mount -t hugetlbfs none /dev/hugepages
qemu-system-aarch64 -accel kvm -m 6G -mem-path /dev/hugepages -mem-prealloc ...
```

The machine needs that much memory on top of what it uses itself.
