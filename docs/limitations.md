# Known Limitations

* Network is opt-in (`--net` on `machine create`). The default backend carries TCP and UDP without emulating a network card, so the guest shows no `eth0` and `ping` fails with `Network unreachable` even while HTTP works. Check connectivity with `wget` or `curl`, not `ping`. Pass `--net-backend virtio-net` for a real interface, an address of its own, and ICMP.
* Volume mounts: directories only (no single files). Mounting at `/workspace` (`-v /host/dir:/workspace`) takes priority over the default storage-disk workspace, so your host directory is used instead.
* macOS: binary must be signed with Hypervisor.framework entitlements (`com.apple.security.hypervisor`). The shipped release is; a re-signed or freshly built binary silently loses it and every VM start then fails with `krun_start_enter returned: -22 (EINVAL)`. Re-sign it (ad-hoc is fine): `codesign --force --sign - --entitlements hv.entitlements <smolvm-bin>` where `hv.entitlements` is a plist containing `<key>com.apple.security.hypervisor</key><true/>`.
* `--ssh-agent` requires an SSH agent running on the host (`SSH_AUTH_SOCK` must be set).
* GPU acceleration requires libkrun built with `GPU=1` and virglrenderer + a Vulkan driver on the host (see [GPU Acceleration](gpu.md)).
* Windows: `--net` works the same as on other platforms (virtio-net with inbound port-forwarding; TSI for outbound-only VMs), as do `machine exec` / interactive sessions and `machine stats`. Not yet available on Windows: GPU acceleration and `machine branch` / `machine checkpoint`. Pack *create* needs `storage-template.ext4` / `overlay-template.ext4` next to `smolvm.exe` (Windows has no host `mkfs.ext4`).

## Host mounts

Host directory mounts propagate host-side changes into guest inotify, so tools
such as Vite, nodemon, and file-watch test runners reload without polling. Set
`SMOL_NO_HOT_RELOAD=1` in the host process to disable recursive watching for a
machine with an unusually large directory tree.

For sequential or mmap-heavy reads, `SMOLVM_MOUNT_DAX=1` enables a 2 GiB
virtiofs DAX window for each user mount when the machine starts. This is a host
process setting (set it on `smolvm serve` for served machines), and an existing
machine needs a stop/start to apply it. DAX does not materially accelerate
metadata-heavy traversal. Confirm it in the guest with
`grep virtiofs /proc/mounts`; an active mount includes `dax=always`.
