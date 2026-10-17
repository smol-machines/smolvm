# Known Limitations

* Network is opt-in (`--net` on `machine create`). The default backend carries TCP and UDP without emulating a network card, so the guest shows no `eth0` and `ping` fails with `Network unreachable` even while HTTP works. Check connectivity with `wget` or `curl`, not `ping`. Pass `--net-backend virtio-net` for a real interface, an address of its own, and ICMP.
* Volume mounts: directories only (no single files). Mounting at `/workspace` (`-v /host/dir:/workspace`) takes priority over the default storage-disk workspace, so your host directory is used instead.
* macOS: binary must be signed with Hypervisor.framework entitlements (`com.apple.security.hypervisor`). The shipped release is; a re-signed or freshly built binary silently loses it and every VM start then fails with `krun_start_enter returned: -22 (EINVAL)`. Re-sign it (ad-hoc is fine): `codesign --force --sign - --entitlements hv.entitlements <smolvm-bin>` where `hv.entitlements` is a plist containing `<key>com.apple.security.hypervisor</key><true/>`.
* GPU acceleration requires libkrun built with `GPU=1` and virglrenderer + a Vulkan driver on the host (see [GPU Acceleration](gpu.md)).
* Windows: `--net` works the same as on other platforms (virtio-net with inbound port-forwarding; TSI for outbound-only VMs), as do `machine exec` / interactive sessions. Checkpoints and pause/resume are supported. A branch must use `--freeze-source` because continuing its source is not implemented. Checkpoint capture rejects active virtiofs DAX mappings. GPU acceleration remains unavailable. Pack *create* needs `storage-template.ext4` / `overlay-template.ext4` next to `smolvm.exe` (Windows has no host `mkfs.ext4`).

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

* Virtio-net accepts up to 512 simultaneous TCP relay connections per machine by
  default. For higher-concurrency workloads, set `SMOLVM_TCP_RELAY_CAPACITY` on
  the host process (1–4096); this bounds the number of host relay threads and
  their buffers. Invalid values use the default. TSI networking does not use
  this relay table.

## S3 mounts

S3 mounts are not a full POSIX workspace: symlinks are unsupported, and changes
to ownership, permissions (including executable bits), and timestamps are not
persisted. Copying a Git repository can therefore lose information even when
all regular-file contents match.

Complete directory listings can answer missing-child lookups locally until
the metadata TTL expires; inferred misses do not extend that lifetime, and a
zero TTL disables them. Local mutations update cached child names and fence
out older lookup/listing responses. Failed or incomplete listings are not
evidence of absence. External changes can remain hidden until the configured
TTL expires; this is not cross-mount coordination or locking.

File renames use the provider's server-side `CopyObject` operation followed by
source deletion, rather than downloading and reuploading the object. This
requires `CopyObject` support and is subject to its single-request object-size
limit; multipart copying and directory renames are not implemented. Renames
are not atomic: a failed source deletion returns an error, but both names may
exist. S3 errors embedded in a successful HTTP response are treated as errors
before attempting source deletion.

Writes are staged on the VM until a successful flush or fsync uploads them.
S3 cannot recover writes lost with the VM before they reach that boundary.
Handles on the same file share local staged bytes: a separate reader can see
pending writes without waiting for an upload, and closing one writer does not
discard another writer's staging state. This visibility is local to this
mount, not a durability guarantee or cross-machine cache coherence. Failed
uploads return an error and retain the staged bytes for retry while the mount
remains alive; failed downloads are not treated as empty file contents.
