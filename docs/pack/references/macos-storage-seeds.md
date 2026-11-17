# First import on macOS

`machine create --from FILE.smolmachine` prepares a reusable ext4 storage
seed for single-layer container packs on macOS. A short-lived Linux helper
extracts the layer TAR onto its own storage disk. The machine receives an
APFS clone of that disk; subsequent creates clone the same immutable seed.
Linux filenames, ownership, hard links, symlinks and extended attributes
are handled inside Linux rather than through a case-sensitive APFS image.

The helper uses two vCPUs, 1 GiB of RAM and no network. It shuts down and
flushes its disk before the seed is published. The source pack is hashed
and checked for replacement or modification before publishing and cloning.
Concurrent imports of the same pack share one preparation. Each machine
gets a writable disk independent of the cached seed and the original pack.
Installation uses a pinned directory descriptor so a cancelled create cannot
write into a different machine created later under the same name.
Guest extraction still takes time proportional to the archive's contents;
this is not constant-time first import or a background-create API.

The seed contains the pack's original image defaults, not environment
overrides or secrets supplied in a create request. Branches and portable
checkpoints use the normal storage disk. Restoring their checkpoints does
not require the original pack or a host-mounted layer volume.

Checkpoint packs, packs with a workspace seed, multi-layer packs and layers
containing OCI whiteouts keep the existing import path. Linux and Windows
imports are unchanged. Set `SMOLVM_PACK_STORAGE_SEEDS=off` in the CLI or API
server's environment to use the previous macOS path too.

## Storage and cleanup

Seeds live under the machine cache's `_pack-storage-seeds` directory. The
cache uses allocated disk blocks, not the sparse disk's logical size, and
`SMOLVM_PACK_CACHE_MAX_BYTES` sets its budget (default 20 GiB). The seed just
used is retained even if it alone exceeds the budget. Evicting another seed
does not affect machines already cloned from it.

Preparing a seed temporarily needs room for both its layer TAR and the
extracted filesystem. Preflight checks reject insufficient free space.
File-heavy packs may need more logical
storage for inodes even when the compressed archive is tiny. The default
disk grows to fit; an explicitly smaller disk keeps the previous host-layer
import path rather than changing the requested capacity or rejecting a pack
that previously worked.

Normal errors remove the helper and temporary files. A later import also
reclaims marked scratch directories whose creator and helper are confirmed
gone. Unmarked directories and ambiguous or live processes are retained.

## Reproduce

Use a separate machine name and output path, then run:

```sh
smolvm machine create --name import-source --image alpine
smolvm machine start --name import-source
smolvm machine exec --name import-source -- sh -ec '
  for directory in $(seq 1000); do
    mkdir -p /srv/d$directory
    for file in $(seq 100); do
      printf "%02000d" "$file" > /srv/d$directory/f$file
    done
  done'
smolvm machine stop --name import-source
smolvm pack create --from-vm import-source -o ./import-bench
time smolvm machine create --name import-first --from ./import-bench.smolmachine
time smolvm machine create --name import-second --from ./import-bench.smolmachine
smolvm machine start --name import-first
smolvm machine exec --name import-first -- sh -ec '
  test "$(find /srv -type f | wc -l)" -eq 100000
  test "$(wc -c < /srv/d1000/f100)" -eq 2000'
```

For an A/B comparison, use a separate cache/profile for each binary. Reusing
a seed makes a cold-import comparison invalid. Measure create, start and
the first verified read separately so deferred work is visible. Check
case-distinct paths, ownership/modes, hard-link identity, symlink ownership,
file capabilities and user xattrs as well as file counts. Include branch
isolation, stop/start, export/reimport, and checkpoint restore after moving
the original pack away.
