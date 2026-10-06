# What the install lays down, how to upgrade, and how to remove it

Observed on macOS arm64, Linux aarch64 and Linux x86_64 on v1.14.2, on macOS arm64 on v1.22.2,
where the image seeds directory appeared, and on macOS arm64 and Linux aarch64 on v1.23.0, where
the two rows marked v1.23.0 did.

## Layout

| | macOS | Linux |
|---|---|---|
| install prefix (wrapper, `smolvm-bin`, `lib/`, `.version`, disk templates) | `$HOME/.smolvm` | `$HOME/.smolvm` |
| launcher symlink | `$HOME/.local/bin/smolvm` | `$HOME/.local/bin/smolvm` |
| agent rootfs | `$HOME/Library/Application Support/smolvm` | `$HOME/.local/share/smolvm` |
| per-VM state | `$HOME/Library/Caches/smolvm/vms` | `$HOME/.cache/smolvm/vms` |
| baked layers, once `--oci-cache` has run | `$HOME/Library/Caches/smolvm/init-layers` | `$HOME/.cache/smolvm/init-layers` |
| shared pack store, after `machine create --from` or a checkpoint restore | not used | `.../smolvm/vms/_shared` |
| image seeds (v1.22.0 and later) | `$HOME/Library/Caches/smolvm/image-seeds` | `$HOME/.cache/smolvm/image-seeds` |
| registry pull tokens (v1.23.0) | `$HOME/Library/Caches/smolvm/registry-tokens` | `$HOME/.cache/smolvm/registry-tokens` |
| images fetched on the host for a machine with no network (v1.23.0), beside local `--image` archives; `--uninstall` leaves it | `$HOME/Library/Caches/smolvm-image-archives` | `$HOME/.cache/smolvm-image-archives` |
| pack cache, where a cached run extracts | `$HOME/Library/Caches/smolvm-pack` | `$HOME/.cache/smolvm-pack` |
| packed-binary lib cache | `$HOME/Library/Caches/smolvm-libs` | `$HOME/.cache/smolvm-libs` |
| registry credentials | `$HOME/.config/smolvm` | `$HOME/.config/smolvm` |
| `PATH` block | your shell profile | your shell profile |

The last three are the ones people miss. `smolvm-libs` appears only once a packed `.smolmachine`
stub has run, and the last two are deliberately not removed by the uninstaller.

Disk: about 120 MB for the install itself. The first VM then creates sparse disks with 20 GiB
storage and 10 GiB overlay **apparent** size; actual usage after one run was 18 MB.

## Isolating a test install

On macOS, and on Linux once `XDG_DATA_HOME` and `XDG_CACHE_HOME` are unset, running the installer
with `HOME` pointed at a scratch directory puts every path above inside it; the runs recorded in
this packet were isolated that way. Keep that directory shallow on macOS or you will hit the socket
path limit in `references/traps.md`.

```bash
unset XDG_DATA_HOME XDG_CACHE_HOME   # Linux: these outrank HOME for the installer and smolvm
export HOME=/tmp/sk
curl -sSL https://smolmachines.com/install.sh | bash -s -- --version 1.23.0
/tmp/sk/.local/bin/smolvm --version
```

This does not work on Windows: state there cannot be relocated at all. See
`references/windows.md`.

## Upgrade

The same installer with a newer `--version`. Upgrading 1.14.1 to 1.14.2 printed
`info: Upgrading from 1.14.1 to 1.14.2` and correctly removed the stale expanded disk templates
the older release had left behind.

## Uninstall

```bash
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
```

Verified complete on macOS against an isolated `HOME` that had been used for machines, packs and
`--oci-cache` runs: afterwards `find "$HOME" -iname '*smolvm*'` returned
nothing. It removes the prefix, the symlink, the data directory, the cache directory, the pack
cache and `smolvm-libs`, and warns about the two things it leaves: the `PATH` block in your shell
profile, and `~/.config/smolvm`.

`scripts/install.sh --help` documents the `--uninstall` flag. The full removal sequence, including the Kubernetes runtime and the Windows tree,
is the `teardown` packet.

## What the release does, worth knowing at install time

- The installer puts the binary and its libraries in `$HOME/.smolvm` and the launcher in
  `$HOME/.local/bin`; only the agent rootfs goes to a data directory.
- No release tarball carries a `smol` command, and none is installed.
- `machine images` takes `--name` and reports one machine's images. No command lists what
  `--oci-cache` has baked.
- A VM's socket path on macOS has about 100 bytes to work with; `references/traps.md` has the
  measurement.
