# What the install lays down, how to upgrade, and how to remove it

Observed on macOS arm64, Linux aarch64 and Linux x86_64 on v1.14.2.

## Layout

| | macOS | Linux |
|---|---|---|
| install prefix (wrapper, `smolvm-bin`, `lib/`, `.version`, disk templates) | `$HOME/.smolvm` | `$HOME/.smolvm` |
| launcher symlink | `$HOME/.local/bin/smolvm` | `$HOME/.local/bin/smolvm` |
| agent rootfs | `$HOME/Library/Application Support/smolvm` | `$HOME/.local/share/smolvm` |
| per-VM state | `$HOME/Library/Caches/smolvm/vms` | `$HOME/.cache/smolvm/vms` |
| image cache, once `--oci-cache` has run | `.../smolvm/vms/_shared` | `.../smolvm/vms/_shared` |
| pack cache | `$HOME/Library/Caches/smolvm-pack` | `$HOME/.cache/smolvm-pack` |
| packed-binary lib cache | `$HOME/Library/Caches/smolvm-libs` | `$HOME/.cache/smolvm-libs` |
| registry credentials | `$HOME/.config/smolvm` | `$HOME/.config/smolvm` |
| `PATH` block | your shell profile | your shell profile |

The last three are the ones people miss. `smolvm-libs` appears only once a packed `.smolmachine`
stub has run, and the last two are deliberately not removed by the uninstaller.

Disk: about 120 MB for the install itself. The first VM then creates sparse disks with 20 GiB
storage and 10 GiB overlay **apparent** size; actual usage after one run was 18 MB.

## Isolating a test install

On macOS and Linux, running the installer with `HOME` pointed at a scratch directory puts every
path above inside it, which is how the runs behind this packet avoided touching a real
installation. Keep that directory shallow on macOS or you will hit the socket path limit in
`references/traps.md`.

```bash
curl -sSL https://smolmachines.com/install.sh | HOME=/tmp/sk bash -s -- --version 1.14.2
HOME=/tmp/sk /tmp/sk/.local/bin/smolvm --version
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

Verified complete on macOS against an isolated `HOME` that had been used for a full session of
machines, packs and `--oci-cache` runs: afterwards `find "$HOME" -iname '*smolvm*'` returned
nothing. It removes the prefix, the symlink, the data directory, the cache directory, the pack
cache and `smolvm-libs`, and warns about the two things it leaves: the `PATH` block in your shell
profile, and `~/.config/smolvm`.

The `--uninstall` flag is documented only in `scripts/install.sh --help`, not in the README or on
the docs site. The full removal sequence, including the Kubernetes runtime and the Windows tree,
is the `teardown` packet.

## Where the docs and the release disagree, at v1.14.2

Checked while running this procedure. Each of these will send you somewhere the release does not
go:

- `README.md` Install says to "download from GitHub Releases, and place it into
  `~/.local/share/`". The installer places the prefix in `$HOME/.smolvm`; only the agent rootfs
  goes to a data directory.
- `scripts/install.sh` and `README.md` describe a unified `smol` CLI. No v1.14.2 tarball
  (darwin-arm64, linux-arm64, linux-x86_64) contains `smol` or `smol-bin`, so that branch never
  fires and no `smol` command is installed.
- `scripts/install.sh` calls `init.krun` "(Linux only, required by libkrunfw kernel)". The
  linux-arm64 tarball contains none, the installer skips it silently, and VMs boot anyway.
- `smolvm machine --help` describes `images` as "List cached images and storage usage", but
  `machine images` requires `--name` and reports one machine's images. There is no command that
  lists what `--oci-cache` has baked.
- Nothing anywhere mentions the macOS path-length limit.
