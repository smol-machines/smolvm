# What the install lays down, how to upgrade, and how to remove it

Observed on macOS arm64, Linux aarch64 and Linux x86_64 on v1.14.2, on macOS arm64 on v1.22.2,
and on macOS arm64 and Linux aarch64 on v1.23.0.

## Layout

The full tree per platform, what each release added and what the uninstaller leaves is the
`teardown` packet's `references/locations.md`. The rows an install needs: the prefix
`$HOME/.smolvm`, the launcher `$HOME/.local/bin/smolvm`, and the agent rootfs in
`$HOME/Library/Application Support/smolvm` (macOS) or `$HOME/.local/share/smolvm` (Linux).

Run as root on Linux without `--prefix`, the installer puts the install prefix and the agent rootfs
together in `/opt/smolvm` and the launcher in `/usr/local/bin`, and leaves the shell profile alone;
that is the installer's source at v1.27.3, not a run recorded here.

Disk: about 120 MB, the prefix (about 65 MB before the first boot, about 88 MB after it
decompresses the disk templates) plus the agent rootfs (about 50 MB). The first VM then creates
sparse disks with 20 GiB storage and 10 GiB overlay **apparent** size; actual usage after one run was 18 MB.

## Isolating a test install

On macOS, and on Linux once `XDG_DATA_HOME` and `XDG_CACHE_HOME` are unset, running the installer
with `HOME` pointed at a scratch directory puts every path smolvm uses inside it; the runs recorded in
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

It removes the prefix, the launcher, the data and cache directories, the pack cache and
`smolvm-libs`, and leaves the `PATH` block and `~/.config/smolvm`. The `teardown` packet's
`references/locations.md` has the verified output, what each release also leaves, and the full
removal sequence, the Kubernetes runtime and the Windows tree included.

## What the release does, worth knowing at install time

- No release tarball carries a `smol` command, and none is installed.
- `machine images` takes `--name` and reports one machine's images. No command lists what
  `--oci-cache` has baked.
