# Where smolvm state lives, and what removes it

Observed on v1.14.2. The install prefix, the agent rootfs, the per-VM state and the pack cache were
at the same paths on v1.18.2, 2026-09-24.

| | macOS | Linux |
|---|---|---|
| install prefix | `$HOME/.smolvm` | `$HOME/.smolvm` |
| launcher symlink | `$HOME/.local/bin/smolvm` | `$HOME/.local/bin/smolvm` |
| agent rootfs | `$HOME/Library/Application Support/smolvm` | `$HOME/.local/share/smolvm` |
| per-VM state | `$HOME/Library/Caches/smolvm/vms` | `$HOME/.cache/smolvm/vms` |
| shared pack store, after `machine create --from` or a checkpoint restore | not used | `.../smolvm/vms/_shared` |
| pack cache | `$HOME/Library/Caches/smolvm-pack` | `$HOME/.cache/smolvm-pack` |
| packed-binary lib cache | `$HOME/Library/Caches/smolvm-libs` | `$HOME/.cache/smolvm-libs` |
| registry cache | `$HOME/Library/Caches/smolvm-registry` | not seen |
| image archives: local `--image` archives, and from v1.23.0 images fetched on the host for a machine with no network | `$HOME/Library/Caches/smolvm-image-archives` | `$HOME/.cache/smolvm-image-archives` |
| registry credentials | `$HOME/.config/smolvm` | `$HOME/.config/smolvm` |
| `PATH` block | your shell profile | your shell profile |

Checkpoints are not in this table because smolvm does not choose where they go: a
`.smolcheckpoint` file or a `--store` directory lives wherever `machine checkpoint -o` was pointed,
the uninstaller does not know about it, and it is removed with `rm -rf` once no machine will be
restored from it. `smolvm machine checkpoint-prune --store <DIR>` drops a store's unreferenced
objects without removing the store.

On macOS the VM cache also holds `_restore-base`, a clone of the last restored checkpoint with its
memory, which stays until removed by hand or by the uninstaller. From v1.22.0 restores are cached in
`_restore-checkpoints` instead, the three most recent and up to 16 GiB. Beside `vms/`, v1.22.2 also
keeps `image-seeds/`, the shared seed of each registry image a machine has run, `init-layers/`, the
images `--oci-cache` baked, and `agent-rootfs-tars/`. v1.23.0 adds `registry-tokens/`, the pull
tokens the registry client keeps between commands
([#1511](https://github.com/smol-machines/smolvm/pull/1511)). The uninstaller removes all of them
with the cache directory.

The last three are the ones people miss. `smolvm-libs` appears only once a packed `.smolmachine`
stub has run, and the last two are deliberately left by the uninstaller.

`scripts/preflight.sh` reports each of these with its size, so you know what a teardown has to
remove before you remove it.

## Relocating state, for a test run

On macOS, and on Linux with `XDG_DATA_HOME` and `XDG_CACHE_HOME` unset, every path above derives
from `HOME`, so installing with `HOME` pointed at a scratch directory keeps a test run entirely
inside it. The runs recorded in this packet were isolated that way, and `scripts/verify-clean.sh`
with a `--protected` for each of the real installation's prefix, data and cache directories is the
assertion that proves it.

`SMOLVM_DATA_DIR` moves the data root on **Linux only**: the function that applies it is compiled
in for Linux and does not exist on macOS or Windows. On macOS `HOME` is still enough. On Windows
neither works, which is what makes that platform's teardown a manual removal. See
`references/windows.md`.

## Full removal

```bash
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
```

Verified complete on macOS against an isolated `HOME` used for machines, packs and `--oci-cache`
runs:

```
success: Removed <HOME>/.smolvm
success: Removed symlink <HOME>/.local/bin/smolvm
success: Removed data directory <HOME>/Library/Application Support/smolvm
success: Removed cache directory <HOME>/Library/Caches/smolvm
success: Removed pack cache directory <HOME>/Library/Caches/smolvm-pack
warning: You may want to remove the PATH entry from your shell profile.
success: smolvm has been uninstalled
```

Afterwards `find "$HOME" -iname '*smolvm*'` returned nothing. It removes `smolvm-libs` too when
present.

**On v1.18.2 on macOS it also leaves `$HOME/Library/Caches/smolvm-registry`**, the registry cache,
and does not say so: after pulls, packs and restores the uninstaller printed
`smolvm has been uninstalled` and that directory was the one smolvm path left, found by
`find "$HOME" -iname '*smolvm*'`. Remove it by hand. The uninstall after the same runs on Linux
aarch64 left nothing, and no such directory had been created there.

**On v1.23.0 it leaves `smolvm-image-archives`**, beside the cache directory on both hosts. A
machine created with no network now has its registry image fetched on the host into
`smolvm-image-archives/fetched` ([#1536](https://github.com/smol-machines/smolvm/pull/1536)), and
the uninstaller does not remove that directory. After this packet's v1.23.0 runs it held 24 MB on
macOS arm64, and it was left on Linux aarch64 too. Remove it by hand.

The two things it deliberately leaves, both of which it warns about:

```bash
# 1. the PATH block it added to your shell profile
sed -i.bak '/# smolvm/,+1d' ~/.zshrc     # or ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.config/fish/config.fish; read the file before running this

# 2. registry credentials, if you ever logged in to a registry
rm -rf ~/.config/smolvm
```

The repository's `scripts/install.sh --help` lists `--uninstall`.

## Reclaiming space without uninstalling

```bash
# machine prune: unreferenced layers; starts the machine if it is stopped. --all also
# drops cached images, except for a machine created from an image
smolvm machine prune --name <NAME>
smolvm pack prune                    # cached pack extractions
```
