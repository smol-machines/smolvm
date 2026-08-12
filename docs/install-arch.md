# Installing smolvm on Arch Linux

smolvm ships an **official pacman repository** maintained by the smol-machines
team. It serves prebuilt packages for `x86_64` and `aarch64`, updated
automatically with every release.

> The `smolvm`, `smolvm-bin` and `smolvm-git` packages on the AUR are
> third-party and not maintained by us. As of 1.4.7 they link against the
> stock Arch `libkrun`, which lacks six symbols smolvm needs — disk overlays,
> snapshots and egress policy do not work with those packages. The official
> package bundles the smol-machines libkrun fork and is fully functional.

## Setup

Add the repository to `/etc/pacman.conf`:

```ini
[smol-machines]
SigLevel = Optional TrustAll
Server = https://smol-machines.github.io/smolvm/pacman/$arch
```

Then install:

```sh
sudo pacman -Sy smolvm
```

Upgrades arrive with your normal `pacman -Syu`.

## Notes

- The repository is served from an atomic GitHub Pages deployment; packages are
  built by CI from the release artifacts and published on every release
  (`.github/workflows/pacman-repo.yml`). It is a rolling repo — the
  latest release only (older versions remain on the GitHub Releases page).
- Package signing (GPG) is planned; until then integrity is provided by
  sha256-pinned sources built in CI and served over HTTPS.
- The package bundles the smol-machines `libkrun`/`libkrunfw` fork under
  `/usr/lib/smolvm/lib` — it does not conflict with the system `libkrun`
  package, which other software may continue to use.
