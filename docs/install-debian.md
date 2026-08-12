# Installing smolvm on Debian / Ubuntu

smolvm ships an **official apt repository** maintained by the smol-machines
team. It serves prebuilt `.deb` packages for `amd64` and `arm64`, updated
automatically with every release.

## Setup

```sh
echo 'deb [trusted=yes] https://smol-machines.github.io/smolvm/apt ./' \
  | sudo tee /etc/apt/sources.list.d/smolvm.list
sudo apt-get update
sudo apt-get install smolvm
```

Upgrades arrive with your normal `apt-get update && apt-get upgrade`.

## Notes

- It is a **flat, unsigned repository** (installed with `[trusted=yes]`), which
  matches the pacman repo's posture — integrity comes from packages built by CI
  from the release artifacts and served over HTTPS. Package signing (GPG) is
  planned; until then keep the `[trusted=yes]` flag.
- Served from an atomic GitHub Pages deployment; packages are built by CI and
  published on every release (`.github/workflows/pacman-repo.yml`). It is a
  rolling repo — the latest release only (older versions remain on the GitHub
  Releases page).
- The package installs the wrapper at `/usr/bin/smolvm` and bundles the
  smol-machines `libkrun`/`libkrunfw` fork under `/usr/lib/smolvm` — it does not
  conflict with any system `libkrun`.
- Requires `crun` and `jq` (pulled in automatically). `crun` is available in
  Debian 12+ and Ubuntu 22.04+.
