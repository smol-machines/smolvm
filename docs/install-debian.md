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

- A **flat, unsigned repository**, hence `[trusted=yes]`, as the pacman repo is: integrity comes from CI-built
  packages of the release artifacts, served over HTTPS. Keep the flag until GPG signing, which is planned, lands.
- A rolling repo of the latest release only (older versions stay on the GitHub Releases page), built by CI on every
  release (`.github/workflows/pacman-repo.yml`) and served from an atomic GitHub Pages deployment.
- The package installs the wrapper at `/usr/bin/smolvm` and bundles the
  smol-machines `libkrun`/`libkrunfw` fork under `/usr/lib/smolvm` — it does not
  conflict with any system `libkrun`.
- Requires `crun` and `jq` (pulled in automatically). `crun` is available in
  Debian 12+ and Ubuntu 22.04+.
