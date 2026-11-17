# Installing smolvm on Fedora / RHEL

smolvm ships an **official dnf/yum repository** maintained by the smol-machines
team. It serves prebuilt `.rpm` packages for `x86_64` and `aarch64`, updated
automatically with every release.

## Setup

```sh
sudo tee /etc/yum.repos.d/smolvm.repo >/dev/null <<'EOF'
[smolvm]
name=smolvm
baseurl=https://smol-machines.github.io/smolvm/yum
enabled=1
gpgcheck=0
EOF
sudo dnf install smolvm
```

Upgrades arrive with your normal `dnf upgrade`.

## Notes

- An **unsigned repository**, hence `gpgcheck=0`, as the pacman repo is: integrity comes from CI-built packages of
  the release artifacts, served over HTTPS. Keep the setting until GPG signing, which is planned, lands.
- A rolling repo of the latest release only (older versions stay on the GitHub Releases page), built by CI on every
  release (`.github/workflows/pacman-repo.yml`) and served from an atomic GitHub Pages deployment.
- The package installs the wrapper at `/usr/bin/smolvm` and bundles the
  smol-machines `libkrun`/`libkrunfw` fork under `/usr/lib/smolvm` — it does not
  conflict with any system `libkrun`.
- Requires `crun` and `jq` (pulled in automatically).
