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

- The repository is **unsigned** (`gpgcheck=0`), which matches the pacman repo's
  posture — integrity comes from packages built by CI from the release artifacts
  and served over HTTPS. Package signing (GPG) is planned; until then keep
  `gpgcheck=0`.
- Served from an atomic GitHub Pages deployment; packages are built by CI and
  published on every release (`.github/workflows/pacman-repo.yml`). It is a
  rolling repo — the latest release only (older versions remain on the GitHub
  Releases page).
- The package installs the wrapper at `/usr/bin/smolvm` and bundles the
  smol-machines `libkrun`/`libkrunfw` fork under `/usr/lib/smolvm` — it does not
  conflict with any system `libkrun`.
- Requires `crun` and `jq` (pulled in automatically).
