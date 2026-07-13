# Installing smolvm with Nix

smolvm is packaged as a **Nix flake**. It repackages the official release
binaries (bundling the smol-machines libkrun fork) and patches them for the Nix
store, with the runtime tools (`crun`, `mkfs.ext4`, `jq`, …) wired onto the
wrapper's `PATH` — so it works on NixOS out of the box.

Supported systems: `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`.

## Run it once

```sh
nix run github:smol-machines/smolvm -- --help
```

## Install into a profile

```sh
nix profile install github:smol-machines/smolvm
```

Upgrades: `nix profile upgrade smolvm` (the flake tracks the latest release).

## NixOS / Home Manager

The flake exposes an overlay, so you can add smolvm to your configuration:

```nix
{
  inputs.smolvm.url = "github:smol-machines/smolvm";

  # in your system/home configuration:
  nixpkgs.overlays = [ inputs.smolvm.overlays.default ];
  environment.systemPackages = [ pkgs.smolvm ];   # or home.packages
}
```

Running microVMs needs `/dev/kvm` on Linux; on NixOS enable it with
`virtualisation.kvmgt.enable = true;` (Intel) or ensure the `kvm` module is
loaded and your user is in the `kvm` group.

## Notes

- It is a **binary repackage** (`sourceProvenance = binaryNativeCode`): the same
  release tarball served on the GitHub Releases page, patchelf'd for Nix. The
  bundled libkrun/libkrunfw fork lives under the package's `libexec`, so it does
  not collide with a system `libkrun`.
- The pinned version and hashes in `nix/smolvm.nix` are bumped automatically on
  every release by `.github/workflows/update-nix-flake.yml` (which opens a PR).
- A submission to the upstream **nixpkgs** collection is planned so
  `nix profile install nixpkgs#smolvm` works without referencing this flake.
