# Installing smolvm

One command on macOS and Linux, then a boot you can prove. A version number alone proves nothing:
on every platform there is at least one way for the install to succeed and every VM start to fail,
which is why this packet ships a preflight and a boot check rather than a download link.

`SKILL.md` is the procedure an agent follows. `references/layout.md` says where the files land,
`references/traps.md` carries the failures that cost the most time, and `references/windows.md` is
the Windows route.

## Install

```bash
curl -sSL https://smolmachines.com/install.sh | bash

# for coding agents: install, then read the full reference
curl -sSL https://smolmachines.com/install.sh | bash && smolvm --help
```

The installer takes the newest published release. A later release is expected to work with these
pages; `SKILL.md` records the version each claim was last verified on.

## Where it puts things

Under `$HOME`: the binary in `~/.smolvm` and the launcher in `~/.local/bin`. `references/layout.md`
has the full tree, including what an uninstall leaves behind on purpose.

**To install without touching an existing copy**, point `HOME` at a scratch directory: every path
above moves with it on macOS, and on Linux once `XDG_DATA_HOME` and `XDG_CACHE_HOME` are unset,
since both outrank `HOME` there. Keep that directory shallow on macOS, because a VM's agent socket
path has about 100 bytes to work with and a deep `HOME` fails every boot with an error that blames
disks.

## Windows

Download the `windows-x86_64` release, which bundles `krun.dll` and `libkrunfw.dll`, unzip it and
run `smolvm.exe`. It needs the Windows Hypervisor Platform feature enabled. State cannot be
relocated on Windows; `references/windows.md` has the three differences that break a Unix-shaped
script.

## Packaged installs

Arch ([install-arch](../install-arch.md)), Debian and Ubuntu ([install-debian](../install-debian.md)),
Fedora ([install-fedora](../install-fedora.md)), and Nix and NixOS ([install-nix](../install-nix.md))
have packaged installs. This packet verifies the `install.sh` route.

## Prove it works

`SKILL.md` runs the preflight, the boot check and the cleanup, with what each one prints.
