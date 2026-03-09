# Embedded Node SDK Workspace

This workspace contains:

- `smolvm-embedded`: the public package users install
- `smolvm-embedded-*`: internal platform packages that carry the `.node`
  binary plus bundled `libkrun` and `libkrunfw`

Users should only install `smolvm-embedded`. The platform packages are an
implementation detail used by npm's optional dependency resolution.
