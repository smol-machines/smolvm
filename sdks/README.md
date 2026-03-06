# Embedded SDKs

This directory holds language bindings that embed `smolvm` directly into the
host process instead of talking to the API server.

Layout convention:

- `sdks/scripts/` contains shared helpers used by all embedded SDKs.
- `sdks/node/` contains the Node.js embedded SDK and its internal platform
  packages.
- future embedded SDKs should live in sibling directories such as
  `sdks/python/`, `sdks/go/`, and `sdks/c/`.

Bundled native library rule:

- Embedded SDKs ship package-local copies of `libkrun` and `libkrunfw`.
- Those libraries are always staged from the `smolvm` repo's bundled `./lib`
  directory, not from Homebrew or other system locations.
- Shared helpers in `sdks/scripts/` should be used to copy the current host's
  libraries into each SDK package's `lib/` directory.

Current status:

- `sdks/node/` is the first embedded SDK implementation.
- the previous standalone `smolvm-sdk/smolvm-node-native` branch is now a
  prototype/reference source, not the primary home for the embedded Node SDK.
