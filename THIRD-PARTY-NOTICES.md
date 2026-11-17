# Third-Party Notices

smolvm itself is licensed under the Apache License 2.0 (see `LICENSE`). Release
bundles also ship the following third-party libraries in `lib/`.

## libkrun

- **Shipped as:** `libkrun.so.2` (Linux), `libkrun.dylib` (macOS), `krun.dll` (Windows)
- **License:** Apache License 2.0
- **Source:** https://github.com/smol-machines/libkrun, our fork of https://github.com/containers/libkrun. The exact commit each bundled build came from is recorded in `lib/**/libkrun.provenance` and pinned as the `libkrun` submodule of this repository.
- **Copyright:** The libkrun Authors

## libkrunfw

- **Shipped as:** `libkrunfw.so.5` (Linux), `libkrunfw.5.dylib` (macOS), `libkrunfw.dll` (Windows)
- **License:** LGPL-2.1-only (library), GPL-2.0-only (the Linux kernel it bundles)
- **Source:** https://github.com/smol-machines/libkrunfw, our fork of https://github.com/containers/libkrunfw, pinned as the `libkrunfw` submodule of this repository. The kernel source and the patches applied to it are in that repository.
- **Copyright:** The libkrunfw Authors; the Linux kernel is copyright its contributors

The complete corresponding source for the libkrunfw library and the kernel it
bundles is the `libkrunfw` submodule commit pinned by the release tag you
downloaded. You may use, modify and redistribute it under the terms of
LGPL-2.1 and GPL-2.0; modified versions you distribute must be offered under
the same licenses.

## virglrenderer (macOS bundles)

- **Shipped as:** `libvirglrenderer.1.dylib`
- **License:** MIT
- **Source:** https://gitlab.freedesktop.org/slp/virglrenderer at tag `0.10.4e-krunkit`, with the patches in `patches/virglrenderer/` of this repository; built by `scripts/build-virglrenderer-macos.sh`
- **Copyright:** The virglrenderer Authors

## MoltenVK (macOS bundles)

- **Shipped as:** `libMoltenVK.dylib`
- **License:** Apache License 2.0
- **Source:** https://github.com/KhronosGroup/MoltenVK
- **Copyright:** The Brenwill Workshop Ltd. and The Khronos Group Inc.

## libepoxy (macOS bundles)

- **Shipped as:** `libepoxy.0.dylib`
- **License:** MIT
- **Source:** https://github.com/anholt/libepoxy
- **Copyright:** Intel Corporation and the libepoxy Authors
