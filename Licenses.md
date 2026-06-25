# Third-Party Licenses

smolvm bundles the following third-party libraries in the `lib/` directory.

## libkrun

- **Version:** 1.17.3, local display fork commit `4e523339b3c05bf4edf957ffa2bca34f18d3c726`
- **License:** Apache License 2.0
- **Source:** https://github.com/smol-machines/libkrun
- **Copyright:** The libkrun Authors

Licensed under the Apache License, Version 2.0. You may obtain a copy of the License at:
http://www.apache.org/licenses/LICENSE-2.0

## libkrunfw

- **Version:** 5.4.0, local input-enabled fork commit `25b9d8d12122d6b361015d477bf18ee91238c0c8`
- **License:** LGPL-2.1-only (library), GPL-2.0-only (bundled Linux kernel)
- **Source:** https://github.com/smol-machines/libkrunfw
- **Copyright:** The libkrunfw Authors

libkrunfw is a library that bundles the Linux kernel for use with libkrun.

### Source Code Availability

In compliance with LGPL-2.1 and GPL-2.0, the complete source code for libkrunfw and the bundled Linux kernel is available at:

- **libkrunfw:** https://github.com/smol-machines/libkrunfw
- **Linux kernel (with patches):** https://github.com/smol-machines/libkrunfw/tree/main/patches

To obtain the exact source code corresponding to the bundled binary, check out the version tag matching the library version from the repository above.

### Your Rights Under LGPL-2.1

You have the right to:
- Use this library in your own projects
- Modify the library and distribute your modifications
- Reverse engineer the library for debugging purposes

If you distribute a modified version of libkrunfw, you must make your modifications available under the same license.

## rustvncserver

- **Version:** 2.2.1, local listener fork commit `5d339c9daf74519e1f4ae6a75a84fbfff70e143e`
- **License:** Apache License 2.0
- **Source:** https://github.com/cap12312/rustvncserver

The local fork adds explicit loopback-address and prebound-listener APIs. See
`docs/native-display.md` for the source-distribution boundary.
