#!/usr/bin/env python3
"""Every bundled libkrun must embed a STATIC guest init.

libkrun carries the guest's first process (krun-init) inside the host library.
The guest has no dynamic loader, so an init linked against glibc (one with a
PT_INTERP program header such as /lib64/ld-linux-x86-64.so.2) cannot start:
the guest kernel has nothing to run, and the VM exits cleanly before the agent
is ready, with nothing on the guest console. v1.19.0 shipped a Windows krun.dll
built that way (issue #1437), so every bundled library is checked here.

Usage: scripts/check-krun-init-static.py [lib paths...]
With no arguments, checks every bundled libkrun under lib/.
"""

import struct
import sys
from pathlib import Path

DEFAULT_LIBS = [
    "lib/libkrun.dylib",
    "lib/linux-x86_64/libkrun.so",
    "lib/linux-aarch64/libkrun.so",
    "lib/windows-x86_64/krun.dll",
]
MACHINES = {62: "x86-64", 183: "aarch64"}
PT_INTERP = 3


def embedded_inits(data: bytes):
    """Yield (offset, arch, interpreter) for each ELF64 executable embedded in
    `data` after offset 0 (offset 0 is the library itself on Linux)."""
    i = 0
    while True:
        i = data.find(b"\x7fELF", i + 1)
        if i < 0:
            return
        if len(data) < i + 64 or data[i + 4] != 2 or data[i + 5] != 1:
            continue
        e_type, e_machine = struct.unpack_from("<HH", data, i + 16)
        if e_machine not in MACHINES or e_type not in (2, 3):
            continue
        phoff = struct.unpack_from("<Q", data, i + 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, i + 54)
        if phentsize != 56 or phnum == 0 or phnum > 64:
            continue
        interp = None
        for k in range(phnum):
            off = i + phoff + k * phentsize
            if off + 56 > len(data):
                break
            if struct.unpack_from("<I", data, off)[0] == PT_INTERP:
                p_offset, _, _, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
                raw = data[i + p_offset : i + p_offset + p_filesz]
                interp = raw.rstrip(b"\0").decode(errors="replace")
        yield i, MACHINES[e_machine], interp


def main(argv):
    paths = argv[1:] or DEFAULT_LIBS
    failed = False
    for name in paths:
        path = Path(name)
        data = path.read_bytes()
        if data.startswith(b"version https://git-lfs"):
            print(f"ERROR: {name} is a Git LFS pointer; fetch LFS objects first")
            failed = True
            continue
        inits = list(embedded_inits(data))
        if not inits:
            print(f"ERROR: {name}: no embedded guest init found")
            failed = True
            continue
        dynamic = [(off, arch, interp) for off, arch, interp in inits if interp]
        if dynamic:
            for off, arch, interp in dynamic:
                print(
                    f"ERROR: {name}: embedded {arch} guest init at offset {off} needs "
                    f"{interp}; the guest has no dynamic loader, so no VM can boot. "
                    "Rebuild with a static (musl) krun-init, e.g. the build-libkrun workflow."
                )
            failed = True
        else:
            arch = inits[0][1]
            print(f"ok: {name}: static {arch} guest init")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
