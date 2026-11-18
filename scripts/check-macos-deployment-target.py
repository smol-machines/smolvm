#!/usr/bin/env python3
"""Reject bundled dylibs that require a newer macOS than the release supports.

Reads Mach-O load commands directly so Linux CI checks the Mac bundle too.
"""
import argparse
from pathlib import Path
import struct
import sys


def minimum_versions(data):
    magic = data[:4]
    fat = {
        b"\xca\xfe\xba\xbe": (">", "IIIII"),
        b"\xbe\xba\xfe\xca": ("<", "IIIII"),
        b"\xca\xfe\xba\xbf": (">", "IIQQII"),
        b"\xbf\xba\xfe\xca": ("<", "IIQQII"),
    }
    if magic in fat:
        endian, layout = fat[magic]
        count = struct.unpack_from(endian + "I", data, 4)[0]
        size = struct.calcsize(endian + layout)
        if not count or 8 + count * size > len(data):
            raise ValueError("invalid universal binary header")
        versions = []
        for index in range(count):
            fields = struct.unpack_from(endian + layout, data, 8 + index * size)
            offset, length = fields[2:4]
            if offset < 8 + count * size or offset + length > len(data):
                raise ValueError("invalid universal binary slice")
            # A universal slice must be a thin Mach-O, not a nested archive.
            if data[offset:offset + 4] in fat:
                raise ValueError("nested universal binary")
            versions.extend(minimum_versions(data[offset:offset + length]))
        return versions

    formats = {
        b"\xce\xfa\xed\xfe": ("<", 28), b"\xfe\xed\xfa\xce": (">", 28),
        b"\xcf\xfa\xed\xfe": ("<", 32), b"\xfe\xed\xfa\xcf": (">", 32),
    }
    if magic not in formats:
        raise ValueError("not a Mach-O library (fetch Git LFS objects if needed)")
    endian, cursor = formats[magic]
    filetype, count, length = struct.unpack_from(endian + "III", data, 12)
    end = cursor + length
    if filetype != 6 or end > len(data) or count > length // 8:
        raise ValueError("invalid dylib load commands")
    versions = []
    for _ in range(count):
        command, size = struct.unpack_from(endian + "II", data, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError("invalid load command length")
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise ValueError("truncated build version")
            platform, version = struct.unpack_from(endian + "II", data, cursor + 8)
            if platform != 1:  # PLATFORM_MACOS
                raise ValueError("library targets a platform other than macOS")
            versions.append(version)
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX
            if size < 16:
                raise ValueError("truncated minimum version")
            versions.append(struct.unpack_from(endian + "I", data, cursor + 8)[0])
        cursor += size
    if cursor != end or not versions:
        raise ValueError("missing or invalid macOS deployment target")
    return versions


def display(version):
    return f"{version >> 16}.{(version >> 8) & 255}.{version & 255}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.paths or sorted(Path("lib").glob("*.dylib"))
    if not paths:
        parser.error("no bundled macOS libraries found")
    failed = False
    for path in paths:
        try:
            versions = minimum_versions(path.read_bytes())
            if max(versions) > (11 << 16):
                raise ValueError(f"requires macOS {display(max(versions))}; release supports 11.0")
            print(f"OK    {path}: minimum macOS {display(max(versions))}")
        except (OSError, ValueError, struct.error) as error:
            print(f"FAIL  {path}: {error}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
