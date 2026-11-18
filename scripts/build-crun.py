#!/usr/bin/env python3
"""Build the guest OCI runtime from pinned inputs on Linux or macOS.

Usage: build-crun.py <aarch64|x86_64> <rootfs-directory>
Only download archives are cached; every invocation verifies them and rebuilds.
The compiler, libc, headers and libraries are independent of the build host.
"""
import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

PROJECT = Path(__file__).resolve().parent.parent
INPUTS = PROJECT / "patches/crun/build-inputs.json"
PATCH = PROJECT / "patches/crun/0001-watch-populated-cgroups-only.patch"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(record, cache):
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / record["sha256"]
    if target.exists():
        if sha256(target) != record["sha256"]:
            raise RuntimeError("Cached download has an invalid digest: " + str(target))
        return target
    descriptor, temporary = tempfile.mkstemp(prefix="download-", dir=cache)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            with urllib.request.urlopen(record["url"], timeout=90) as source:
                shutil.copyfileobj(source, output)
        if sha256(temporary) != record["sha256"]:
            raise RuntimeError("Download digest mismatch: " + record["url"])
        os.replace(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def extract(archive, destination, prefixes=None):
    """Extract only regular files, directories and links within the private tree.

    APKs concatenate signature, control and data tar streams; ignore_zeros is
    necessary to reach the data stream. Keep the same checks on Python 3.9/macOS.
    """
    destination.mkdir(parents=True, exist_ok=True)
    boundary = destination.resolve()
    with tarfile.open(archive, "r:*", ignore_zeros=True) as source:
        for member in source:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise RuntimeError("Archive contains an unsafe path: " + member.name)
            if prefixes and not member.name.startswith(prefixes):
                continue
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError("Unsupported archive entry: " + member.name)
            target = destination / member.name
            paths = [target]
            if member.issym():
                paths.append(target.parent / member.linkname)
            if member.islnk():
                paths.append(destination / member.linkname)
            for path in paths:
                try:
                    path.resolve().relative_to(boundary)
                except ValueError:
                    raise RuntimeError("Archive link escapes its tree: " + member.name)
            # Pinned build inputs never need setuid/setgid bits or foreign owners.
            member.mode &= 0o777
            member.uid = os.getuid()
            member.gid = os.getgid()
            member.uname = member.gname = ""
            if hasattr(tarfile, "data_filter"):
                source.extract(member, destination, filter="data")
            else:
                source.extract(member, destination)


def elf_target(path, arch):
    data = path.read_bytes()
    header = data[:64]
    machine = {"aarch64": 183, "x86_64": 62}[arch]
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != machine
            or struct.unpack_from("<H", header, 16)[0] != 3):
        raise RuntimeError("Expected a position-independent Linux executable for " + arch)
    offset = struct.unpack_from("<Q", header, 32)[0]
    size, count = struct.unpack_from("<HH", header, 54)
    if size != 56 or offset + size * count > len(data):
        raise RuntimeError("Invalid ELF program headers")
    segments = [struct.unpack_from("<IIQQQQQQ", data, offset + size * i) for i in range(count)]
    interpreters = [data[p[2]:p[2] + p[5]] for p in segments if p[0] == 3]
    if interpreters != [("/lib/ld-musl-" + arch + ".so.1\0").encode()]:
        raise RuntimeError("Expected the Alpine musl interpreter for " + arch)
    dynamic = [p for p in segments if p[0] == 2]
    if len(dynamic) != 1:
        raise RuntimeError("Expected one ELF dynamic segment")
    segment = dynamic[0]
    if segment[2] + segment[5] > len(data) or segment[5] % 16:
        raise RuntimeError("Invalid ELF dynamic segment")
    entries = list(struct.iter_unpack("<qQ", data[segment[2]:segment[2] + segment[5]]))
    strings = next((value for tag, value in entries if tag == 5), None)
    table = next((p[2] + strings - p[3] for p in segments
                  if strings is not None and p[0] == 1 and p[3] <= strings < p[3] + p[5]), None)
    if table is None:
        raise RuntimeError("ELF has no mapped dynamic string table")
    needed = {data[table + value:].split(b"\0", 1)[0].decode()
              for tag, value in entries if tag == 1}
    expected = {"libseccomp.so.2", "libcap.so.2", "libjson-c.so.5", "libc.musl-" + arch + ".so.1"}
    if needed != expected or any(tag in (15, 29) for tag, _ in entries):
        raise RuntimeError("Unexpected runtime libraries or embedded search path: " + repr(needed))


def wrapper(path, argv, libc=None):
    content = "#!/bin/sh\n"
    if libc:
        content += "ZIG_LIBC=" + shlex.quote(str(libc)) + "\nexport ZIG_LIBC\n"
    content += "exec " + " ".join(shlex.quote(str(arg)) for arg in argv) + ' "$@"\n'
    path.write_text(content)
    path.chmod(0o755)
    return shlex.quote(str(path))


def build(arch, rootfs):
    inputs = json.loads(INPUTS.read_text())
    host_arch = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    host_os = {"Linux": "linux", "Darwin": "macos"}.get(platform.system())
    host = host_arch + "-" + str(host_os)
    if host not in inputs["toolchain"]["hosts"]:
        raise RuntimeError("Unsupported build host: " + host)
    for tool in ["make", "patch", "pkg-config"]:
        if not shutil.which(tool):
            raise RuntimeError("Building crun requires " + tool)
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "smolvm-crun/downloads"
    records = [inputs["source"], inputs["toolchain"]["hosts"][host]]
    records.extend(inputs["sysroots"][arch].values())
    archives = {record["sha256"]: download(record, cache) for record in records}
    with tempfile.TemporaryDirectory(prefix="smolvm-crun-") as temporary:
        work = Path(temporary)
        extract(archives[inputs["source"]["sha256"]], work / "source")
        source = work / "source" / ("crun-" + inputs["version"])
        extract(archives[inputs["toolchain"]["hosts"][host]["sha256"]], work / "toolchain")
        zig = next((work / "toolchain").glob("*/zig"))
        sysroot = work / "sysroot"
        for record in inputs["sysroots"][arch].values():
            extract(archives[record["sha256"]], sysroot, ("usr/include/", "usr/lib/", "lib/"))
        libc = work / "libc.txt"
        libc.write_text("\n".join([
            "include_dir=" + str(sysroot / "usr/include"),
            "sys_include_dir=" + str(sysroot / "usr/include"),
            "crt_dir=" + str(sysroot / "usr/lib"),
            "msvc_lib_dir=", "kernel32_lib_dir=", "gcc_dir=", "",
        ]))
        env = os.environ.copy()
        for key in ["CC", "CXX", "AR", "RANLIB", "LD", "CFLAGS", "CPPFLAGS", "LDFLAGS",
                    "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
                    "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "ZIG_LIBC", "ZIG_LIB_DIR",
                    "PKG_CONFIG_PATH", "PKG_CONFIG_SYSROOT_DIR", "PKG_CONFIG_LIBDIR"]:
            env.pop(key, None)
        env.update(
            CC=wrapper(work / "cc", [zig, "cc", "-target", arch + "-linux-musl",
                                   "-L" + str(sysroot / "usr/lib"), "-L" + str(sysroot / "lib")], libc),
            AR=wrapper(work / "ar", [zig, "ar"]),
            RANLIB=wrapper(work / "ranlib", [zig, "ranlib"]),
            STRIP=wrapper(work / "strip", [zig, "objcopy", "--strip-all"]),
            PKG_CONFIG_SYSROOT_DIR=str(sysroot),
            PKG_CONFIG_LIBDIR=str(sysroot / "usr/lib/pkgconfig"),
            CFLAGS="-O2 -g0 -fPIE -fstack-protector-strong -ffile-prefix-map=" + str(work) + "=/build",
            LDFLAGS="-pie -Wl,-z,relro,-z,now",
            SOURCE_DATE_EPOCH=str(inputs["source_date_epoch"]),
            PYTHON=sys.executable, PYTHONHASHSEED="0", LC_ALL="C",
            ZIG_GLOBAL_CACHE_DIR=str(work / "zig-cache"), ZIG_LOCAL_CACHE_DIR=str(work / "zig-local"),
        )
        def run(argv):
            subprocess.run(list(map(str, argv)), cwd=source, env=env, check=True)
        run(["patch", "--batch", "--fuzz=0", "-p1", "-i", PATCH])
        build_triple = subprocess.check_output(["sh", "build-aux/config.guess"], cwd=source, text=True).strip()
        run(["./configure", "--host=" + arch + "-linux-musl", "--build=" + build_triple,
             "--prefix=/usr", "--disable-systemd"])
        # Explicit targets need BUILT_SOURCES before parallel compilation.
        run(["make", "git-version.h"])
        run(["make", "-j" + str(min(os.cpu_count() or 1, 4)), "crun"])
        binary = work / "crun"
        run([zig, "objcopy", "--strip-all", source / "crun", binary])
        elf_target(binary, arch)
        destination = rootfs / "usr/bin/crun"
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, staged = tempfile.mkstemp(prefix=".crun-", dir=destination.parent)
        os.close(descriptor)
        staged = Path(staged)
        try:
            shutil.copyfile(binary, staged)
            staged.chmod(0o755)
            os.replace(staged, destination)
        finally:
            staged.unlink(missing_ok=True)
        metadata = rootfs / "usr/share/smolvm/crun"
        metadata.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PATCH, metadata / PATCH.name)
        provenance = {"version": inputs["version"], "arch": arch, "source": inputs["source"],
                      "toolchain_version": inputs["toolchain"]["version"],
                      "toolchain": inputs["toolchain"]["hosts"][host],
                      "sysroot": inputs["sysroots"][arch], "patch_sha256": sha256(PATCH),
                      "builder_sha256": sha256(Path(__file__)), "binary_sha256": sha256(destination)}
        (metadata / "build.json").write_text(json.dumps(provenance, indent=2) + "\n")
        print("Installed crun " + inputs["version"] + " for " + arch + ": " + provenance["binary_sha256"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arch", choices=["aarch64", "x86_64"])
    parser.add_argument("rootfs", type=Path)
    args = parser.parse_args()
    build(args.arch, args.rootfs.resolve())


if __name__ == "__main__":
    main()
