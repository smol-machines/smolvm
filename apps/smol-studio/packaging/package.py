#!/usr/bin/env python3
"""Build Studio with a checksum-verified matching SmolVM distribution."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

def runtime_filter(member, destination):
    # Absolute symlinks inside the guest filesystem are interpreted relative to
    # the guest root at boot; preserve them, but never extract through one.
    parts = PurePosixPath(member.name).parts
    guest_link = (member.issym() and member.linkname.startswith('/') and
                  len(parts) > 2 and parts[1] == 'agent-rootfs' and '..' not in parts and
                  not member.name.startswith('/'))
    if guest_link:
        parent = (Path(destination) / member.name).parent.resolve()
        if not parent.is_relative_to(Path(destination).resolve()):
            raise ValueError('Guest symlink parent escapes the archive.')
        return member
    return tarfile.data_filter(member, destination)

app = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime-archive', type=Path, required=True)
parser.add_argument('--checksums', type=Path, required=True)
parser.add_argument('--output', type=Path, default=app / 'dist')
args = parser.parse_args()
archive = args.runtime_archive.resolve()
expected = next((line.split()[0] for line in args.checksums.read_text().splitlines()
                 if len(line.split()) == 2 and line.split()[1].lstrip('*').removeprefix('./') == archive.name), None)
actual = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
if expected is None or actual != expected:
    raise SystemExit('Runtime archive checksum is missing or does not match.')
version = tomllib.loads((app / 'Cargo.toml').read_text())['package']['version']
system = platform.system().lower()
arch = {'aarch64': 'arm64', 'AMD64': 'x86_64'}.get(platform.machine(), platform.machine())
if system not in ('linux', 'darwin', 'windows'):
    raise SystemExit('Supported desktop platforms are macOS, Linux and Windows.')
if f'-{system}-{arch}.' not in archive.name:
    raise SystemExit('The runtime archive must match this build host and architecture.')
subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path', str(app / 'Cargo.toml')], check=True)
args.output.mkdir(parents=True, exist_ok=True)
name = f'smol-studio-{version}-{system}-{arch}'
with tempfile.TemporaryDirectory() as temporary:
    temporary = Path(temporary)
    extracted = temporary / 'runtime'; extracted.mkdir()
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                if not (extracted / item.filename).resolve().is_relative_to(extracted):
                    raise SystemExit('Unsafe path in runtime archive.')
            bundle.extractall(extracted)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(extracted, filter=runtime_filter)
    executable = 'smolvm.exe' if system == 'windows' else 'smolvm'
    candidates = [path for path in extracted.rglob(executable) if path.is_file()]
    if len(candidates) != 1:
        raise SystemExit('Runtime archive must contain exactly one SmolVM launcher.')
    runtime = candidates[0].parent
    root = temporary / name; root.mkdir()
    if system == 'darwin':
        bundle = root / 'Smol Studio.app'
        contents = bundle / 'Contents'; binaries = contents / 'MacOS'; binaries.mkdir(parents=True)
        with (contents / 'Info.plist').open('wb') as file:
            plistlib.dump({'CFBundleName': 'Smol Studio', 'CFBundleDisplayName': 'Smol Studio',
                          'CFBundleIdentifier': 'com.smolmachines.studio', 'CFBundleExecutable': 'smol-studio',
                          'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': version,
                          'CFBundleVersion': version, 'NSHighResolutionCapable': True}, file)
    else:
        binaries = root
    studio = 'smol-studio.exe' if system == 'windows' else 'smol-studio'
    shutil.copy2(app / 'target' / 'release' / studio, binaries / studio)
    shutil.copytree(runtime, binaries / 'runtime', symlinks=True)
    (root / 'build.json').write_text(json.dumps({'studioVersion': version, 'runtimeArchive': archive.name,
                                               'runtimeSha256': actual, 'platform': system, 'architecture': arch}, indent=2))
    if system == 'linux':
        shutil.copy2(app / 'packaging' / 'smol-studio.svg', root)
        (root / 'smol-studio.desktop').write_text('[Desktop Entry]\nType=Application\nName=Smol Studio\nExec=smol-studio\nIcon=smol-studio\nTerminal=false\nCategories=Development;System;\n')
    if system == 'darwin':
        # Distribution signing/notarization is a release step; this enables local testing.
        subprocess.run(['codesign', '--force', '--sign', '-', str(bundle)], check=True)
    if system == 'linux':
        destination = args.output / f'{name}.tar.gz'
        with tarfile.open(destination, 'w:gz') as bundle:
            bundle.add(root, arcname=name)
    elif system == 'darwin':
        destination = args.output / f'{name}.zip'
        subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(root), str(destination)], check=True)
    else:
        destination = Path(shutil.make_archive(str(args.output / name), 'zip', root_dir=temporary, base_dir=name))
    digest = hashlib.file_digest(destination.open('rb'), 'sha256').hexdigest()
    destination.with_suffix(destination.suffix + '.sha256').write_text(f'{digest}  {destination.name}\n')
    print(destination)
