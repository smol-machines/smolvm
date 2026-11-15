#!/usr/bin/env python3
"""Build Studio with checksum-verified Smol CLI and Docker engine distributions."""
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
parser.add_argument('--cli-archive', type=Path, required=True)
parser.add_argument('--cli-checksums', type=Path, required=True)
parser.add_argument('--runtime-archive', type=Path, required=True)
parser.add_argument('--checksums', type=Path, required=True)
parser.add_argument('--output', type=Path, default=app / 'dist')
args = parser.parse_args()
def verified_archive(path, checksums):
    path = path.resolve()
    expected = next((line.split()[0] for line in checksums.read_text().splitlines()
                     if len(line.split()) == 2 and line.split()[1].lstrip('*').removeprefix('./') == path.name), None)
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if expected is None or digest != expected:
        raise SystemExit(f'Archive checksum is missing or does not match: {path.name}')
    return path, digest

archive, actual = verified_archive(args.runtime_archive, args.checksums)
cli_archive, cli_digest = verified_archive(args.cli_archive, args.cli_checksums)
version = tomllib.loads((app / 'Cargo.toml').read_text())['package']['version']
system = platform.system().lower()
arch = {'aarch64': 'arm64', 'AMD64': 'x86_64'}.get(platform.machine(), platform.machine())
if system not in ('linux', 'darwin', 'windows'):
    raise SystemExit('Supported desktop platforms are macOS, Linux and Windows.')
for distribution in (archive, cli_archive):
    if f'-{system}-{arch}.' not in distribution.name:
        raise SystemExit('Both archives must match this build host and architecture.')
if (not archive.name.startswith('smolvm-') or not cli_archive.name.startswith('smol-') or
        archive.name.removeprefix('smolvm-') != cli_archive.name.removeprefix('smol-')):
    raise SystemExit('Smol CLI and engine archives must have matching versions and formats.')
subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path', str(app / 'Cargo.toml')], check=True)
args.output.mkdir(parents=True, exist_ok=True)
name = f'smol-studio-{version}-{system}-{arch}'
with tempfile.TemporaryDirectory() as temporary:
    temporary = Path(temporary)
    def extract_distribution(source, name, executable):
        extracted = temporary / name
        extracted.mkdir()
        if source.suffix == '.zip':
            with zipfile.ZipFile(source) as distribution:
                for item in distribution.infolist():
                    if not (extracted / item.filename).resolve().is_relative_to(extracted):
                        raise SystemExit('Unsafe path in distribution archive.')
                distribution.extractall(extracted)
        else:
            with tarfile.open(source) as distribution:
                distribution.extractall(extracted, filter=runtime_filter)
        candidates = [path for path in extracted.rglob(executable) if path.is_file()]
        if len(candidates) != 1:
            raise SystemExit(f'Archive must contain exactly one {executable} launcher.')
        return candidates[0].parent

    suffix = '.exe' if system == 'windows' else ''
    cli = extract_distribution(cli_archive, 'cli', 'smol' + suffix)
    engine = extract_distribution(archive, 'engine', 'smolvm' + suffix)
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
    resources = contents / 'Resources' if system == 'darwin' else binaries
    shutil.copytree(cli, resources / 'runtime', symlinks=True)
    shutil.copytree(engine, resources / 'engine', symlinks=True)
    (root / 'build.json').write_text(json.dumps({
        'studioVersion': version, 'cliArchive': cli_archive.name, 'cliSha256': cli_digest,
        'runtimeArchive': archive.name, 'runtimeSha256': actual,
        'platform': system, 'architecture': arch}, indent=2))
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
