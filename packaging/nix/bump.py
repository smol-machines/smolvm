#!/usr/bin/env python3
"""Bump nix/smolvm.nix to a release: rewrites the version and the per-arch
SRI hashes by downloading each release tarball. Run by the CI workflow
.github/workflows/update-nix-flake.yml on every release.

Usage: bump.py <version-without-v> <path-to-smolvm.nix>
"""
import base64
import hashlib
import re
import sys
import urllib.request

REPO = "smol-machines/smolvm"
# nix system -> release tarball arch label
ASSETS = {
    "x86_64-linux": "linux-x86_64",
    "aarch64-linux": "linux-arm64",
    "aarch64-darwin": "darwin-arm64",
}


def sri(url: str) -> str:
    with urllib.request.urlopen(url) as r:
        data = r.read()
    return "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode()


def main() -> int:
    version, path = sys.argv[1], sys.argv[2]
    text = open(path).read()
    text = re.sub(r'version = "[^"]*";', f'version = "{version}";', text, count=1)
    for system, label in ASSETS.items():
        url = f"https://github.com/{REPO}/releases/download/v{version}/smolvm-{version}-{label}.tar.gz"
        h = sri(url)
        # Replace the hash line inside this system's attribute block only. Use a
        # non-greedy .*? (DOTALL) — the asset strings contain "}" via ${version},
        # so a [^}] class would stop short.
        pattern = r"(" + re.escape(system) + r" = \{.*?hash = \")[^\"]*(\";)"
        text, n = re.subn(pattern, lambda m: m.group(1) + h + m.group(2), text, flags=re.S)
        if n != 1:
            print(f"error: expected exactly one hash for {system}, replaced {n}", file=sys.stderr)
            return 1
        print(f"{system}: {h}")
    open(path, "w").write(text)
    print(f"bumped nix/smolvm.nix to {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
