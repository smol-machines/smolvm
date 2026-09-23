#!/usr/bin/env bash
# Refresh the per-arch SRI hashes in nix/smolvm.nix from a published release.
#
# The flake pins each platform tarball by hash, so the hashes are only knowable
# once the release assets exist. cut-release.sh cannot do it: it pushes the tag,
# and the tag is what triggers the workflow that builds the tarballs.
#
# The release path normally runs packaging/nix/bump.py from the "Update Nix
# flake" workflow, which downloads all three tarballs. This is the hand-run
# equivalent for when that bump has not landed: it reads the release's
# checksums.sha256 instead, so it costs one small download rather than three
# large ones, and it rewrites only the hashes (the version is left alone).
#
# Usage: ./scripts/update-nix-hashes.sh 1.14.6
#
# SMOLVM_CHECKSUMS_FILE=<path> reads a local checksums file instead of
# downloading one, which is how the test drives it offline.
set -euo pipefail

VERSION="${1:?usage: update-nix-hashes.sh X.Y.Z}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: '$VERSION' is not X.Y.Z" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
NIX_FILE="${SMOLVM_NIX_FILE:-$REPO_ROOT/nix/smolvm.nix}"
[[ -f "$NIX_FILE" ]] || { echo "error: no such file: $NIX_FILE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CHECKSUMS="$WORK/checksums.sha256"
if [[ -n "${SMOLVM_CHECKSUMS_FILE:-}" ]]; then
  cp "$SMOLVM_CHECKSUMS_FILE" "$CHECKSUMS"
else
  gh release download "v$VERSION" -R smol-machines/smolvm \
    --pattern checksums.sha256 --output "$CHECKSUMS" --clobber
fi

# The nix file is the source of truth for which assets are pinned: read the
# asset names out of it rather than hardcoding a list that can drift from it.
ASSETS="$(sed -n 's/.*asset = "smolvm-\${version}-\([^"]*\)";.*/\1/p' "$NIX_FILE")"
[[ -n "$ASSETS" ]] || { echo "error: no asset lines found in $NIX_FILE" >&2; exit 1; }

while read -r suffix; do
  [[ -n "$suffix" ]] || continue
  asset="smolvm-$VERSION-$suffix"
  digest="$(awk -v a="$asset" '$2 == a { print $1 }' "$CHECKSUMS")"
  # A pinned asset with no checksum line means the release is incomplete or the
  # asset was renamed; either way the resulting flake would not build.
  if [[ -z "$digest" ]]; then
    echo "error: $asset has no line in the checksums for v$VERSION" >&2
    exit 1
  fi
  sri="sha256-$(printf '%s' "$digest" | xxd -r -p | base64)"

  # Rewrite the hash inside this asset's attribute block only. The block runs
  # from its asset line to its hash line, so a range address pins it without
  # needing to name the nix system attribute.
  # The values go in through the environment, not the program text: base64
  # uses `/` and `+`, which would end or corrupt an interpolated s///.
  SUFFIX="$suffix" SRI="$sri" perl -i -pe '
    if (/asset = "smolvm-\$\{version\}-\Q$ENV{SUFFIX}\E";/) { $in = 1 }
    if ($in && s/hash = "[^"]*";/hash = "$ENV{SRI}";/) { $in = 0 }
  ' "$NIX_FILE"
  echo "$asset: $sri"
done <<EOF
$ASSETS
EOF

echo "rewrote the release hashes in $NIX_FILE for v$VERSION"
