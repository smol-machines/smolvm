#!/usr/bin/env bash
# Fail when nix/smolvm.nix pins hashes that do not match the release it names.
#
# The flake pins each platform tarball by hash, so a flake whose version and
# hashes disagree fails `nix build` on every platform with a fixed-output hash
# mismatch. That has shipped twice: a workspace bump rewrote `version` and left
# the previous release's hashes behind, and a bump that lands before the release
# exists cannot know the hashes at all. This recomputes the hashes for the pinned
# version from the release's checksums.sha256 (the same way
# update-nix-hashes.sh writes them) and requires them to be what is committed.
#
# SMOLVM_NIX_FILE / SMOLVM_CHECKSUMS_FILE point it at fixtures for the tests.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
NIX_FILE="${SMOLVM_NIX_FILE:-$REPO_ROOT/nix/smolvm.nix}"
[[ -f "$NIX_FILE" ]] || { echo "error: no such file: $NIX_FILE" >&2; exit 1; }

VERSION="$(sed -n 's/^ *version = "\([^"]*\)";.*/\1/p' "$NIX_FILE" | head -1)"
[[ -n "$VERSION" ]] || { echo "error: no version line in $NIX_FILE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$NIX_FILE" "$WORK/expected.nix"

if ! SMOLVM_NIX_FILE="$WORK/expected.nix" \
    "$REPO_ROOT/scripts/update-nix-hashes.sh" "$VERSION" >"$WORK/log" 2>&1; then
  cat "$WORK/log" >&2
  echo "error: could not read the v$VERSION release checksums; nix/smolvm.nix must pin a published release (bump it after the release, with ./scripts/update-nix-hashes.sh)" >&2
  exit 1
fi

if ! diff -u "$NIX_FILE" "$WORK/expected.nix" >&2; then
  echo "error: nix/smolvm.nix pins v$VERSION with hashes that do not match that release; fix with ./scripts/update-nix-hashes.sh $VERSION" >&2
  exit 1
fi

echo "nix/smolvm.nix hashes match the v$VERSION release"
