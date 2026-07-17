#!/usr/bin/env bash
# Cut a smolvm engine release: bump every workspace crate + nix to VERSION on a
# fresh branch off origin/main, tag vVERSION, and push — which triggers the
# Release (platform tarballs) and crates.io publish workflows.
#
# Why a script: version bumps live only on release branches (main stays at the
# last baseline), so every manual cut re-derives "what version is main at?" by
# hand — get it wrong and the bump silently misses files, or worse, the branch
# is cut from a stale local main and reverts merged work. This automates the
# exact sequence, always from a freshly-fetched origin/main.
#
# Usage: ./scripts/cut-release.sh 1.7.0
set -euo pipefail

VERSION="${1:?usage: cut-release.sh X.Y.Z}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "error: '$VERSION' is not X.Y.Z" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git fetch origin main --tags
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "error: tag v$VERSION already exists" >&2; exit 1
fi

BRANCH="release-v$VERSION"
WT="$(mktemp -d)/smolvm-rel-$VERSION"
git worktree add -b "$BRANCH" "$WT" origin/main
trap 'git worktree remove "$WT" --force 2>/dev/null || true' EXIT
cd "$WT"

# The current baseline is whatever the workspace package declares on main.
BASE="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "(.*)"/\1/')"
echo ">>> bumping workspace $BASE -> $VERSION"

# Bump the first-package version line in every OUR-crate manifest, plus every
# internal dep spec in the root manifest, plus the nix flake. Third-party
# vendored crates (different versions) are untouched by construction: only
# exact "$BASE" strings are rewritten.
for f in Cargo.toml crates/*/Cargo.toml; do
  perl -i -pe "s/^version = \"\Q$BASE\E\"/version = \"$VERSION\"/" "$f"
done
perl -i -pe "s/version = \"\Q$BASE\E\"/version = \"$VERSION\"/g" Cargo.toml nix/smolvm.nix

if grep -rn "^version = \"$BASE\"" Cargo.toml crates/*/Cargo.toml >/dev/null 2>&1; then
  echo "error: some manifests still at $BASE after bump:" >&2
  grep -rn "^version = \"$BASE\"" Cargo.toml crates/*/Cargo.toml >&2
  exit 1
fi

cargo update -w
cargo metadata --no-deps --format-version 1 >/dev/null

git add -A
git commit -m "Bump the workspace to $VERSION"
git tag -a "v$VERSION" -m "smolvm v$VERSION"
git push -u origin "$BRANCH"
git push origin "v$VERSION"

echo ">>> v$VERSION tagged and pushed. Watch the Release + crates workflows:"
echo "    gh run list --repo smol-machines/smolvm --limit 4"
