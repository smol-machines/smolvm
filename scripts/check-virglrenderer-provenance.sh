#!/usr/bin/env bash
# Verify that the bundled macOS virglrenderer was built from the sources the
# tree currently describes: the krunkit tarball version named in
# scripts/build-virglrenderer-macos.sh and the patches in patches/virglrenderer/.
#
# The library is a checked-in binary that the release copies as-is, so a change
# to the bridge patch reaches nobody until the library is rebuilt. Without this
# guard such a change merges green and ships nothing. Exit codes:
#   PASS → lib/libvirglrenderer.provenance matches the version and patch set
#   FAIL → the stamp is missing or was made from different sources
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LIB="lib/libvirglrenderer.1.dylib"
PROV="lib/libvirglrenderer.provenance"
[[ -f "$LIB" ]] || { echo "SKIP  no $LIB in this tree"; exit 0; }

want_version="$(sed -n 's/^VIRGL_VERSION="\(.*\)"$/\1/p' scripts/build-virglrenderer-macos.sh)"
want_patches="$(scripts/virglrenderer-patch-digest.sh)"

if [[ ! -f "$PROV" ]]; then
  echo "FAIL  $LIB has no $PROV — the sources it was built from are unknown."
  echo "      Rebuild and stamp with: ./scripts/build-virglrenderer-macos.sh"
  exit 1
fi
got_version="$(grep '^virglrenderer=' "$PROV" | cut -d= -f2-)"
got_patches="$(grep '^patches=' "$PROV" | cut -d= -f2-)"

fail=0
if [[ "$got_version" != "$want_version" ]]; then
  echo "FAIL  $LIB was built from virglrenderer $got_version but the build script names $want_version"; fail=1
fi
if [[ "$got_patches" != "$want_patches" ]]; then
  echo "FAIL  $LIB was built with patch set $got_patches but patches/virglrenderer/ now hashes to $want_patches"
  echo "      The bridge patch changed without a rebuild, so the change would ship nothing."; fail=1
fi
if [[ "$fail" == "1" ]]; then
  echo "      Rebuild and stamp with: ./scripts/build-virglrenderer-macos.sh"
  exit 1
fi
echo "OK    $LIB (virglrenderer=$got_version patches=$got_patches)"
