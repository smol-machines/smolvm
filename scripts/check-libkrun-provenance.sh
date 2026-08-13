#!/usr/bin/env bash
# Verify the committed libkrun/libkrunfw binaries in lib/ match the pinned
# submodule commits. Fails loudly if a lib dir is stale or unstamped — this is
# the guard that stops a stale prebuilt libkrun (e.g. one missing the latest TSI
# egress enforcement) from shipping in a release.
#
# Uses the superproject's recorded submodule commit (the gitlink), so it works
# in CI without initialising the submodules. Run in CI (see ci.yml).
#
#   PASS  → every lib dir's libkrun.provenance matches the pinned submodules
#   FAIL  → a lib dir is missing provenance or was built from an older submodule
#           commit; rebuild + restamp before merging.

set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Pinned submodule commits (gitlinks recorded in the superproject).
want_krun="$(git rev-parse "HEAD:libkrun")"
want_fw="$(git rev-parse "HEAD:libkrunfw")"

# Lib dirs that bundle a libkrun (macOS dylib + each Linux arch + Windows DLL).
LIB_DIRS=(lib lib/linux-x86_64 lib/linux-aarch64 lib/windows-x86_64)

fail=0
for dir in "${LIB_DIRS[@]}"; do
  # Skip dirs that don't actually ship a libkrun. The lib is `libkrun.*` on
  # macOS/Linux and `krun.dll` on Windows.
  { compgen -G "$dir/libkrun.*" || compgen -G "$dir/krun.dll"; } >/dev/null 2>&1 || continue
  prov="$dir/libkrun.provenance"

  if [[ ! -f "$prov" ]]; then
    echo "FAIL  $dir: no libkrun.provenance — binary's source commit is unknown."
    fail=1
    continue
  fi
  got_krun="$(grep '^libkrun=' "$prov" | cut -d= -f2)"
  got_fw="$(grep '^libkrunfw=' "$prov" | cut -d= -f2)"

  dir_ok=1
  if [[ "$got_krun" != "$want_krun" ]]; then
    echo "FAIL  $dir: libkrun built from $got_krun but submodule is pinned at $want_krun"
    dir_ok=0; fail=1
  fi
  if [[ "$got_fw" != "$want_fw" ]]; then
    echo "FAIL  $dir: libkrunfw built from $got_fw but submodule is pinned at $want_fw"
    dir_ok=0; fail=1
  fi

  # A GPU-enabled Linux libkrun normally records virglrenderer as DT_NEEDED.
  # The runtime deliberately makes Vulkan optional, so committed artifacts must
  # have that eager dependency removed; otherwise even CPU-only/CUDA-only VMs
  # fail before boot on hosts without virglrenderer installed.
  if [[ "$dir" == lib/linux-* ]]; then
    libkrun="$dir/libkrun.so"
    if readelf -d "$libkrun" 2>/dev/null | grep -q 'libvirglrenderer\.so\.1'; then
      echo "FAIL  $dir: libkrun has a hard libvirglrenderer dependency"
      dir_ok=0; fail=1
    fi
  fi
  [[ "$dir_ok" == "1" ]] && echo "OK    $dir (libkrun=$got_krun)"
done

if [[ "$fail" != "0" ]]; then
  cat >&2 <<EOF

Bundled libkrun is out of sync with the pinned submodule. Rebuild and restamp:
  macOS:  cargo make build-libkrun                 # stamps lib/
  Linux:  ./scripts/build-libkrun-linux.sh         # stamps lib/linux-<arch>/
then commit the updated lib/ (binaries + libkrun.provenance). This is the guard
that prevents shipping a stale libkrun (e.g. missing TSI egress enforcement).
EOF
  exit 1
fi
echo "All bundled libkrun binaries match the pinned submodules."
