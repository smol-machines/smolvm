#!/usr/bin/env bash
# Assert the bundled linux libkrun.so libraries keep a glibc symbol floor <= 2.31
# — the release runtime floor (the dist binaries link against glibc 2.31, see
# release.yml). A libkrun linked against a newer glibc loads fine on that host
# but fails on Ubuntu 20.04 / Debian 11 hosts with "GLIBC_x.y not found" before
# the VM can boot (issue #636). objdump -T reads the ELF version-needed records; the check is
# arch-independent (an x86_64 objdump reads the arm64 .so fine).
#
# If this fails, rebuild the libs via the build-libkrun workflow (which links
# against glibc 2.31) and commit the refreshed lib/linux-<arch>/libkrun.so.
set -euo pipefail

FLOOR="2.31"
status=0

for so in lib/linux-x86_64/libkrun.so lib/linux-aarch64/libkrun.so; do
  if [ ! -f "$so" ]; then
    echo "::error::$so is missing (LFS not pulled?)"
    status=1
    continue
  fi
  maxv=$(objdump -T "$so" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)
  echo "max GLIBC required by $so: ${maxv:-none}"
  if [ -n "$maxv" ] && [ "$(printf '%s\n%s\n' "$maxv" "$FLOOR" | sort -V | tail -1)" != "$FLOOR" ]; then
    echo "::error::$so requires glibc $maxv (> $FLOOR) — rebuild via build-libkrun.yml"
    status=1
  fi
done

if [ "$status" = 0 ]; then
  echo "OK: all bundled linux libkrun.so glibc floors are <= $FLOOR"
fi
exit "$status"
