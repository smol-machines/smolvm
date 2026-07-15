#!/usr/bin/env bash
# Assert the bundled linux libkrun.so libraries keep a glibc symbol floor <= 2.35
# — the release runtime floor (the dist binaries build on ubuntu-22.04). A libkrun
# built on a newer distro (e.g. Ubuntu 24.04 / glibc 2.39) loads fine there but
# fails on 22.04 / Debian 12 hosts with "GLIBC_2.39 not found" before the VM can
# boot (issue #636). objdump -T reads the ELF version-needed records; the check is
# arch-independent (an x86_64 objdump reads the arm64 .so fine).
#
# If this fails, rebuild the libs on ubuntu-22.04 via the build-libkrun workflow
# and commit the refreshed lib/linux-<arch>/libkrun.so.
set -euo pipefail

FLOOR="2.35"
status=0

for so in lib/linux-x86_64/libkrun.so lib/linux-arm64/libkrun.so; do
  if [ ! -f "$so" ]; then
    echo "::error::$so is missing (LFS not pulled?)"
    status=1
    continue
  fi
  maxv=$(objdump -T "$so" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)
  echo "max GLIBC required by $so: ${maxv:-none}"
  if [ -n "$maxv" ] && [ "$(printf '%s\n%s\n' "$maxv" "$FLOOR" | sort -V | tail -1)" != "$FLOOR" ]; then
    echo "::error::$so requires glibc $maxv (> $FLOOR) — rebuild on ubuntu-22.04 via build-libkrun.yml"
    status=1
  fi
done

if [ "$status" = 0 ]; then
  echo "OK: all bundled linux libkrun.so glibc floors are <= $FLOOR"
fi
exit "$status"
