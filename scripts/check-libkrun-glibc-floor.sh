#!/usr/bin/env bash
# Assert the bundled linux libraries (libkrun, libkrunfw and the host renderer)
# keep a glibc symbol floor <= 2.28 — the release runtime floor (the dist
# binaries link against glibc 2.28, see release.yml). A library linked against a
# newer glibc loads fine on that host but fails on RHEL 8 / Debian 10 hosts with
# "GLIBC_x.y not found" before the VM can boot (issue #636). objdump -T reads the
# ELF version-needed records; the check is arch-independent (an x86_64 objdump
# reads the arm64 .so fine).
#
# If libkrun fails, rebuild it via the build-libkrun workflow (which links
# against glibc 2.28); if the renderer fails, via build-virglrenderer-linux.yml.
# Then commit the refreshed files in lib/linux-<arch>/.
set -euo pipefail

FLOOR="2.28"
status=0

for arch in x86_64 aarch64; do
  for name in libkrun.so libkrunfw.so libvirglrenderer.so libepoxy.so virgl_render_server; do
    so="lib/linux-$arch/$name"
    if [ ! -f "$so" ]; then
      echo "::error::$so is missing (LFS not pulled?)"
      status=1
      continue
    fi
    maxv=$(objdump -T "$so" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)
    echo "max GLIBC required by $so: ${maxv:-none}"
    if [ -n "$maxv" ] && [ "$(printf '%s\n%s\n' "$maxv" "$FLOOR" | sort -V | tail -1)" != "$FLOOR" ]; then
      echo "::error::$so requires glibc $maxv (> $FLOOR) — rebuild it (see above)"
      status=1
    fi
  done
done

if [ "$status" = 0 ]; then
  echo "OK: all bundled linux library glibc floors are <= $FLOOR"
fi
exit "$status"
