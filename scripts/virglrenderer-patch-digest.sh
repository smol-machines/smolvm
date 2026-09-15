#!/usr/bin/env bash
# Print one digest for the whole patch set in patches/virglrenderer/, in name
# order, so the same patches always yield the same value on any host.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v sha256sum >/dev/null 2>&1; then
  cat $(ls patches/virglrenderer/*.patch | sort) | sha256sum | cut -c1-16
else
  cat $(ls patches/virglrenderer/*.patch | sort) | shasum -a 256 | cut -c1-16
fi
