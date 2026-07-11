#!/usr/bin/env bash
# Verify every bundled libkrun exports all the symbols smolvm *requires* at
# runtime — the `load_sym!` set in src/agent/krun.rs.
#
# Why this exists: smolvm dlopen()s the platform libkrun and resolves each
# required symbol. A lib missing one fails at startup with
# "symbol not found: <sym>" on that OS only. CI cross-compiles smolvm and
# packages the libs but never dlopens them on the target, so a lib built with
# the wrong feature set (e.g. the Windows krun.dll shipped once without the
# `blk`/disk API) sails through green and breaks only on a user's machine.
# This check is that missing dlopen, done statically at build time.
#
# Optional symbols (load_optional_sym!) are intentionally NOT required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KRUN_RS="$ROOT/src/agent/krun.rs"

# Source of truth: the identifiers passed to load_sym!(...) (required), not the
# string literals passed to load_optional_sym!(...) (optional).
mapfile -t REQUIRED < <(grep -oE 'load_sym!\(krun_[a-z0-9_]+\)' "$KRUN_RS" \
  | sed -E 's/.*\((krun_[a-z0-9_]+)\)/\1/' | sort -u)
if [ "${#REQUIRED[@]}" -eq 0 ]; then
  echo "ERROR: parsed 0 required symbols from $KRUN_RS — check the load_sym! pattern"
  exit 1
fi
echo "smolvm requires ${#REQUIRED[@]} krun symbols (load_sym!):"
printf '  %s\n' "${REQUIRED[@]}"
echo

# Print the exported krun_* names of a shared library, format-detected.
exports_of() {
  local f="$1"
  case "$f" in
    *.dll)
      local od
      od="$(command -v x86_64-w64-mingw32-objdump || command -v llvm-objdump || command -v objdump)"
      # PE export directory lists the exported names; grep the krun_* ones.
      "$od" -p "$f" 2>/dev/null | grep -oE 'krun_[a-z0-9_]+'
      ;;
    *)
      # ELF (.so) or Mach-O (.dylib). llvm-nm reads both; fall back to nm.
      local nmtool
      nmtool="$(command -v llvm-nm || command -v nm)"
      # Defined external text symbols; leading '_' on Mach-O is ignored by the
      # krun_* grep. Try dynamic (-D, ELF) then general defined (-gU, Mach-O).
      { "$nmtool" -D --defined-only "$f" 2>/dev/null; "$nmtool" -gU "$f" 2>/dev/null; } \
        | grep -oE 'krun_[a-z0-9_]+'
      ;;
  esac | sort -u
}

# Resolve to the real files (skip symlinks; pick the versioned .so).
libs=()
[ -f "$ROOT/lib/libkrun.dylib" ] && libs+=("$ROOT/lib/libkrun.dylib")
for d in linux-x86_64 linux-aarch64; do
  so="$(ls "$ROOT/lib/$d"/libkrun.so.*.* 2>/dev/null | head -1 || true)"
  [ -n "$so" ] && libs+=("$so")
done
[ -f "$ROOT/lib/windows-x86_64/krun.dll" ] && libs+=("$ROOT/lib/windows-x86_64/krun.dll")

rc=0
for lib in "${libs[@]}"; do
  rel="${lib#$ROOT/}"
  present="$(exports_of "$lib")"
  if [ -z "$present" ]; then
    echo "⚠ $rel: could not read exports (missing tool for this format?) — skipping"
    continue
  fi
  missing=()
  for sym in "${REQUIRED[@]}"; do
    grep -qxF "$sym" <<<"$present" || missing+=("$sym")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    echo "✓ $rel — all ${#REQUIRED[@]} required symbols exported"
  else
    echo "✗ $rel — MISSING ${#missing[@]} required symbol(s): ${missing[*]}"
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo
  echo "FAIL: a bundled libkrun is missing symbols smolvm requires — it would"
  echo "fail at dlopen on that platform. Rebuild that lib with the correct"
  echo "features (the disk API needs the 'blk' feature) and re-stamp lib/."
fi
exit "$rc"
