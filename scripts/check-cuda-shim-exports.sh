#!/bin/sh
# Fail when an application-required CUDA symbol is absent from the guest shim.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
shim=${1:-"$root/target/release/libcudart.so"}
matrix="$root/tests/fixtures/cudart-exports/application-facing.txt"
fallback="$root/crates/smolvm-cudart-shim/abi/required-application-exports.txt"
if [ -f "$matrix" ]; then
    required=$matrix
else
    required=$fallback
fi

if [ ! -f "$shim" ]; then
    echo "CUDA runtime shim not found: $shim" >&2
    exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
LC_ALL=C awk 'NF && $1 !~ /^#/ { print $1 }' "$required" | sort -u > "$tmp/required"
LC_ALL=C nm -D --defined-only "$shim" \
    | awk 'NF >= 3 { sub(/@.*/, "", $3); print $3 }' \
    | sort -u > "$tmp/exported"
comm -23 "$tmp/required" "$tmp/exported" > "$tmp/missing"

if [ -s "$tmp/missing" ]; then
    echo "Missing application-required CUDA shim exports:" >&2
    sed 's/^/  /' "$tmp/missing" >&2
    exit 1
fi

echo "CUDA shim ABI gate passed ($(wc -l < "$tmp/required" | tr -d ' ') required exports)."
