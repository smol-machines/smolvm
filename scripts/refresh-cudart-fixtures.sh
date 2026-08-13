#!/usr/bin/env bash
# Regenerate tests/fixtures/cudart-exports/: the set of symbols each CUDA-13
# workload image imports from a soname smolvm stages its cudart shim over.
#
# Why this exists: smolvm bind-mounts one cdylib (libcudart-shim.so) over each
# RPATH_PINNED_SONAMES entry it finds in an image (crates/smolvm-agent/src/cuda.rs).
# Every symbol an image imports from one of those sonames therefore has to be an
# export of the shim. Miss one and the workload dies at dlopen with
# "undefined symbol: <sym>, version libcudart.so.13" — a hard ImportError with no
# partial-functionality warning, on a --cuda machine only. Nothing in CI catches
# it: we build the shim but never load a real torch against it.
#
# The trap this encodes: the required set is NOT stable across images. It is a
# property of how each torch build was compiled, and it drifts non-monotonically.
# Measured across the matrix below, no two images require the same set — 2.11.0
# and vllm differ by 98 symbols. So enumerating the surface from whichever image
# is currently failing converges on nothing; you fix one ImportError and the next
# image fails on a different symbol. These fixtures exist so the surface is a
# checked-in baseline that a diff can be taken against, instead of being
# rediscovered one crash at a time.
#
# Two things this scan gets right that a naive one does not:
#
#   1. It reads EVERY ELF shared object in the rootfs, not just torch's. cuSOLVER,
#      cuSOLVER-Mg and nvBLAS are real NVIDIA wheels that are NOT staged over, so
#      they load for real — and they link libcublas.so.13, which IS staged over.
#      That makes them clients of the shim. A torch-only scan misses them, and
#      also misses libtorch_nvshmem.so, which exists only in torch 2.11+.
#   2. It keys on the ELF symbol VERSION TAG, not on a `cuda[A-Z]` name heuristic.
#      "A requirement on the shim" has an exact definition — an undefined symbol
#      whose version tag names one of RPATH_PINNED_SONAMES — and that is a closed
#      question about the image rather than a guess about which names matter. The
#      earlier name-heuristic scan undercounted every image by 129-234 symbols.
#
# Images are pinned BY DIGEST, not by tag. vllm/vllm-openai:latest moved within
# hours of the original audit; a fixture regenerated from a moving tag produces a
# different file every run and the diff stops being reviewable. Refreshing to a
# newer image is therefore a deliberate, reviewable edit to the digests below.
#
# Needs: curl, jq, tar, and an ELF-capable nm (binutils). No Docker daemon and no
# GPU — layers are streamed straight from the registry API.
#
# Usage:
#   scripts/refresh-cudart-fixtures.sh            # regenerate all images
#   scripts/refresh-cudart-fixtures.sh torch290   # regenerate one
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE_DIR="$ROOT/tests/fixtures/cudart-exports"
CUDA_RS="$ROOT/crates/smolvm-agent/src/cuda.rs"

# The image matrix, pinned by manifest digest. Format: key|repo|tag|digest
# The tag is retained for provenance only; the digest is what gets fetched.
IMAGES=(
  "torch290|pytorch/pytorch|2.9.0-cuda13.0-cudnn9-runtime|sha256:1ba3f20399f5e4f9835cde308a4de86c3e63ba098caee367e490ec5455afc02a"
  "torch2100|pytorch/pytorch|2.10.0-cuda13.0-cudnn9-runtime|sha256:1f57418aedd9a4d0d3a59646619e1d4f82cacc33817247cead4f749e1f452d4b"
  "torch2110|pytorch/pytorch|2.11.0-cuda13.0-cudnn9-runtime|sha256:bfbb4a2b4fdba0fefdb428ea737e626d61bb3daf74a16e1ff935bdb03aa7c3f0"
  "torch2130|pytorch/pytorch|2.13.0-cuda13.0-cudnn9-runtime|sha256:db80a41f8428644cebcb3d75b0b62df334ab6c0e75785951eb25f48bfbd42407"
  "vllm|vllm/vllm-openai|latest|sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52"
)

# Source of truth for what the shim stands in for: the RPATH_PINNED_SONAMES array
# in cuda.rs. Parsed rather than duplicated so adding a soname there (a cu14 wheel
# layout, say) widens this scan automatically instead of silently not widening it.
# (while-read rather than mapfile: this has to run on macOS bash 3.2 too, so a
# maintainer can regenerate without a newer bash.)
SONAMES=()
while IFS= read -r s; do
  [ -n "$s" ] && SONAMES+=("$s")
done < <(
  sed -n '/RPATH_PINNED_SONAMES/,/];/p' "$CUDA_RS" \
    | grep -oE '"lib[a-zA-Z]+\.so[0-9.]*"' | tr -d '"' | sort -u
)
if [ "${#SONAMES[@]}" -eq 0 ]; then
  echo "ERROR: parsed 0 sonames from $CUDA_RS — check the RPATH_PINNED_SONAMES pattern" >&2
  exit 1
fi

NM="$(command -v llvm-nm || command -v nm)"
for tool in curl jq tar; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done

REG="https://registry-1.docker.io"
ACCEPT='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'

# Registry tokens are short-lived; re-mint per layer rather than per image.
token_for() {
  curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$1:pull" | jq -r .token
}

# Stream every layer of one image and extract every shared object. Layers are
# applied in order, so a later layer overwrites an earlier one exactly as the
# union filesystem would.
extract_image() {
  local repo="$1" digest="$2" dest="$3"
  local tok manifest sub
  tok="$(token_for "$repo")"
  manifest="$(curl -s -H "Authorization: Bearer $tok" -H "Accept: $ACCEPT" \
    "$REG/v2/$repo/manifests/$digest")"
  # Multi-arch index: descend to the linux/amd64 manifest.
  if jq -e '.mediaType // "" | test("index|list")' <<<"$manifest" >/dev/null 2>&1; then
    sub="$(jq -r '.manifests[] | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' <<<"$manifest" | head -1)"
    manifest="$(curl -s -H "Authorization: Bearer $tok" -H "Accept: $ACCEPT" \
      "$REG/v2/$repo/manifests/$sub")"
  fi
  local layers=()
  local l
  while IFS= read -r l; do
    [ -n "$l" ] && layers+=("$l")
  done < <(jq -r '.layers[].digest' <<<"$manifest")
  local i=0
  for l in "${layers[@]}"; do
    i=$((i + 1))
    echo "     layer $i/${#layers[@]}"
    tok="$(token_for "$repo")"
    curl -sL -H "Authorization: Bearer $tok" "$REG/v2/$repo/blobs/$l" \
      | tar -xf - -C "$dest" --no-same-owner '*.so' '*.so.*' 2>/dev/null || true
  done
}

# Emit the sorted symbol set one rootfs imports from a staged soname.
scan_rootfs() {
  local dest="$1"
  local sopattern
  # "sym@@libcudart.so.13" / "sym@libcudart.so.13" — anchor on the version tag.
  sopattern="$(printf '%s\n' "${SONAMES[@]}" | sed 's/\./\\./g' | paste -sd'|' -)"
  find "$dest" -type f \( -name '*.so' -o -name '*.so.*' \) -print0 \
    | while IFS= read -r -d '' f; do
        # A file the shim itself replaces is not a client of the shim; its own
        # imports are irrelevant because that file never loads.
        case " ${SONAMES[*]} " in *" $(basename "$f") "*) continue ;; esac
        "$NM" -D --undefined-only "$f" 2>/dev/null \
          | grep -oE "[A-Za-z_][A-Za-z0-9_]*@@?($sopattern)\$" || true
      done \
    | sed -E 's/@@?.*$//' | sort -u
}

mkdir -p "$FIXTURE_DIR"
only="${1:-}"
rc=0

for entry in "${IMAGES[@]}"; do
  IFS='|' read -r key repo tag digest <<<"$entry"
  [ -n "$only" ] && [ "$only" != "$key" ] && continue

  echo "==> $repo:$tag"
  echo "    $digest"
  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT

  extract_image "$repo" "$digest" "$work"
  count_so="$(find "$work" -type f \( -name '*.so' -o -name '*.so.*' \) | wc -l | tr -d ' ')"
  syms="$(scan_rootfs "$work")"
  n="$(printf '%s\n' "$syms" | grep -c . || true)"

  if [ "$n" -eq 0 ]; then
    echo "ERROR: scanned $count_so shared objects but found 0 staged-soname imports" >&2
    echo "       (a broken nm or an empty extract would look exactly like this)" >&2
    rc=1
    rm -rf "$work"; trap - EXIT
    continue
  fi

  out="$FIXTURE_DIR/$key.txt"
  {
    echo "# $repo:$tag"
    echo "# $digest"
    echo "# Symbols this image imports from a soname smolvm stages its cudart shim over."
    echo "# Generated: nm -D --undefined-only over EVERY .so in the image rootfs,"
    echo "# keeping undefined symbols whose ELF version tag is one of"
    echo "# RPATH_PINNED_SONAMES (crates/smolvm-agent/src/cuda.rs)."
    echo "# $n symbols from $count_so shared objects."
    echo "# Regenerate with scripts/refresh-cudart-fixtures.sh — do not hand-edit."
    printf '%s\n' "$syms"
  } > "$out"
  echo "    wrote ${out#"$ROOT"/} — $n symbols from $count_so shared objects"

  rm -rf "$work"; trap - EXIT
done

# The union is what the shim must export to cover the whole matrix; it is derived,
# never hand-maintained. Rebuilt from the on-disk fixtures after every run,
# including a single-image one — deriving it from this run's scan instead would
# leave union.txt silently stale whenever one image was refreshed on its own.
if [ "$rc" -eq 0 ]; then
  union="$FIXTURE_DIR/union.txt"
  {
    echo "# Union of every image fixture — the set the shim must export."
    echo "# Derived from the per-image fixtures; do not hand-edit."
    grep -hv '^#' "$FIXTURE_DIR"/torch*.txt "$FIXTURE_DIR"/vllm.txt | sort -u
  } > "$union"
  echo "==> wrote ${union#"$ROOT"/} — $(grep -cv '^#' "$union") symbols"
fi

exit "$rc"
