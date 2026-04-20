#!/usr/bin/env bash
# Populate the repo's lib/ directory with the native libkrun and libkrunfw
# binaries pinned in lib/manifest.toml, fetching them from the smolvm GitHub
# Release assets listed there.
#
# Release assets do not share bandwidth quota with Git LFS, so this path is
# stable even when the repo's LFS budget is exhausted.
#
# Usage:
#   scripts/ensure-libs.sh             # fetch if missing or out of date
#   scripts/ensure-libs.sh --check     # verify only, no downloads
#   scripts/ensure-libs.sh --force     # always re-fetch
#   scripts/ensure-libs.sh --platform darwin-arm64
#
# Environment overrides:
#   LIBKRUN_BUNDLE   Use pre-staged libraries from this directory instead of
#                    downloading. SHA256s are still verified against the
#                    manifest; a mismatch is a hard error.
#   ENSURE_LIBS_TMP  Temporary work directory (default: target/ensure-libs).
#   GH_REPO          Override the repo used for downloads (default from manifest).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/lib/manifest.toml"

cd "$REPO_ROOT"

# Track every per-run temporary directory we create so a Ctrl-C, kill, or
# unexpected error unwinds them. TMP_ROOT itself is a cache and is NOT cleaned
# up; only the ephemeral staging/extract dirs inside it are.
_ENSURE_LIBS_CLEANUP=()
_ensure_libs_cleanup() {
    local d rc=$?
    if [[ ${#_ENSURE_LIBS_CLEANUP[@]} -gt 0 ]]; then
        for d in "${_ENSURE_LIBS_CLEANUP[@]}"; do
            [[ -n "$d" && -d "$d" ]] && rm -rf "$d"
        done
    fi
    return "$rc"
}
trap _ensure_libs_cleanup EXIT INT TERM

MODE="fetch"
FORCE=0
PLATFORM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) MODE="check"; shift ;;
        --force) FORCE=1; shift ;;
        --platform) PLATFORM="${2:-}"; shift 2 ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "ensure-libs: unknown argument: $1" >&2; exit 2 ;;
    esac
done

log()  { printf 'ensure-libs: %s\n' "$*"; }
warn() { printf 'ensure-libs: warning: %s\n' "$*" >&2; }
die()  { printf 'ensure-libs: error: %s\n' "$*" >&2; exit 1; }

# --- dependency detection --------------------------------------------------

if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    die "neither sha256sum nor shasum is installed"
fi

download_to() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "neither curl nor wget is installed; set LIBKRUN_BUNDLE to a local directory or install one of them"
    fi
}

# --- platform detection ----------------------------------------------------

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Darwin) os="darwin" ;;
        Linux)  os="linux" ;;
        *) die "unsupported OS: $os" ;;
    esac
    case "$arch" in
        arm64|aarch64) arch="arm64"; [[ "$os" == "linux" ]] && arch="aarch64" ;;
        x86_64|amd64)  arch="x86_64" ;;
        *) die "unsupported architecture: $arch" ;;
    esac
    printf '%s-%s\n' "$os" "$arch"
}

if [[ -z "$PLATFORM" ]]; then
    PLATFORM="$(detect_platform)"
fi

# --- manifest parsing ------------------------------------------------------
#
# The manifest is a small, predictable TOML subset. We parse it with awk so
# the script has no Python/toml dependencies.

read_scalar() {
    # Usage: read_scalar <key>  (from top-level table)
    awk -v k="$1" '
        $0 ~ "^" k " *= *\"" { sub("^" k " *= *\"", ""); sub("\".*$", ""); print; exit }
    ' "$MANIFEST"
}

read_platform_scalar() {
    # Usage: read_platform_scalar <platform> <key>
    awk -v plat="$1" -v k="$2" '
        $0 ~ "^\\[platform\\.\"" plat "\"\\]" { in_sec = 1; next }
        /^\[/ { in_sec = 0 }
        in_sec && $0 ~ "^" k " *= *\"" {
            sub("^" k " *= *\"", "")
            sub("\".*$", "")
            print
            exit
        }
    ' "$MANIFEST"
}

# Emit one line per file entry in the platform's `files = [ ... ]` array.
# Format (tab-separated): kind<TAB>name<TAB>sha256_or_target
read_platform_files() {
    awk -v plat="$1" '
        BEGIN { in_sec = 0; in_files = 0 }
        $0 ~ "^\\[platform\\.\"" plat "\"\\]" { in_sec = 1; next }
        /^\[/ { in_sec = 0; in_files = 0 }
        in_sec && /^files *= *\[/ { in_files = 1; next }
        in_files && /^\]/ { in_files = 0; next }
        in_files && /\{/ {
            line = $0
            name = ""; kind = ""; sha = ""; target = ""
            if (match(line, /name *= *"[^"]+"/)) {
                s = substr(line, RSTART, RLENGTH); sub(/name *= *"/, "", s); sub(/"$/, "", s); name = s
            }
            if (match(line, /kind *= *"[^"]+"/)) {
                s = substr(line, RSTART, RLENGTH); sub(/kind *= *"/, "", s); sub(/"$/, "", s); kind = s
            }
            if (match(line, /sha256 *= *"[^"]+"/)) {
                s = substr(line, RSTART, RLENGTH); sub(/sha256 *= *"/, "", s); sub(/"$/, "", s); sha = s
            }
            if (match(line, /target *= *"[^"]+"/)) {
                s = substr(line, RSTART, RLENGTH); sub(/target *= *"/, "", s); sub(/"$/, "", s); target = s
            }
            if (kind == "symlink") printf "%s\t%s\t%s\n", kind, name, target
            else                   printf "%s\t%s\t%s\n", kind, name, sha
        }
    ' "$MANIFEST"
}

RELEASE_TAG="$(read_scalar release_tag)"
GH_REPO_DEFAULT="$(read_scalar repo)"
GH_REPO="${GH_REPO:-$GH_REPO_DEFAULT}"

[[ -n "$RELEASE_TAG" ]] || die "manifest is missing release_tag"
[[ -n "$GH_REPO" ]]     || die "manifest is missing repo"

TARBALL="$(read_platform_scalar "$PLATFORM" tarball)"
TARBALL_SHA="$(read_platform_scalar "$PLATFORM" tarball_sha256)"
EXTRACT_TO="$(read_platform_scalar "$PLATFORM" extract_to)"
TARBALL_LIB_DIR="$(read_platform_scalar "$PLATFORM" tarball_lib_dir)"

if [[ -z "$TARBALL" || -z "$EXTRACT_TO" ]]; then
    die "manifest has no entry for platform '$PLATFORM'. Known-good platforms are defined in lib/manifest.toml."
fi

# --- file-level verification ----------------------------------------------

verify_installed() {
    # Returns 0 if every file/symlink listed in the manifest is present at
    # $EXTRACT_TO and matches the pinned hash/target. Returns 1 otherwise.
    local kind name value path actual
    while IFS=$'\t' read -r kind name value; do
        path="$EXTRACT_TO/$name"
        if [[ "$kind" == "symlink" ]]; then
            if [[ ! -L "$path" ]]; then return 1; fi
            actual="$(readlink "$path")"
            [[ "$actual" == "$value" ]] || return 1
        else
            [[ -f "$path" && ! -L "$path" ]] || return 1
            actual="$(sha256_of "$path")"
            [[ "$actual" == "$value" ]] || return 1
        fi
    done < <(read_platform_files "$PLATFORM")
    return 0
}

install_from_dir() {
    # Stage the platform's files from $1 into $EXTRACT_TO. Verifies SHA256 per
    # file up front, so the destination is not touched unless every expected
    # file is present and matches its pinned hash. Individual moves are atomic
    # on a single filesystem; if the script is interrupted mid-promotion, some
    # files may be new and some old, but each file is either fully old or
    # fully new (never truncated). A subsequent run will observe the mismatch
    # via verify_installed and re-promote.
    local src="$1" kind name value expected actual dst tmp_dir
    mkdir -p "$EXTRACT_TO"
    tmp_dir="$(mktemp -d "${ENSURE_LIBS_TMP:-$REPO_ROOT/target/ensure-libs}/stage.XXXXXX")"
    _ENSURE_LIBS_CLEANUP+=("$tmp_dir")

    while IFS=$'\t' read -r kind name value; do
        if [[ "$kind" == "symlink" ]]; then
            ln -sf "$value" "$tmp_dir/$name"
        else
            [[ -f "$src/$name" ]] || die "missing '$name' in $src"
            actual="$(sha256_of "$src/$name")"
            expected="$value"
            if [[ "$actual" != "$expected" ]]; then
                die "sha256 mismatch for '$name' (expected $expected, got $actual). Source: $src"
            fi
            cp "$src/$name" "$tmp_dir/$name"
        fi
    done < <(read_platform_files "$PLATFORM")

    while IFS=$'\t' read -r kind name value; do
        dst="$EXTRACT_TO/$name"
        rm -f "$dst"
        mv "$tmp_dir/$name" "$dst"
    done < <(read_platform_files "$PLATFORM")

    rm -rf "$tmp_dir"
}

# --- main flow -------------------------------------------------------------

log "platform: $PLATFORM  release: $RELEASE_TAG  repo: $GH_REPO"

if [[ "$FORCE" -eq 0 ]] && verify_installed; then
    log "lib/ is up to date, nothing to do"
    exit 0
fi

if [[ "$MODE" == "check" ]]; then
    die "lib/ is missing or does not match manifest. Run scripts/ensure-libs.sh to populate."
fi

TMP_ROOT="${ENSURE_LIBS_TMP:-$REPO_ROOT/target/ensure-libs}"
mkdir -p "$TMP_ROOT"

if [[ -n "${LIBKRUN_BUNDLE:-}" ]]; then
    log "using LIBKRUN_BUNDLE=$LIBKRUN_BUNDLE"
    [[ -d "$LIBKRUN_BUNDLE" ]] || die "LIBKRUN_BUNDLE=$LIBKRUN_BUNDLE is not a directory"
    install_from_dir "$LIBKRUN_BUNDLE"
    if verify_installed; then
        log "installed from LIBKRUN_BUNDLE"
        exit 0
    else
        die "files installed from LIBKRUN_BUNDLE do not match manifest"
    fi
fi

ASSET_URL="https://github.com/$GH_REPO/releases/download/$RELEASE_TAG/$TARBALL"
TARBALL_PATH="$TMP_ROOT/$TARBALL"

if [[ ! -f "$TARBALL_PATH" ]] || [[ "$(sha256_of "$TARBALL_PATH")" != "$TARBALL_SHA" ]]; then
    log "downloading $ASSET_URL"
    download_to "$ASSET_URL" "$TARBALL_PATH.tmp"
    mv "$TARBALL_PATH.tmp" "$TARBALL_PATH"
fi

actual_sha="$(sha256_of "$TARBALL_PATH")"
if [[ -n "$TARBALL_SHA" && "$actual_sha" != "$TARBALL_SHA" ]]; then
    die "tarball sha256 mismatch (expected $TARBALL_SHA, got $actual_sha). Delete $TARBALL_PATH and retry, or update lib/manifest.toml."
fi

EXTRACT_DIR="$(mktemp -d "$TMP_ROOT/extract.XXXXXX")"
_ENSURE_LIBS_CLEANUP+=("$EXTRACT_DIR")
TARBALL_ROOT="${TARBALL%.tar.gz}"
log "extracting $TARBALL_ROOT/$TARBALL_LIB_DIR"
tar -xzf "$TARBALL_PATH" -C "$EXTRACT_DIR" "$TARBALL_ROOT/$TARBALL_LIB_DIR"

install_from_dir "$EXTRACT_DIR/$TARBALL_ROOT/$TARBALL_LIB_DIR"
rm -rf "$EXTRACT_DIR"

if verify_installed; then
    log "lib/ populated for $PLATFORM from $TARBALL"
else
    die "post-install verification failed; please re-run with --force"
fi
