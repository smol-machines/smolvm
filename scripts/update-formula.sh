#!/usr/bin/env bash
# Update the Homebrew formula with SHA256 hashes from dist/ tarballs
#
# Usage: ./scripts/update-formula.sh
#
# This script reads tarballs from dist/ and updates the formula with correct SHA256 hashes.

set -e

FORMULA="homebrew-tap/Formula/smolvm.rb"
VERSION="${VERSION:-$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)}"

# Colors
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' NC=''
fi

info() { echo -e "${GREEN}info:${NC} $1"; }
warn() { echo -e "${YELLOW}warning:${NC} $1"; }

echo "Updating formula for version $VERSION"

# Check formula exists
if [[ ! -f "$FORMULA" ]]; then
    echo "Error: Formula not found at $FORMULA"
    exit 1
fi

# Update version in formula
sed -i '' "s/version \"[^\"]*\"/version \"$VERSION\"/" "$FORMULA"
info "Updated version to $VERSION"

# Platform mapping: tarball name -> placeholder name in formula
declare -A PLATFORMS=(
    ["darwin-arm64"]="PLACEHOLDER_DARWIN_ARM64_SHA256"
    ["darwin-x86_64"]="PLACEHOLDER_DARWIN_X86_64_SHA256"
    ["linux-arm64"]="PLACEHOLDER_LINUX_ARM64_SHA256"
    ["linux-x86_64"]="PLACEHOLDER_LINUX_X86_64_SHA256"
)

# Calculate and update SHA256 for each platform
echo ""
echo "Updating SHA256 hashes:"

for platform in "${!PLATFORMS[@]}"; do
    tarball="dist/smolvm-${VERSION}-${platform}.tar.gz"
    placeholder="${PLATFORMS[$platform]}"

    if [[ -f "$tarball" ]]; then
        sha=$(shasum -a 256 "$tarball" | cut -d' ' -f1)
        info "$platform: $sha"

        # Replace placeholder or existing SHA with new one
        # First try to replace the placeholder
        if grep -q "$placeholder" "$FORMULA"; then
            sed -i '' "s/$placeholder/$sha/" "$FORMULA"
        fi

        # Also try to replace any existing 64-char hex string on lines mentioning this platform
        # This handles re-running the script
    else
        warn "$platform: tarball not found at $tarball"
    fi
done

echo ""
info "Formula updated at $FORMULA"

# Generate checksums.txt for releases
CHECKSUMS_FILE="dist/checksums.txt"
echo ""
echo "Generating $CHECKSUMS_FILE for release..."
rm -f "$CHECKSUMS_FILE"

for tarball in dist/smolvm-${VERSION}-*.tar.gz; do
    if [[ -f "$tarball" ]]; then
        shasum -a 256 "$tarball" >> "$CHECKSUMS_FILE"
    fi
done

if [[ -f "$CHECKSUMS_FILE" ]]; then
    info "Created $CHECKSUMS_FILE:"
    cat "$CHECKSUMS_FILE"
else
    warn "No tarballs found to generate checksums"
fi

echo ""
echo "Next steps:"
echo "  1. Review changes: git diff $FORMULA"
echo "  2. Test formula locally: brew install --build-from-source $FORMULA"
echo "  3. Commit and push to homebrew-tap repo"
