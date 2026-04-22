#!/bin/bash
# Install smolvm from a local tarball or build directory
#
# Usage:
#   ./scripts/install-local.sh                    # Install from dist/
#   ./scripts/install-local.sh path/to/tarball    # Install from tarball
#   ./scripts/install-local.sh --uninstall        # Uninstall

set -e

INSTALL_PREFIX="${HOME}/.smolvm"
BIN_DIR="${HOME}/.local/bin"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info() { echo -e "${BLUE}info:${NC} $1"; }
success() { echo -e "${GREEN}success:${NC} $1"; }
warn() { echo -e "${YELLOW}warning:${NC} $1"; }
error() { echo -e "${RED}error:${NC} $1" >&2; }

# Check platform requirements
check_requirements() {
    # macOS-specific checks
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local macos_version
        macos_version=$(sw_vers -productVersion 2>/dev/null || echo "0.0")
        local major_version
        major_version=$(echo "$macos_version" | cut -d. -f1)

        if [[ "$major_version" -lt 11 ]]; then
            error "smolvm requires macOS 11.0 or later (you have $macos_version)"
            exit 1
        fi
    fi

    # Linux-specific checks
    if [[ "$(uname -s)" == "Linux" ]]; then
        if [[ ! -e /dev/kvm ]]; then
            warn "/dev/kvm not found. smolvm requires KVM support."
            warn "Make sure your system supports virtualization and KVM is enabled."
        fi
    fi
}

# Find tarball in dist directory
find_tarball() {
    local platform
    platform="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"

    # Try exact match first
    local tarball
    tarball=$(find dist -maxdepth 1 -name "smolvm-*-${platform}.tar.gz" 2>/dev/null | head -1)

    # Try with arm64 variant
    if [[ -z "$tarball" && "$platform" == *-aarch64 ]]; then
        platform="${platform/aarch64/arm64}"
        tarball=$(find dist -maxdepth 1 -name "smolvm-*-${platform}.tar.gz" 2>/dev/null | head -1)
    fi

    echo "$tarball"
}

# Install from directory
install_from_dir() {
    local src_dir="$1"

    # Verify required files exist
    if [[ ! -f "$src_dir/smolvm" ]] || [[ ! -f "$src_dir/smolvm-bin" ]]; then
        error "Invalid smolvm distribution: missing smolvm or smolvm-bin"
        exit 1
    fi

    if [[ ! -d "$src_dir/lib" ]]; then
        error "Invalid smolvm distribution: missing lib directory"
        exit 1
    fi

    # Get version from distribution or default
    local version="dev"
    if [[ -f "$src_dir/README.txt" ]]; then
        version=$(echo "$src_dir" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "dev")
    fi

    info "Installing smolvm $version to $INSTALL_PREFIX"

    # Create installation directory
    mkdir -p "$INSTALL_PREFIX"

    # Remove old installation
    rm -rf "$INSTALL_PREFIX/lib"
    rm -f "$INSTALL_PREFIX/smolvm" "$INSTALL_PREFIX/smolvm-bin"

    # Copy files
    cp -r "$src_dir/lib" "$INSTALL_PREFIX/"
    cp "$src_dir/smolvm" "$INSTALL_PREFIX/"
    cp "$src_dir/smolvm-bin" "$INSTALL_PREFIX/"
    chmod +x "$INSTALL_PREFIX/smolvm" "$INSTALL_PREFIX/smolvm-bin"

    if [[ "$(uname -s)" == "Darwin" ]] && [[ -f "$INSTALL_PREFIX/lib/libkrun.dylib" ]] && [[ ! -e "$INSTALL_PREFIX/lib/libkrun.1.dylib" ]]; then
        ln -sf libkrun.dylib "$INSTALL_PREFIX/lib/libkrun.1.dylib"
    fi

    # Install agent-rootfs to data directory
    local data_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        data_dir="$HOME/Library/Application Support/smolvm"
    else
        data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi

    if [[ -d "$src_dir/agent-rootfs" ]]; then
        info "Installing agent-rootfs to $data_dir..."
        mkdir -p "$data_dir"
        rm -rf "$data_dir/agent-rootfs"
        # Use cp -a to preserve symlinks (busybox creates many symlinks)
        cp -a "$src_dir/agent-rootfs" "$data_dir/"
        success "Agent rootfs installed"
    else
        warn "agent-rootfs not found in distribution"
    fi

    # Copy init.krun if present (Linux only, required by libkrunfw kernel)
    if [[ -f "$src_dir/init.krun" ]]; then
        info "Installing init.krun to $data_dir..."
        cp "$src_dir/init.krun" "$data_dir/init.krun"
        chmod +x "$data_dir/init.krun"
        success "init.krun installed"
    fi

    # Store version
    echo "$version" > "$INSTALL_PREFIX/.version"

    # Create symlink
    mkdir -p "$BIN_DIR"
    ln -sf "$INSTALL_PREFIX/smolvm" "$BIN_DIR/smolvm"

    success "Installed smolvm to $INSTALL_PREFIX"
    success "Symlink created at $BIN_DIR/smolvm"
}

# Uninstall
uninstall() {
    info "Uninstalling smolvm..."

    if [[ -d "$INSTALL_PREFIX" ]]; then
        rm -rf "$INSTALL_PREFIX"
        success "Removed $INSTALL_PREFIX"
    fi

    if [[ -L "$BIN_DIR/smolvm" ]]; then
        rm -f "$BIN_DIR/smolvm"
        success "Removed $BIN_DIR/smolvm"
    fi

    success "smolvm uninstalled"
}

# Main
main() {
    echo ""
    echo -e "${BOLD}smolvm local installer${NC}"
    echo ""

    # Handle uninstall
    if [[ "$1" == "--uninstall" ]]; then
        uninstall
        exit 0
    fi

    # Check platform requirements
    check_requirements

    local tarball="$1"
    local tmp_dir=""
    local install_dir=""

    # If no argument, find tarball in dist/
    if [[ -z "$tarball" ]]; then
        tarball=$(find_tarball)
        if [[ -z "$tarball" ]]; then
            error "No tarball found in dist/"
            error "Run './scripts/build-dist.sh' first or specify a tarball path."
            exit 1
        fi
        info "Found tarball: $tarball"
    fi

    # Check if it's a tarball or directory
    if [[ -f "$tarball" && "$tarball" == *.tar.gz ]]; then
        # Extract tarball
        tmp_dir=$(mktemp -d)
        info "Extracting $tarball..."
        tar -xzf "$tarball" -C "$tmp_dir"

        install_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "smolvm-*" | head -1)
        if [[ -z "$install_dir" ]]; then
            error "Could not find smolvm directory in tarball"
            rm -rf "$tmp_dir"
            exit 1
        fi
    elif [[ -d "$tarball" ]]; then
        # Use directory directly
        install_dir="$tarball"
    else
        error "Not a valid tarball or directory: $tarball"
        exit 1
    fi

    # Install
    install_from_dir "$install_dir"

    # Cleanup
    if [[ -n "$tmp_dir" ]]; then
        rm -rf "$tmp_dir"
    fi

    # Check PATH
    echo ""
    if ! echo "$PATH" | grep -q "$BIN_DIR"; then
        warn "$BIN_DIR is not in your PATH"
        echo ""
        echo "Add to your shell profile:"
        echo "    export PATH=\"$BIN_DIR:\$PATH\""
        echo ""
    fi

    echo "Test your installation:"
    echo "    smolvm --help"
    echo ""
}

main "$@"
