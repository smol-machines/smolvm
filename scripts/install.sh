#!/usr/bin/env bash
# smolvm installer
#
# Usage:
#   curl -sSL https://smolmachines.com/install.sh | bash
#   curl -sSL https://smolmachines.com/install.sh | bash -s -- --version 0.1.1
#   curl -sSL https://smolmachines.com/install.sh | bash -s -- --prefix /opt/smolvm
#
# Options:
#   --version VERSION   Install specific version (default: latest)
#   --prefix DIR        Install to DIR (default: ~/.smolvm)
#   --no-modify-path    Don't modify shell profile
#   --uninstall         Remove smolvm installation
#   --help              Show this help message

set -e

# Configuration
GITHUB_REPO="smol-machines/smolvm"
INSTALL_PREFIX="${HOME}/.smolvm"
BIN_DIR="${HOME}/.local/bin"
MODIFY_PATH=true
VERSION=""
UNINSTALL=false

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
fi

# Print functions
info() {
    echo -e "${BLUE}info:${NC} $1"
}

success() {
    echo -e "${GREEN}success:${NC} $1"
}

warn() {
    echo -e "${YELLOW}warning:${NC} $1"
}

error() {
    echo -e "${RED}error:${NC} $1" >&2
}

# Detect platform
detect_platform() {
    local os arch

    # Detect OS
    case "$(uname -s)" in
        Darwin)
            os="darwin"
            ;;
        Linux)
            os="linux"
            ;;
        *)
            error "Unsupported operating system: $(uname -s)"
            error "smolvm supports macOS and Linux only."
            exit 1
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            error "Unsupported architecture: $(uname -m)"
            error "smolvm supports x86_64 and arm64 only."
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Check system requirements
check_requirements() {
    local platform="$1"

    # Check for curl or wget
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        error "curl or wget is required to download smolvm."
        exit 1
    fi

    # Check for tar
    if ! command -v tar &> /dev/null; then
        error "tar is required to extract smolvm."
        exit 1
    fi

    # macOS-specific checks
    if [[ "$platform" == darwin-* ]]; then
        # Check macOS version (need 11.0+)
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
    if [[ "$platform" == linux-* ]]; then
        # Check for KVM support
        if [[ ! -e /dev/kvm ]]; then
            warn "/dev/kvm not found. smolvm requires KVM support."
            warn ""
            warn "To enable KVM:"
            warn "  1. Ensure virtualization is enabled in your BIOS/UEFI"
            warn "  2. Load the KVM kernel module:"
            warn "     sudo modprobe kvm"
            warn "     sudo modprobe kvm_intel  # For Intel CPUs"
            warn "     sudo modprobe kvm_amd    # For AMD CPUs"
            warn ""
            warn "For persistent loading, add to /etc/modules-load.d/kvm.conf:"
            warn "     kvm"
            warn "     kvm_intel  # or kvm_amd"
        elif [[ ! -r /dev/kvm ]] || [[ ! -w /dev/kvm ]]; then
            warn "Cannot access /dev/kvm (permission denied)."
            warn ""
            warn "Add your user to the 'kvm' group:"
            warn "  sudo usermod -aG kvm $USER"
            warn ""
            warn "Then log out and log back in for the change to take effect."
        else
            info "KVM access verified"
        fi
    fi
}

# Get latest version from GitHub
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local version

    if command -v curl &> /dev/null; then
        version=$(curl -sSL "$url" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')
    else
        version=$(wget -qO- "$url" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')
    fi

    if [[ -z "$version" ]]; then
        # Fallback to a default version if GitHub API fails
        echo "0.1.1"
    else
        echo "$version"
    fi
}

# Download file
download() {
    local url="$1"
    local output="$2"

    info "Downloading $url"

    if command -v curl &> /dev/null; then
        curl -fSL --progress-bar "$url" -o "$output"
    else
        wget --show-progress -q "$url" -O "$output"
    fi
}

# Get download URL for a version and platform
get_download_url() {
    local version="$1"
    local platform="$2"

    # Convert platform format (darwin-aarch64 -> darwin-arm64 for compatibility)
    local download_platform="$platform"
    if [[ "$platform" == *-aarch64 ]]; then
        download_platform="${platform/aarch64/arm64}"
    fi

    echo "https://github.com/${GITHUB_REPO}/releases/download/v${version}/smolvm-${version}-${download_platform}.tar.gz"
}

# Get checksum URL for a version and platform
get_checksum_url() {
    local version="$1"
    echo "https://github.com/${GITHUB_REPO}/releases/download/v${version}/checksums.txt"
}

# Verify file checksum
verify_checksum() {
    local file="$1"
    local checksums_file="$2"
    local filename
    filename=$(basename "$file")

    # Extract expected checksum for this file
    local expected
    expected=$(grep "$filename" "$checksums_file" 2>/dev/null | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        warn "Checksum not found for $filename, skipping verification"
        return 0
    fi

    # Calculate actual checksum
    local actual
    if command -v sha256sum &> /dev/null; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum &> /dev/null; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        warn "sha256sum/shasum not found, skipping checksum verification"
        return 0
    fi

    if [[ "$expected" != "$actual" ]]; then
        error "Checksum verification failed!"
        error "  Expected: $expected"
        error "  Actual:   $actual"
        return 1
    fi

    info "Checksum verified"
    return 0
}

# Install smolvm
install_smolvm() {
    local version="$1"
    local platform="$2"
    local prefix="$3"

    local url
    url=$(get_download_url "$version" "$platform")
    local checksums_url
    checksums_url=$(get_checksum_url "$version")
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local archive_name
    archive_name=$(basename "$url")
    local archive="${tmp_dir}/${archive_name}"
    local checksums="${tmp_dir}/checksums.txt"

    # Download archive
    download "$url" "$archive" || {
        error "Failed to download smolvm from $url"
        error "Please check if version $version exists for platform $platform"
        rm -rf "$tmp_dir"
        exit 1
    }

    # Download and verify checksums (optional - don't fail if checksums unavailable)
    if download "$checksums_url" "$checksums" 2>/dev/null; then
        verify_checksum "$archive" "$checksums" || {
            error "Archive failed checksum verification - aborting for security"
            rm -rf "$tmp_dir"
            exit 1
        }
    else
        warn "Checksums not available for this release, skipping verification"
    fi

    # Extract
    info "Extracting archive..."
    tar -xzf "$archive" -C "$tmp_dir" || {
        error "Failed to extract archive"
        rm -rf "$tmp_dir"
        exit 1
    }

    # Find extracted directory
    local extracted_dir
    extracted_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "smolvm-*" | head -1)

    if [[ -z "$extracted_dir" ]]; then
        error "Could not find extracted smolvm directory"
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Create installation directory
    info "Installing to $prefix..."
    mkdir -p "$prefix"

    # Remove old installation if exists
    if [[ -d "$prefix/lib" ]]; then
        rm -rf "$prefix/lib"
    fi
    if [[ -f "$prefix/smolvm" ]]; then
        rm -f "$prefix/smolvm"
    fi
    if [[ -f "$prefix/smolvm-bin" ]]; then
        rm -f "$prefix/smolvm-bin"
    fi
    if [[ -f "$prefix/smolvm-stub" ]]; then
        rm -f "$prefix/smolvm-stub"
    fi
    if [[ -f "$prefix/storage-template.ext4" ]]; then
        rm -f "$prefix/storage-template.ext4"
    fi
    if [[ -f "$prefix/overlay-template.ext4" ]]; then
        rm -f "$prefix/overlay-template.ext4"
    fi

    # Copy files
    cp -r "$extracted_dir/lib" "$prefix/"
    cp "$extracted_dir/smolvm" "$prefix/"
    cp "$extracted_dir/smolvm-bin" "$prefix/"
    chmod +x "$prefix/smolvm"
    chmod +x "$prefix/smolvm-bin"

    # Copy disk templates if present
    if [[ -f "$extracted_dir/storage-template.ext4" ]]; then
        cp "$extracted_dir/storage-template.ext4" "$prefix/"
    fi
    if [[ -f "$extracted_dir/overlay-template.ext4" ]]; then
        cp "$extracted_dir/overlay-template.ext4" "$prefix/"
    fi

    # Install agent-rootfs to data directory
    local data_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        data_dir="$HOME/Library/Application Support/smolvm"
    else
        data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi

    if [[ -d "$extracted_dir/agent-rootfs" ]]; then
        info "Installing agent-rootfs to $data_dir..."
        mkdir -p "$data_dir"
        rm -rf "$data_dir/agent-rootfs"
        # Use cp -a to preserve symlinks (busybox creates many symlinks)
        cp -a "$extracted_dir/agent-rootfs" "$data_dir/"
    else
        warn "agent-rootfs not found in distribution - some features may not work"
    fi

    # Copy init.krun if present (Linux only, required by libkrunfw kernel)
    if [[ -f "$extracted_dir/init.krun" ]]; then
        info "Installing init.krun to $data_dir..."
        cp "$extracted_dir/init.krun" "$data_dir/init.krun"
        chmod +x "$data_dir/init.krun"
    fi

    # Store version info
    echo "$version" > "$prefix/.version"

    # Cleanup
    rm -rf "$tmp_dir"

    # Create symlink in bin directory
    mkdir -p "$BIN_DIR"
    ln -sf "$prefix/smolvm" "$BIN_DIR/smolvm"

    success "smolvm $version installed to $prefix"
}

# Modify shell profile to add to PATH
modify_path() {
    local bin_dir="$1"
    local profile=""
    local export_line="export PATH=\"$bin_dir:\$PATH\""

    # Determine shell profile
    case "$SHELL" in
        */zsh)
            profile="$HOME/.zshrc"
            ;;
        */bash)
            if [[ -f "$HOME/.bash_profile" ]]; then
                profile="$HOME/.bash_profile"
            else
                profile="$HOME/.bashrc"
            fi
            ;;
        */fish)
            profile="$HOME/.config/fish/config.fish"
            export_line="set -gx PATH $bin_dir \$PATH"
            ;;
        *)
            profile="$HOME/.profile"
            ;;
    esac

    # Check if already in PATH
    if echo "$PATH" | grep -q "$bin_dir"; then
        info "$bin_dir is already in PATH"
        return
    fi

    # Check if already in profile
    if [[ -f "$profile" ]] && grep -q "$bin_dir" "$profile" 2>/dev/null; then
        info "PATH already configured in $profile"
        return
    fi

    # Add to profile
    info "Adding $bin_dir to PATH in $profile"
    echo "" >> "$profile"
    echo "# smolvm" >> "$profile"
    echo "$export_line" >> "$profile"

    warn "PATH updated. Run 'source $profile' or open a new terminal."
}

# Uninstall smolvm
uninstall_smolvm() {
    local prefix="$1"

    info "Uninstalling smolvm..."

    # Remove installation directory
    if [[ -d "$prefix" ]]; then
        rm -rf "$prefix"
        success "Removed $prefix"
    else
        warn "Installation directory not found: $prefix"
    fi

    # Remove symlink
    if [[ -L "$BIN_DIR/smolvm" ]]; then
        rm -f "$BIN_DIR/smolvm"
        success "Removed symlink $BIN_DIR/smolvm"
    fi

    # Remove data directory (agent-rootfs, storage)
    local data_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        data_dir="$HOME/Library/Application Support/smolvm"
    else
        data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi
    if [[ -d "$data_dir" ]]; then
        rm -rf "$data_dir"
        success "Removed data directory $data_dir"
    fi

    # Remove cache directories
    local cache_dir cache_pack_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        cache_dir="$HOME/Library/Caches/smolvm"
        cache_pack_dir="$HOME/Library/Caches/smolvm-pack"
    else
        cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm"
        cache_pack_dir="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm-pack"
    fi
    if [[ -d "$cache_dir" ]]; then
        rm -rf "$cache_dir"
        success "Removed cache directory $cache_dir"
    fi
    if [[ -d "$cache_pack_dir" ]]; then
        rm -rf "$cache_pack_dir"
        success "Removed pack cache directory $cache_pack_dir"
    fi

    # Note about PATH
    warn "You may want to remove the PATH entry from your shell profile."

    success "smolvm has been uninstalled"
}

# Print usage
usage() {
    cat << EOF
smolvm installer

Usage:
    install.sh [OPTIONS]

Options:
    --version VERSION   Install specific version (default: latest)
    --prefix DIR        Install to DIR (default: ~/.smolvm)
    --no-modify-path    Don't modify shell profile
    --uninstall         Remove smolvm installation
    --help              Show this help message

Examples:
    # Install latest version
    curl -sSL https://smolmachines.com/install.sh | bash

    # Install specific version
    curl -sSL https://smolmachines.com/install.sh | bash -s -- --version 0.1.1

    # Install to custom directory
    curl -sSL https://smolmachines.com/install.sh | bash -s -- --prefix /opt/smolvm

    # Uninstall
    curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --no-modify-path)
                MODIFY_PATH=false
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main
main() {
    parse_args "$@"

    echo ""
    echo -e "${BOLD}smolvm installer${NC}"
    echo ""

    # Handle uninstall
    if [[ "$UNINSTALL" == true ]]; then
        uninstall_smolvm "$INSTALL_PREFIX"
        exit 0
    fi

    # Detect platform
    local platform
    platform=$(detect_platform)
    info "Detected platform: $platform"

    # Check requirements
    check_requirements "$platform"

    # Get version
    if [[ -z "$VERSION" ]]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi
    info "Installing version: $VERSION"

    # Check for existing installation
    if [[ -f "$INSTALL_PREFIX/.version" ]]; then
        local current_version
        current_version=$(cat "$INSTALL_PREFIX/.version")
        if [[ "$current_version" == "$VERSION" ]]; then
            info "Reinstalling smolvm $VERSION..."
        else
            info "Upgrading from $current_version to $VERSION"
        fi
    fi

    # Install
    install_smolvm "$VERSION" "$platform" "$INSTALL_PREFIX"

    # Modify PATH
    if [[ "$MODIFY_PATH" == true ]]; then
        modify_path "$BIN_DIR"
    fi

    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "To get started, run:"
    echo ""
    if ! echo "$PATH" | grep -q "$BIN_DIR"; then
        echo "    export PATH=\"$BIN_DIR:\$PATH\""
    fi
    echo "    smolvm --help"
    echo ""
}

main "$@"
