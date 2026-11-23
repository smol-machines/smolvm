#!/usr/bin/env bash
#
# Agent Rootfs Permission Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_agent_rootfs_modes.sh
#
# Covers relativize_absolute_symlinks() and normalize_owner_only_modes() in
# scripts/build-agent-rootfs.sh. The first makes every absolute link relative,
# so no link points outside the install directory on the host. The second
# widens the stock Alpine paths that only their owner can read. A mode-preserving
# install lands those root-owned under a system prefix, where `pack create` — it
# tars the whole rootfs and cannot skip anything — fails for the user running
# smolvm. The rootfs build only runs in the release workflow, so without this the
# behavior is unexercised until a tarball is already cut.
#
# Pure fixture test: no smolvm binary, no VM, no network. It therefore carries
# its own runner rather than sourcing common.sh, whose helpers assume an
# initialized smolvm and a machine lifecycle to clean up.
#

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; FAILED_TESTS=()

run_test() {
    local test_name="$1" test_func="$2" output
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${YELLOW}[TEST]${NC} $test_name"
    if output=$($test_func 2>&1); then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}[PASS]${NC} $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        echo -e "${RED}[FAIL]${NC} $test_name"
        [[ -n "$output" ]] && echo "$output" | sed 's/^/    /'
    fi
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "  $1 Summary"
    echo "=========================================="
    echo ""
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo ""
        echo -e "${RED}Failed tests:${NC}"
        printf "  ${RED}✗${NC} %s\n" "${FAILED_TESTS[@]}"
        return 1
    fi
    return 0
}

BUILD_SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/scripts/build-agent-rootfs.sh"

# Source just the functions under test; the build script's top level would go off
# and download Alpine.
eval "$(awk '/^normalize_owner_only_modes\(\) \{/,/^\}/' "$BUILD_SCRIPT")"
eval "$(awk '/^relativize_absolute_symlinks\(\) \{/,/^\}/' "$BUILD_SCRIPT")"

echo ""
echo "=========================================="
echo "  Agent Rootfs Permission Tests"
echo "=========================================="
echo ""

# Mode of a path, portable across GNU and BSD stat.
mode_of() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1"
}

# The owner-only layout the stock Alpine minirootfs ships.
make_rootfs_fixture() {
    local root="$1"
    mkdir -p "$root/etc/crontabs" "$root/lib/apk/db" "$root/root" "$root/bin"
    : > "$root/etc/shadow"
    : > "$root/etc/crontabs/root"
    : > "$root/lib/apk/db/lock"
    : > "$root/bin/busybox"
    chmod 0640 "$root/etc/shadow"
    chmod 0600 "$root/etc/crontabs/root"
    chmod 0600 "$root/lib/apk/db/lock"
    chmod 0700 "$root/root"
    chmod 0755 "$root/bin/busybox"
    ln -sf /usr/local/bin/smolvm-agent "$root/bin/init"
}

test_stock_alpine_paths_are_widened() {
    local root
    root=$(mktemp -d)
    make_rootfs_fixture "$root"

    normalize_owner_only_modes "$root" >/dev/null || {
        echo "normalize_owner_only_modes failed on a stock layout"
        rm -rf "$root"
        return 1
    }

    local rc=0
    local path
    for path in etc/shadow etc/crontabs/root lib/apk/db/lock; do
        if [[ "$(mode_of "$root/$path")" != "644" ]]; then
            echo "$path is $(mode_of "$root/$path"), want 644"
            rc=1
        fi
    done
    for path in . root; do
        if [[ "$(mode_of "$root/$path")" != "755" ]]; then
            echo "$path is $(mode_of "$root/$path"), want 755"
            rc=1
        fi
    done

    rm -rf "$root"
    return $rc
}

# The rootfs is shared into every VM and this script also runs against
# user-supplied trees, so an unrecognized owner-only path must stop the build
# rather than be widened silently.
test_unexpected_owner_only_path_fails_loudly() {
    local root
    root=$(mktemp -d)
    make_rootfs_fixture "$root"
    mkdir -p "$root/etc/smolvm"
    : > "$root/etc/smolvm/registry-token"
    chmod 0600 "$root/etc/smolvm/registry-token"

    local output rc=0
    if output=$(normalize_owner_only_modes "$root" 2>&1); then
        echo "expected a non-zero exit for an unrecognized owner-only file"
        rc=1
    fi
    if ! grep -q "registry-token" <<<"$output"; then
        echo "error output does not name the offending path:"
        echo "$output"
        rc=1
    fi
    if [[ "$(mode_of "$root/etc/smolvm/registry-token")" != "600" ]]; then
        echo "the unrecognized file was widened to $(mode_of "$root/etc/smolvm/registry-token")"
        rc=1
    fi

    rm -rf "$root"
    return $rc
}

test_unexpected_owner_only_directory_fails_loudly() {
    local root
    root=$(mktemp -d)
    make_rootfs_fixture "$root"
    mkdir -p "$root/opt/private"
    chmod 0700 "$root/opt/private"

    # Called in a subshell: the function exits rather than returning, so that a
    # failure stops the build script it normally runs from.
    local rc=0
    if (normalize_owner_only_modes "$root" >/dev/null 2>&1); then
        echo "expected a non-zero exit for an unrecognized owner-only directory"
        rc=1
    fi

    rm -rf "$root"
    return $rc
}

# --no-build-agent and cross-arch builds can legitimately omit some of these.
test_missing_optional_paths_are_tolerated() {
    local root
    root=$(mktemp -d)
    mkdir -p "$root/bin"
    : > "$root/bin/busybox"
    chmod 0755 "$root/bin/busybox"

    local rc=0
    normalize_owner_only_modes "$root" >/dev/null 2>&1 || {
        echo "a rootfs without the Alpine owner-only paths should pass"
        rc=1
    }

    rm -rf "$root"
    return $rc
}

# A symlink's own mode is not meaningful and cannot be chmod'd portably; the
# check must look through to file/directory types only.
test_symlinks_do_not_trip_the_check() {
    local root
    root=$(mktemp -d)
    make_rootfs_fixture "$root"
    ln -sf /nonexistent-target "$root/bin/dangling"

    local rc=0
    normalize_owner_only_modes "$root" >/dev/null 2>&1 || {
        echo "a dangling symlink should not fail the check"
        rc=1
    }

    rm -rf "$root"
    return $rc
}

test_shared_temporary_directories_are_sticky_and_writable() {
    local root rc=0 path
    root=$(mktemp -d)
    make_rootfs_fixture "$root"
    mkdir -p "$root/tmp" "$root/var/tmp"
    chmod 0755 "$root/tmp" "$root/var/tmp"
    normalize_owner_only_modes "$root" >/dev/null || rc=1
    for path in tmp var/tmp; do
        if [[ "$(mode_of "$root/$path")" != "1777" ]]; then
            echo "$path must be writable with the sticky bit"
            rc=1
        fi
    done
    rm -rf "$root"
    return "$rc"
}

# The guest mounts the rootfs at /, so each rewritten link must name the same
# guest path, and none may point outside the tree on the host.
test_absolute_symlinks_become_relative_to_the_same_guest_path() {
    local root rc=0 link want got
    root=$(mktemp -d)
    mkdir -p "$root/bin" "$root/sbin" "$root/etc/ssl1.1"
    ln -s /bin/busybox "$root/bin/sed"
    ln -s /usr/local/bin/smolvm-agent "$root/sbin/init"
    ln -s /etc/ssl/cert.pem "$root/etc/ssl1.1/cert.pem"
    ln -s /etc/ssl/certs "$root/etc/ssl1.1/certs"
    ln -s /proc/mounts "$root/etc/mtab"
    ln -s /usr/lib "$root/lib64"
    ln -s / "$root/rootfs"
    ln -s busybox "$root/bin/sh"

    relativize_absolute_symlinks "$root" || rc=1
    while read -r link want; do
        got="$(readlink "$root/$link")"
        if [[ "$got" != "$want" ]]; then
            echo "$link -> $got, want $want"
            rc=1
        fi
    done <<'EOF'
bin/sed busybox
sbin/init ../usr/local/bin/smolvm-agent
etc/ssl1.1/cert.pem ../ssl/cert.pem
etc/ssl1.1/certs ../ssl/certs
etc/mtab ../proc/mounts
lib64 usr/lib
rootfs .
bin/sh busybox
EOF

    rm -rf "$root"
    return $rc
}

run_test "Temporary directories keep sticky write access" test_shared_temporary_directories_are_sticky_and_writable
run_test "Stock Alpine owner-only paths are widened" test_stock_alpine_paths_are_widened
run_test "Unexpected owner-only file fails loudly" test_unexpected_owner_only_path_fails_loudly
run_test "Unexpected owner-only directory fails loudly" test_unexpected_owner_only_directory_fails_loudly
run_test "Missing optional paths are tolerated" test_missing_optional_paths_are_tolerated
run_test "Symlinks do not trip the check" test_symlinks_do_not_trip_the_check
run_test "Absolute symlinks become relative to the same guest path" test_absolute_symlinks_become_relative_to_the_same_guest_path

print_summary "Agent Rootfs Permission Tests"
