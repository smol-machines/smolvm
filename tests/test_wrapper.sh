#!/bin/bash
#
# Wrapper tests for release archive behavior.
#
# These tests use a fake release layout so they do not require a built smolvm
# binary, libkrun, KVM, or an agent rootfs with real contents.

source "$(dirname "$0")/common.sh"

echo ""
echo "=========================================="
echo "  smolvm Wrapper Tests"
echo "=========================================="
echo ""

make_release_fixture() {
    local release_dir="$1"

    mkdir -p "$release_dir/lib"
    cp "$PROJECT_ROOT/scripts/smolvm-wrapper.sh" "$release_dir/smolvm"
    chmod +x "$release_dir/smolvm"

    cat > "$release_dir/smolvm-bin" <<'EOF'
#!/bin/bash
printf 'SMOLVM_AGENT_ROOTFS=%s\n' "${SMOLVM_AGENT_ROOTFS-}"
EOF
    chmod +x "$release_dir/smolvm-bin"
}

agent_rootfs_from_output() {
    printf '%s\n' "$1" | sed -n 's/^SMOLVM_AGENT_ROOTFS=//p'
}

test_bundled_rootfs_sets_env_when_unset() {
    local tmp release_dir output actual expected
    tmp=$(mktemp -d)
    release_dir="$tmp/release"
    make_release_fixture "$release_dir"
    mkdir -p "$release_dir/agent-rootfs"

    output=$(env -u SMOLVM_AGENT_ROOTFS "$release_dir/smolvm")
    actual=$(agent_rootfs_from_output "$output")
    expected="$release_dir/agent-rootfs"

    rm -rf "$tmp"
    [[ "$actual" == "$expected" ]]
}

test_existing_agent_rootfs_env_wins() {
    local tmp release_dir output actual expected
    tmp=$(mktemp -d)
    release_dir="$tmp/release"
    make_release_fixture "$release_dir"
    mkdir -p "$release_dir/agent-rootfs"

    expected="/custom/rootfs"
    output=$(SMOLVM_AGENT_ROOTFS="$expected" "$release_dir/smolvm")
    actual=$(agent_rootfs_from_output "$output")

    rm -rf "$tmp"
    [[ "$actual" == "$expected" ]]
}

test_missing_bundled_rootfs_leaves_env_unset() {
    local tmp release_dir output actual
    tmp=$(mktemp -d)
    release_dir="$tmp/release"
    make_release_fixture "$release_dir"

    output=$(env -u SMOLVM_AGENT_ROOTFS "$release_dir/smolvm")
    actual=$(agent_rootfs_from_output "$output")

    rm -rf "$tmp"
    [[ -z "$actual" ]]
}

test_symlinked_wrapper_uses_real_release_dir() {
    local tmp release_dir bin_dir output actual expected
    tmp=$(mktemp -d)
    release_dir="$tmp/release"
    bin_dir="$tmp/bin"
    make_release_fixture "$release_dir"
    mkdir -p "$release_dir/agent-rootfs" "$bin_dir"
    ln -s "$release_dir/smolvm" "$bin_dir/smolvm"

    output=$(env -u SMOLVM_AGENT_ROOTFS "$bin_dir/smolvm")
    actual=$(agent_rootfs_from_output "$output")
    expected="$release_dir/agent-rootfs"

    rm -rf "$tmp"
    [[ "$actual" == "$expected" ]]
}

run_test "Bundled rootfs sets SMOLVM_AGENT_ROOTFS when unset" test_bundled_rootfs_sets_env_when_unset || true
run_test "Existing SMOLVM_AGENT_ROOTFS wins" test_existing_agent_rootfs_env_wins || true
run_test "Missing bundled rootfs leaves env unset" test_missing_bundled_rootfs_leaves_env_unset || true
run_test "Symlinked wrapper uses real release dir" test_symlinked_wrapper_uses_real_release_dir || true

print_summary "Wrapper Tests"
