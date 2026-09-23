#!/usr/bin/env bash
#
# Tests for the flake's release-hash refresh (scripts/update-nix-hashes.sh).
#
# These use a fake nix file and a fake checksums file, so they need no network,
# no release, and no nix.
#
# The incident: cut-release.sh used to bump `version` in nix/smolvm.nix while
# leaving the three hashes at the previous release's digests. Six releases
# shipped that way, and `nix build` failed the fixed-output check on every one
# of them because the flake claimed a version its hashes did not describe.

source "$(dirname "$0")/common.sh"

echo ""
echo "=========================================="
echo "  smolvm Nix Release Hash Tests"
echo "=========================================="
echo ""

UPDATE_HASHES="$PROJECT_ROOT/scripts/update-nix-hashes.sh"

# A nix file shaped like nix/smolvm.nix: three pinned assets, stale hashes.
make_nix_fixture() {
    cat > "$1" <<'EOF'
{lib}: let
  version = "9.9.9";

  releases = {
    x86_64-linux = {
      asset = "smolvm-${version}-linux-x86_64.tar.gz";
      root = "smolvm-${version}-linux-x86_64";
      hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    };
    aarch64-linux = {
      asset = "smolvm-${version}-linux-arm64.tar.gz";
      root = "smolvm-${version}-linux-arm64";
      hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    };
    aarch64-darwin = {
      asset = "smolvm-${version}-darwin-arm64.tar.gz";
      root = "smolvm-${version}-darwin-arm64";
      hash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
    };
  };
in
  releases
EOF
}

# Digests chosen so each SRI is distinct and independently checkable: the
# base64 of the raw bytes of each hex digest below.
make_checksums_fixture() {
    cat > "$1" <<'EOF'
1111111111111111111111111111111111111111111111111111111111111111  smolvm-9.9.9-darwin-arm64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  smolvm-9.9.9-linux-arm64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  smolvm-9.9.9-linux-x86_64.tar.gz
EOF
}

hash_for() {
    sed -n "/asset = \"smolvm-\${version}-$2\";/,/hash = /p" "$1" | sed -n 's/.*hash = "\(.*\)";.*/\1/p'
}

test_rewrites_every_pinned_hash() {
    local tmp nixf sums rc
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"; make_checksums_fixture "$sums"

    SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$UPDATE_HASHES" 9.9.9 >/dev/null 2>&1
    rc=$?

    # base64 of the raw bytes of 0x33.. / 0x22.. / 0x11.. respectively.
    local want_x86 want_arm want_darwin
    want_x86="sha256-MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
    want_arm="sha256-IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
    want_darwin="sha256-ERERERERERERERERERERERERERERERERERERERERERE="

    local got_x86 got_arm got_darwin
    got_x86=$(hash_for "$nixf" "linux-x86_64.tar.gz")
    got_arm=$(hash_for "$nixf" "linux-arm64.tar.gz")
    got_darwin=$(hash_for "$nixf" "darwin-arm64.tar.gz")
    rm -rf "$tmp"

    [[ $rc -eq 0 ]] || return 1
    [[ "$got_x86" == "$want_x86" ]] || { echo "x86_64: got $got_x86 want $want_x86"; return 1; }
    [[ "$got_arm" == "$want_arm" ]] || { echo "arm64: got $got_arm want $want_arm"; return 1; }
    [[ "$got_darwin" == "$want_darwin" ]] || { echo "darwin: got $got_darwin want $want_darwin"; return 1; }
}

test_leaves_the_version_alone() {
    local tmp nixf sums before after
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"; make_checksums_fixture "$sums"
    before=$(sed -n 's/.*version = "\(.*\)";.*/\1/p' "$nixf")

    SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$UPDATE_HASHES" 9.9.9 >/dev/null 2>&1

    after=$(sed -n 's/.*version = "\(.*\)";.*/\1/p' "$nixf")
    rm -rf "$tmp"
    [[ "$before" == "$after" ]]
}

test_missing_asset_fails_loudly() {
    local tmp nixf sums rc output
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"
    # A release that shipped no darwin tarball: the flake still pins it.
    cat > "$sums" <<'EOF'
2222222222222222222222222222222222222222222222222222222222222222  smolvm-9.9.9-linux-arm64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  smolvm-9.9.9-linux-x86_64.tar.gz
EOF

    output=$(SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$UPDATE_HASHES" 9.9.9 2>&1)
    rc=$?
    rm -rf "$tmp"

    [[ $rc -ne 0 ]] || { echo "expected a non-zero exit for a missing asset"; return 1; }
    printf '%s\n' "$output" | grep -q "has no line in the checksums"
}

test_rewrites_hashes_with_slash_and_plus() {
    # base64 uses `/` and `+`; a hash containing them used to end the
    # substitution early and leave that platform on its old hash.
    local tmp nixf sums rc got
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"
    make_checksums_fixture "$sums"
    sed -i.bak 's/^1111*  smolvm-9.9.9-darwin/fbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbeffff  smolvm-9.9.9-darwin/' "$sums"

    SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$UPDATE_HASHES" 9.9.9 >/dev/null 2>&1
    rc=$?
    got=$(hash_for "$nixf" "darwin-arm64.tar.gz")
    rm -rf "$tmp"

    [[ $rc -eq 0 ]] || { echo "update exited $rc"; return 1; }
    [[ "$got" == "sha256-++++++++++++++++++++++++++++++++++++++++//8=" ]] || { echo "darwin: got $got"; return 1; }
}

CHECK_HASHES="$PROJECT_ROOT/scripts/check-nix-hashes.sh"

test_check_passes_when_hashes_match() {
    local tmp nixf sums rc
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"; make_checksums_fixture "$sums"
    SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$UPDATE_HASHES" 9.9.9 >/dev/null 2>&1

    SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$CHECK_HASHES" >/dev/null 2>&1
    rc=$?
    rm -rf "$tmp"
    [[ $rc -eq 0 ]]
}

test_check_fails_on_stale_hashes() {
    # The shipped failure: the version names a release, the hashes belong to
    # an older one.
    local tmp nixf sums rc output
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"; sums="$tmp/checksums.sha256"
    make_nix_fixture "$nixf"; make_checksums_fixture "$sums"

    output=$(SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$sums" \
        "$CHECK_HASHES" 2>&1)
    rc=$?
    rm -rf "$tmp"
    [[ $rc -ne 0 ]] || { echo "expected a non-zero exit for stale hashes"; return 1; }
    printf '%s\n' "$output" | grep -q "do not match that release"
}

test_check_fails_without_a_release() {
    # A flake bumped before its release exists has no hashes to agree with.
    local tmp nixf rc output
    tmp=$(mktemp -d)
    nixf="$tmp/smolvm.nix"
    make_nix_fixture "$nixf"

    output=$(SMOLVM_NIX_FILE="$nixf" SMOLVM_CHECKSUMS_FILE="$tmp/missing" \
        "$CHECK_HASHES" 2>&1)
    rc=$?
    rm -rf "$tmp"
    [[ $rc -ne 0 ]] || { echo "expected a non-zero exit without release checksums"; return 1; }
    printf '%s\n' "$output" | grep -q "must pin a published release"
}

test_cut_release_does_not_bump_the_flake() {
    # The regression itself: cutting a release must not rewrite the flake's
    # version, because the hashes it would then contradict cannot be computed
    # until the tag has built the tarballs.
    ! grep -qE '^perl .*nix/smolvm\.nix' "$PROJECT_ROOT/scripts/cut-release.sh"
}

run_test "Rewrites every pinned hash" test_rewrites_every_pinned_hash || true
run_test "Leaves the version alone" test_leaves_the_version_alone || true
run_test "Missing asset fails loudly" test_missing_asset_fails_loudly || true
run_test "Rewrites hashes containing / and +" test_rewrites_hashes_with_slash_and_plus || true
run_test "Check passes when hashes match" test_check_passes_when_hashes_match || true
run_test "Check fails on stale hashes" test_check_fails_on_stale_hashes || true
run_test "Check fails without a release" test_check_fails_without_a_release || true
run_test "Cutting a release does not bump the flake" test_cut_release_does_not_bump_the_flake || true

print_summary "Nix Release Hash Tests"
