#!/bin/bash
#
# Network and Egress Tests
#
# Part of the smolvm test suite. Run with: ./tests/test_network.sh
#

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

trap cleanup_machine EXIT

echo ""
echo "=========================================="
echo "  Network and Egress Tests"
echo "=========================================="
echo ""

test_machine_network_disabled_by_default() {
    local vm_name="net-disabled-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM without --net (network disabled by default)
    $SMOLVM machine create "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS resolution should fail when network is disabled
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1 || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should fail (non-zero exit code) because network is disabled
    [[ $exit_code -ne 0 ]]
}

test_machine_network_dns_resolution() {
    local vm_name="net-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test DNS resolution
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain resolved address info
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_network_multiple_dns_lookups() {
    local vm_name="net-multi-dns-test-$$"

    # Clean up any existing
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM with --net (network enabled)
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Test multiple DNS lookups
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c "nslookup google.com && nslookup github.com" 2>&1) || exit_code=$?

    # Clean up
    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    # Should succeed and contain addresses for both
    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_egress_allow_cidr_permitted() {
    local vm_name="egress-allow-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only Cloudflare DNS
    $SMOLVM machine create "$vm_name" --allow-cidr 1.1.1.1/32 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS lookup to allowed IP should succeed
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1) || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_egress_allow_cidr_blocked() {
    local vm_name="egress-block-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only private range + auto-included DNS (1.1.1.1).
    # Test with 8.8.8.8 which is NOT in the allowlist.
    $SMOLVM machine create "$vm_name" --allow-cidr 10.0.0.0/8 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_outbound_localhost_only() {
    local vm_name="egress-localhost-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" --outbound-localhost-only 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_invalid_cidr_rejected() {
    local vm_name="egress-invalid-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-cidr "not-a-cidr" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    [[ $exit_code -ne 0 ]] && [[ "$output" == *"invalid"* ]]
}

test_machine_egress_allow_host_permitted() {
    local vm_name="egress-host-allow-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one (resolves to 1.1.1.1)
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # DNS lookup to allowed host's IP should succeed
    local output exit_code=0
    output=$($SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 1.1.1.1 2>&1) || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]] && [[ "$output" == *"Address"* ]]
}

test_machine_egress_allow_host_blocked() {
    local vm_name="egress-host-block-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one — 8.8.8.8 should be blocked
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -ne 0 ]]
}

test_machine_egress_allow_host_invalid_rejected() {
    local vm_name="egress-host-invalid-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-host "this-does-not-exist.invalid" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Should fail with a resolution error (hard error, not warning)
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"failed to resolve"* ]]
}

test_machine_egress_allow_host_port_rejected() {
    local vm_name="egress-host-port-test-$$"
    local output exit_code=0
    output=$($SMOLVM machine create "$vm_name" --allow-host "example.com:443" 2>&1) || exit_code=$?

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Should fail — port suffixes are not supported
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"port suffixes are not supported"* ]]
}

test_machine_dns_filter_blocks_resolution() {
    local vm_name="dns-filter-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create VM allowing only one.one.one.one
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Resolving an allowed domain should work
    local exit_code_allowed=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 || exit_code_allowed=$?

    # Resolving a non-allowed domain should fail (DNS proxy returns NXDOMAIN,
    # or if agent doesn't have DNS proxy, TSI still blocks the IP)
    local exit_code_blocked=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup attacker-test.example 2>&1 || exit_code_blocked=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_allowed -eq 0 ]] && [[ $exit_code_blocked -ne 0 ]]
}

test_machine_allow_host_persists_across_restart() {
    local vm_name="dns-persist-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    # Create with --allow-host, start, stop, start again
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify egress works
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 || exit_code=$?
    [[ $exit_code -ne 0 ]] && { $SMOLVM machine stop --name "$vm_name" 2>/dev/null; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Stop and restart — config should persist from VmRecord
    $SMOLVM machine stop --name "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Should still be blocked (8.8.8.8 is not in allowlist)
    local exit_code_after=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code_after=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_after -ne 0 ]]
}

test_smolfile_allow_hosts_stale_cidr_regression() {
    local vm_name="allow-hosts-stale-test-$$"

    # sqlite3 is required to inject stale CIDRs into the DB
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "SKIP: sqlite3 not available"
        return 0
    fi

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)

    # Smolfile with allow_hosts — no explicit allow_cidrs.
    # one.one.one.one resolves to 1.1.1.1 / 1.0.0.1 (Cloudflare DNS).
    cat > "$tmpdir/Smolfile.toml" <<'EOF'
[network]
allow_hosts = ["one.one.one.one"]
EOF

    (
        cd "$tmpdir"
        $SMOLVM machine create "$vm_name" -s Smolfile.toml 2>&1
    ) || { rm -rf "$tmpdir"; return 1; }

    # Determine DB path (matches SmolvmDb::default_path logic)
    local db_path
    if [[ "$(uname)" == "Darwin" ]]; then
        db_path="$HOME/Library/Application Support/smolvm/server/smolvm.db"
    else
        db_path="$HOME/.local/share/smolvm/server/smolvm.db"
    fi

    # Inject stale CIDRs — 192.0.2.0/24 is RFC 5737 TEST-NET, never routed.
    # This simulates the old bug: CIDRs resolved at create time that are now
    # stale due to CDN IP rotation.
    # The data column is stored as BLOB. json_set returns TEXT, so we must
    # CAST both ways: TEXT for JSON manipulation, then back to BLOB for storage.
    sqlite3 "$db_path" \
        "UPDATE vms SET data = CAST(json_set(CAST(data AS TEXT), '$.allowed_cidrs', json('[\"192.0.2.0/24\"]')) AS BLOB) WHERE name = '$vm_name'" \
        2>&1 || { echo "sqlite3 update failed"; rm -rf "$tmpdir"; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Start — fix must re-resolve allow_hosts and override the stale CIDRs
    $SMOLVM machine start --name "$vm_name" 2>&1 \
        || { rm -rf "$tmpdir"; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Probe egress using 1.0.0.1 as the resolver — also a valid IP for
    # one.one.one.one, but NOT auto-added by ensure_dns_in_cidrs (which only
    # injects 1.1.1.1). With stale CIDRs and no re-resolution, 1.0.0.1 is
    # blocked; with the fix, fresh resolution adds it and the query succeeds.
    local exit_code=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.0.0.1 2>&1 || exit_code=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    # Fallback: if machine delete failed due to a corrupt DB row (e.g. from a
    # botched sqlite3 update), remove the row directly so it doesn't poison
    # subsequent test runs that scan all rows.
    sqlite3 "$db_path" "DELETE FROM vms WHERE name = '$vm_name'" 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code -eq 0 ]]
}

test_smolfile_allow_hosts_egress_basic() {
    local vm_name="allow-hosts-sf-basic-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)

    cat > "$tmpdir/Smolfile.toml" <<'EOF'
[network]
allow_hosts = ["one.one.one.one"]
EOF

    (
        cd "$tmpdir"
        $SMOLVM machine create "$vm_name" -s Smolfile.toml 2>&1
    ) || { rm -rf "$tmpdir"; return 1; }

    $SMOLVM machine start --name "$vm_name" 2>&1 \
        || { rm -rf "$tmpdir"; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Probe 1: 1.1.1.1 — always in the egress policy via ensure_dns_in_cidrs.
    # Verifies the policy doesn't block what it should allow, but does NOT
    # prove that hostname resolution ran (1.1.1.1 is auto-added regardless).
    local exit_code_allowed=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 || exit_code_allowed=$?

    # Probe 2: 1.0.0.1 — a real IP of one.one.one.one, but NOT auto-added by
    # ensure_dns_in_cidrs. This probe passes only if allow_hosts DNS resolution
    # actually ran and added 1.0.0.1 to the CIDR list. It is the definitive
    # proof that the hostname-to-CIDR path works end-to-end.
    local exit_code_resolution=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.0.0.1 2>&1 || exit_code_resolution=$?

    # Egress to a non-allowed resolver (8.8.8.8) must be blocked
    local exit_code_blocked=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup cloudflare.com 8.8.8.8 2>&1 || exit_code_blocked=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_allowed -eq 0 ]] && [[ $exit_code_resolution -eq 0 ]] && [[ $exit_code_blocked -ne 0 ]]
}

test_egress_refresh_thread_stability() {
    skip_if_slow && return 0
    local vm_name="egress-refresh-smoke-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    local tmpdir
    tmpdir=$(mktemp -d)

    cat > "$tmpdir/Smolfile.toml" <<'EOF'
[network]
allow_hosts = ["one.one.one.one"]
EOF

    (
        cd "$tmpdir"
        $SMOLVM machine create "$vm_name" -s Smolfile.toml 2>&1
    ) || { rm -rf "$tmpdir"; return 1; }

    # Start with a 10-second refresh interval so the thread fires twice during
    # the test window without making the test slow.
    SMOLVM_EGRESS_REFRESH_SECS=10 $SMOLVM machine start --name "$vm_name" 2>&1 \
        || { rm -rf "$tmpdir"; $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Verify egress works immediately after start.
    local exit_code_before=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 \
        || exit_code_before=$?

    # Wait for two refresh cycles to fire (2 × 10 s + 5 s buffer).
    echo "  Waiting 25s for two egress refresh cycles..."
    sleep 25

    # Egress must still work after refreshes — the thread must not have
    # wiped or corrupted the existing CIDR list.
    local exit_code_after=0
    $SMOLVM machine exec --name "$vm_name" -- nslookup one.one.one.one 1.1.1.1 2>&1 \
        || exit_code_after=$?

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_before -eq 0 ]] && [[ $exit_code_after -eq 0 ]]
}

test_grpcio_channel_ready() {
    skip_if_slow && return 0
    local output
    output=$($SMOLVM machine run --net --mem 4096 --image python:3.12-alpine -- sh -c '
        pip install grpcio > /dev/null 2>&1
        python3 -c "
import os
os.environ[\"GRPC_DNS_RESOLVER\"] = \"native\"
import grpc
ch = grpc.secure_channel(\"google.com:443\", grpc.ssl_channel_credentials())
grpc.channel_ready_future(ch).result(timeout=10)
print(\"grpcio_channel_ready: PASS\")
"
    ' 2>&1)
    echo "$output"
    [[ "$output" == *"grpcio_channel_ready: PASS"* ]]
}


run_test "Network: disabled by default" test_machine_network_disabled_by_default || true
run_test "Network: DNS resolution" test_machine_network_dns_resolution || true
run_test "Network: multiple DNS lookups" test_machine_network_multiple_dns_lookups || true
run_test "Egress: allow-cidr permits matching traffic" test_machine_egress_allow_cidr_permitted || true
run_test "Egress: allow-cidr blocks non-matching traffic" test_machine_egress_allow_cidr_blocked || true
run_test "Egress: --outbound-localhost-only blocks external" test_machine_egress_outbound_localhost_only || true
run_test "Egress: invalid CIDR rejected at create" test_machine_egress_invalid_cidr_rejected || true
run_test "Egress: allow-host permits matching traffic" test_machine_egress_allow_host_permitted || true
run_test "Egress: allow-host blocks non-matching traffic" test_machine_egress_allow_host_blocked || true
run_test "Egress: invalid hostname rejected at create" test_machine_egress_allow_host_invalid_rejected || true
run_test "Egress: host:port syntax rejected" test_machine_egress_allow_host_port_rejected || true
run_test "DNS filter: blocks resolution of non-allowed domains" test_machine_dns_filter_blocks_resolution || true
run_test "DNS filter: allow-host persists across restart" test_machine_allow_host_persists_across_restart || true
run_test "Smolfile: allow_hosts basic egress permitted/blocked" test_smolfile_allow_hosts_egress_basic || true
run_test "Smolfile: allow_hosts re-resolves stale CIDRs on start (issue #124)" test_smolfile_allow_hosts_stale_cidr_regression || true
run_test "Egress refresh thread: stability across refresh cycles" test_egress_refresh_thread_stability || true
run_test "grpcio: secure channel ready (ilyaterin grpc test)" test_grpcio_channel_ready || true

print_summary "Network Tests"
