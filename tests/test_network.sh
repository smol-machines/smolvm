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

# Assert that egress from a VM to a destination outside its allowlist is
# blocked by the egress policy (EACCES) — not merely failing or timing out.
#
# The probe deliberately targets a real, reachable, NON-resolver web host on
# port 443 (resolved on the host, where egress is open). A public-DNS IP such
# as 8.8.8.8 is NOT a valid "blocked" example: the policy auto-adds the host's
# own DNS resolver to every allowlist (so VMs can resolve names), so on a host
# whose resolver is 8.8.8.8 that IP is silently permitted. A web IP is never
# auto-added, so it is a sound block target regardless of the host's DNS config.
#
# A policy block returns EACCES immediately; an unreachable host would hang
# until the timeout. We require BOTH a nonzero exit AND a fast failure, so a
# timeout (or any non-policy failure) can never masquerade as a real block.
assert_egress_blocked() {
    local vm_name="$1"

    local web_ip
    web_ip=$(getent ahostsv4 example.com | awk 'NR==1{print $1}')
    if [[ -z "$web_ip" ]]; then
        echo "FAIL: could not resolve a non-resolver block-probe target on host"
        return 1
    fi

    # Probe inside the guest; emit "<exit_code> <elapsed_ms>".
    local result
    result=$($SMOLVM machine exec --name "$vm_name" -- sh -c \
        "s=\$(date +%s%N); nc -w 4 -z $web_ip 443 >/dev/null 2>&1; r=\$?; e=\$(date +%s%N); echo \"\$r \$(((e-s)/1000000))\"" \
        2>/dev/null | tail -1)
    if [[ -z "$result" ]]; then
        echo "FAIL: egress probe to $web_ip:443 produced no result (exec failed?)"
        return 1
    fi

    local rc=${result%% *} ms=${result##* }
    if [[ "$rc" == "0" ]]; then
        echo "FAIL: egress to non-allowlisted $web_ip:443 was permitted (policy not enforced)"
        return 1
    fi
    if [[ -z "$ms" ]] || [[ "$ms" -ge 2000 ]]; then
        echo "FAIL: egress to $web_ip:443 failed by timeout (${ms}ms), not a policy block (EACCES)"
        return 1
    fi
    return 0
}

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

    # Create VM allowing only a private range. ensure_dns_in_cidrs also
    # auto-adds the host's DNS resolver so the VM can still resolve names.
    $SMOLVM machine create "$vm_name" --allow-cidr 10.0.0.0/8 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # A destination outside 10.0.0.0/8 (and not the auto-added resolver) blocked.
    local blocked_rc=0
    assert_egress_blocked "$vm_name" || blocked_rc=1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $blocked_rc -eq 0 ]]
}

test_machine_egress_outbound_localhost_only() {
    local vm_name="egress-localhost-test-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" --outbound-localhost-only 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Loopback-only egress: every external destination must be blocked.
    local blocked_rc=0
    assert_egress_blocked "$vm_name" || blocked_rc=1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $blocked_rc -eq 0 ]]
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

    # Create VM allowing only one.one.one.one. A host outside the allowlist
    # (and not the auto-added resolver) must be blocked.
    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    local blocked_rc=0
    assert_egress_blocked "$vm_name" || blocked_rc=1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $blocked_rc -eq 0 ]]
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

# Helper: send a raw TCP DNS query to 127.0.0.1:53 inside a running VM and
# return the RCODE (0–15) from the response, or 255 on error.
#
# Usage: dns_tcp_rcode <vm_name> <printf_query_string>
#
# The query string must be a printf-compatible byte sequence including the
# 2-byte big-endian length prefix followed by the raw DNS query bytes.
# Response RCODE lives in the lower nibble of byte 5 of the TCP stream
# (= 2-byte length prefix + 3 DNS header bytes: ID×2, flags-byte-0).
_dns_tcp_rcode() {
    local vm_name="$1"
    local query_printf="$2"

    local resp_file
    resp_file=$(mktemp)

    $SMOLVM machine exec --name "$vm_name" -- sh -c \
        "printf '$query_printf' | nc -w 2 127.0.0.1 53" \
        >"$resp_file" 2>/dev/null || true

    local rcode=255
    if [[ -s "$resp_file" ]]; then
        local hex
        hex=$(dd if="$resp_file" bs=1 skip=5 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ -n "$hex" ]] && rcode=$(( 16#${hex} & 0x0F ))
    fi

    rm -f "$resp_file"
    echo "$rcode"
}

test_dns_filter_tcp_allowed() {
    local vm_name="dns-tcp-allowed-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 \
        || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # Minimal A query for "one.one.one.one" (33 DNS bytes = 0x21).
    # TCP DNS framing: 2-byte BE length prefix + raw DNS query.
    # Header: ID=0x1234, RD=1, QDCOUNT=1. Name: \x03one×4 + \x00.
    # Host filter allows one.one.one.one → should return RCODE=0 (NOERROR).
    local rcode
    rcode=$(_dns_tcp_rcode "$vm_name" \
        '\x00\x21\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03one\x03one\x03one\x03one\x00\x00\x01\x00\x01')

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ "$rcode" -eq 0 ]] || { echo "FAIL: expected RCODE=0 (NOERROR), got RCODE=$rcode"; return 1; }
}

test_dns_filter_tcp_blocked() {
    local vm_name="dns-tcp-blocked-$$"

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true

    $SMOLVM machine create "$vm_name" --allow-host one.one.one.one 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 \
        || { $SMOLVM machine delete "$vm_name" -f 2>/dev/null; return 1; }

    # A query for "attacker.invalid" (34 DNS bytes = 0x22).
    # Name: \x08attacker (9 bytes) + \x07invalid (8 bytes) + \x00 (1 byte) = 18 bytes.
    # Not in the allowlist → host filter returns NXDOMAIN → RCODE=3.
    local rcode
    rcode=$(_dns_tcp_rcode "$vm_name" \
        '\x00\x22\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08attacker\x07invalid\x00\x00\x01\x00\x01')

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ "$rcode" -eq 3 ]] || { echo "FAIL: expected RCODE=3 (NXDOMAIN), got RCODE=$rcode"; return 1; }
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

    # Egress restriction must still hold after the restart.
    local blocked_rc=0
    assert_egress_blocked "$vm_name" || blocked_rc=1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    ensure_data_dir_deleted "$vm_name"

    [[ $blocked_rc -eq 0 ]]
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

    # Egress to a destination outside the allowlist must be blocked.
    local blocked_rc=0
    assert_egress_blocked "$vm_name" || blocked_rc=1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
    rm -rf "$tmpdir"
    ensure_data_dir_deleted "$vm_name"

    [[ $exit_code_allowed -eq 0 ]] && [[ $exit_code_resolution -eq 0 ]] && [[ $blocked_rc -eq 0 ]]
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

test_proxy_flag_routes_pull_through_proxy() {
    skip_if_slow && return 0

    if ! command -v python3 >/dev/null 2>&1; then
        echo "SKIP: python3 not available"
        return 0
    fi

    local proxy_log proxy_pid proxy_port pull_output pull_exit
    proxy_log=$(mktemp)
    proxy_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

    # Real CONNECT-tunneling proxy: logs each request line, opens a TCP
    # connection to the target host:port, returns 200, and bidirectionally
    # relays bytes. Exercises the full path the user hits in production —
    # a corporate forward proxy doing CONNECT for TLS image pulls.
    python3 - "$proxy_port" "$proxy_log" <<'PYEOF' &
import socketserver, socket, sys, threading
port = int(sys.argv[1]); log_path = sys.argv[2]

def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except OSError: pass

class P(socketserver.StreamRequestHandler):
    timeout = 60
    def handle(self):
        line = self.rfile.readline().decode('ascii', errors='replace').strip()
        with open(log_path, 'a') as f:
            f.write(line + "\n"); f.flush()
        while True:
            h = self.rfile.readline()
            if not h or h in (b"\r\n", b"\n"): break
        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return
        host, _, port_s = parts[1].rpartition(":")
        try:
            target = socket.create_connection((host, int(port_s)), timeout=30)
        except Exception:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); return
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        client = self.request
        t1 = threading.Thread(target=relay, args=(client, target), daemon=True)
        t2 = threading.Thread(target=relay, args=(target, client), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        target.close()

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

S(("127.0.0.1", port), P).serve_forever()
PYEOF
    proxy_pid=$!

    # Wait for the proxy to bind (up to ~1s).
    local ready=0 i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if (echo > /dev/tcp/127.0.0.1/$proxy_port) 2>/dev/null; then
            ready=1; break
        fi
        sleep 0.1
    done
    if [[ $ready -ne 1 ]]; then
        kill $proxy_pid 2>/dev/null
        rm -f "$proxy_log"
        echo "FAIL: proxy never bound to 127.0.0.1:$proxy_port"
        return 1
    fi

    # Run the pull. With a real tunneling proxy, this must succeed —
    # both the manifest fetch and the blob downloads flow through CONNECT.
    pull_output=$($SMOLVM machine run --net \
        --proxy "http://127.0.0.1:$proxy_port" \
        --image alpine -- echo ok 2>&1)
    pull_exit=$?

    kill $proxy_pid 2>/dev/null
    wait $proxy_pid 2>/dev/null

    # Two conditions must hold for the feature to be considered working:
    #   1. The pull succeeded (exit 0 + workload printed "ok")
    #   2. The proxy log contains a CONNECT for a docker registry, proving
    #      the request actually went through the proxy (not direct DNS).
    local connect_seen=0
    if grep -qiE '^CONNECT[[:space:]]+([a-z0-9.-]*\.)?docker\.io:443' "$proxy_log"; then
        connect_seen=1
    fi

    local result=0
    if [[ $pull_exit -ne 0 ]] || [[ "$pull_output" != *"ok"* ]] || [[ $connect_seen -ne 1 ]]; then
        result=1
        echo "  pull exit code:    $pull_exit"
        echo "  workload output:   $(echo "$pull_output" | tail -1)"
        echo "  CONNECT logged:    $connect_seen"
        echo "  proxy log contents:"
        sed 's/^/    /' "$proxy_log"
    fi
    rm -f "$proxy_log"
    return $result
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
run_test "DNS filter: TCP/53 allowed domain returns NOERROR" test_dns_filter_tcp_allowed || true
run_test "DNS filter: TCP/53 blocked domain returns NXDOMAIN" test_dns_filter_tcp_blocked || true
run_test "DNS filter: allow-host persists across restart" test_machine_allow_host_persists_across_restart || true
run_test "Smolfile: allow_hosts basic egress permitted/blocked" test_smolfile_allow_hosts_egress_basic || true
run_test "Smolfile: allow_hosts re-resolves stale CIDRs on start (issue #124)" test_smolfile_allow_hosts_stale_cidr_regression || true
run_test "Egress refresh thread: stability across refresh cycles" test_egress_refresh_thread_stability || true
run_test "Proxy: --proxy flag routes image pull through proxy" test_proxy_flag_routes_pull_through_proxy || true
run_test "grpcio: secure channel ready (ilyaterin grpc test)" test_grpcio_channel_ready || true


print_summary "Network Tests"
