#!/usr/bin/env bash
#
# HTTPS request rule tests for smolvm (--allow-request / --deny-request).
#
# Boots two machines and checks, from inside the guest, that the host
# interceptor enforces their rules. Needs a hypervisor and internet access to
# httpbin.org; the suite is skipped when the host cannot reach it.

source "$(dirname "$0")/common.sh"
init_smolvm

RULES_TEST_IMAGE="${RULES_TEST_IMAGE:-curlimages/curl:8.11.1}"
ALLOW_VM="rr-allow-$$"
DENY_VM="rr-deny-$$"

cleanup() {
    for vm in "$ALLOW_VM" "$DENY_VM"; do
        $SMOLVM machine stop --name "$vm" >/dev/null 2>&1 || true
        $SMOLVM machine delete --name "$vm" -f >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

echo ""
echo "=========================================="
echo "  smolvm Request Rule Tests"
echo "=========================================="
echo ""

if ! curl -sS --max-time 15 -o /dev/null https://httpbin.org/get 2>/dev/null; then
    log_skip "httpbin.org is unreachable from this host"
    print_summary "Request Rule Tests"
    exit 0
fi

# expect_status VM METHOD PATH WANT: the HTTP status the guest sees. The path
# is sent as written, so a test can spell it in a non-canonical way.
expect_status() {
    local vm=$1 method=$2 path=$3 want=$4 got
    got=$($SMOLVM machine exec --name "$vm" -- \
        curl -sS --path-as-is --max-time 20 -o /dev/null -w '%{http_code}' \
        -X "$method" "https://httpbin.org$path" 2>&1 | tail -n 1) || true
    [[ $got == "$want" ]] || {
        echo "$method $path -> $got, wanted $want"
        return 1
    }
}

# Allow rule: only GET /get reaches httpbin.org.
$SMOLVM machine create --name "$ALLOW_VM" --image "$RULES_TEST_IMAGE" \
    --allow-host httpbin.org --allow-request 'GET httpbin.org/get' >/dev/null
$SMOLVM machine start --name "$ALLOW_VM" >/dev/null

# Deny-only rules: everything else on the host stays open. Plain --net, so
# only the QUIC drop refuses UDP.
$SMOLVM machine create --name "$DENY_VM" --image "$RULES_TEST_IMAGE" --net \
    --deny-request 'DELETE httpbin.org' --deny-request 'httpbin.org/headers' >/dev/null
$SMOLVM machine start --name "$DENY_VM" >/dev/null

test_allow_rule_needs_a_match() {
    expect_status "$ALLOW_VM" GET /get 200 &&
        expect_status "$ALLOW_VM" POST /post 403 &&
        expect_status "$ALLOW_VM" GET /headers 403
}

test_refusal_body_names_smolvm() {
    local body
    body=$($SMOLVM machine exec --name "$ALLOW_VM" -- \
        curl -sS --max-time 20 -X POST https://httpbin.org/post 2>&1) || true
    grep -q "smolvm: request denied" <<<"$body" || {
        echo "403 body: $body"
        return 1
    }
}

test_refused_request_is_an_egress_event() {
    expect_status "$ALLOW_VM" POST '/post?token=secret' 403 || return 1
    local events
    events=$($SMOLVM machine egress-events --name "$ALLOW_VM" 2>&1) || true
    grep -q "request *POST https://httpbin.org/post$" <<<"$events" || {
        echo "egress-events: $events"
        return 1
    }
    ! grep -q "token=secret" <<<"$events" || {
        echo "the query string was recorded: $events"
        return 1
    }
}

test_deny_only_host_allows_the_rest() {
    expect_status "$DENY_VM" DELETE /delete 403 &&
        expect_status "$DENY_VM" GET /get 200
}

test_alternate_path_spellings_cannot_pass_a_deny() {
    expect_status "$DENY_VM" GET /headers 403 &&
        expect_status "$DENY_VM" GET /anything/../headers 403 &&
        expect_status "$DENY_VM" GET /%68eaders 403 &&
        expect_status "$DENY_VM" GET //headers 403
}

# QUIC (UDP 443) would skip the rules, so it is dropped; other UDP is not.
test_quic_is_dropped() {
    $SMOLVM machine exec --name "$DENY_VM" -- sh -c \
        'echo x | nc -u -w1 192.0.2.7 443; echo x | nc -u -w1 192.0.2.7 4433' \
        >/dev/null 2>&1 || true
    local events
    events=$($SMOLVM machine egress-events --name "$DENY_VM" 2>&1) || true
    grep -q '192.0.2.7:443$' <<<"$events" && ! grep -q '192.0.2.7:4433' <<<"$events" || {
        echo "egress-events: $events"
        return 1
    }
}

run_test "Allow rule: a host with one needs a match" test_allow_rule_needs_a_match || true
run_test "Refusal: the 403 body says smolvm refused it" test_refusal_body_names_smolvm || true
run_test "Refusal: listed in egress-events without its query" test_refused_request_is_an_egress_event || true
run_test "Deny-only rule: the rest of the host stays open" test_deny_only_host_allows_the_rest || true
run_test "Deny rule: alternate path spellings cannot pass it" test_alternate_path_spellings_cannot_pass_a_deny || true
run_test "QUIC: UDP 443 dropped, other UDP relayed" test_quic_is_dropped || true

print_summary "Request Rule Tests"
