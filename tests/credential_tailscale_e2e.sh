#!/usr/bin/env bash
# A --credential binding applies when the workload reaches the credential
# host through a real Tailscale client, in both of its modes:
#
#   kernel       tailscaled with a TUN (tailscale0): a tailnet host over IPv4
#                and IPv6, and every host through an exit node; and again
#                with tailscaled's firewall rules in legacy iptables;
#   userspace    tailscaled --tun=userspace-networking: through its SOCKS5
#                proxy (by name and by address) and its HTTP proxy, to an
#                exit node.
#
# A local Headscale control server stands in for Tailscale's, so no account
# is needed. The exit node also relays the echo host's HTTPS from its tailnet
# addresses ("tailnet host"); TLS passes through untouched and the real
# certificate is verified.
#
# Run after building smolvm on Linux KVM with an agent rootfs carrying the
# matching agent. Needs internet access (Alpine packages, Tailscale's public
# DERP relays, the echo host).
#   SMOLVM_E2E_BIN   smolvm binary (default target/debug/smolvm)
#   E2E_REGISTRY     prefix for the Docker Hub images, e.g. mirror.gcr.io/library/
#   E2E_HEADSCALE    headscale binary (default: download v0.29.5)
#   E2E_ECHO_HOST    HTTPS host that echoes request headers at /headers
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${SMOLVM_E2E_BIN:-"$repo/target/debug/smolvm"}
registry=${E2E_REGISTRY:-}
echo_host=${E2E_ECHO_HOST:-httpbin.org}
[[ -x $binary ]] || { echo "Missing smolvm binary: $binary" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo 'This test requires Linux KVM' >&2; exit 1; }

suffix=$$
exit_vm=tsexit-$suffix
kernel_vm=tskernel-$suffix
legacy_vm=tslegacy-$suffix
user_vm=tsuser-$suffix
tmp=$(mktemp -d /tmp/smolvm-credts-XXXXXXXX)
host_ip=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])')
port=$((22000 + RANDOM % 20000))
headscale_pid=
current=setup
passed=()

cleanup() {
  [[ ${E2E_KEEP:-0} == 1 ]] && { echo "kept machines (suffix $suffix), headscale pid $headscale_pid"; return; }
  for vm in "$kernel_vm" "$legacy_vm" "$user_vm" "$exit_vm"; do
    "$binary" machine delete --name "$vm" -f >/dev/null 2>&1 || true
  done
  if [[ -n $headscale_pid ]]; then kill "$headscale_pid" 2>/dev/null || true; fi
  case $tmp in /tmp/smolvm-credts-*) rm -rf "$tmp" ;; esac
}
trap cleanup EXIT
fail() { echo "FAIL [$current]: $*" >&2; exit 1; }
pass() { echo "PASS [$current]: $*"; passed+=("$current"); }
in_vm() { local vm=$1; shift; "$binary" machine exec --name "$vm" -- sh -c "$*"; }

# --- the control server ---------------------------------------------------------
headscale=${E2E_HEADSCALE:-}
if [[ -z $headscale ]]; then
  headscale=$tmp/headscale
  curl -fsSL -o "$headscale" \
    https://github.com/juanfont/headscale/releases/download/v0.29.5/headscale_0.29.5_linux_amd64
  chmod +x "$headscale"
fi
cat >"$tmp/headscale.yaml" <<EOF
server_url: http://$host_ip:$port
listen_addr: $host_ip:$port
metrics_listen_addr: 127.0.0.1:$((port + 1))
grpc_listen_addr: 127.0.0.1:$((port + 2))
noise:
  private_key_path: $tmp/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: $tmp/headscale.db
dns:
  magic_dns: false
  override_local_dns: false
  nameservers:
    global: []
unix_socket: $tmp/headscale.sock
unix_socket_permission: "0700"
EOF
hs() { "$headscale" -c "$tmp/headscale.yaml" "$@"; }
# Started directly, not through hs, so $! is the server itself.
"$headscale" -c "$tmp/headscale.yaml" serve >"$tmp/headscale.log" 2>&1 &
headscale_pid=$!
for _ in $(seq 1 30); do hs users list >/dev/null 2>&1 && break; sleep 1; done
hs users create e2e >/dev/null
key=$(hs preauthkeys create -u 1 --reusable -e 2h 2>/dev/null | tail -1)
[[ -n $key ]] || fail "no pre-auth key"

printf %s value-from-file >"$tmp/token"
credential=(--credential "t=TOKEN@$echo_host" --secret-file "TOKEN=$tmp/token")
ts_up="tailscale up --login-server http://$host_ip:$port --authkey $key --timeout 120s"
start_tailscaled() {
  local vm=$1 flags=${2:-} env=${3:-}
  in_vm "$vm" "apk add -q tailscale iptables ip6tables curl openssl socat iproute2 >/dev/null &&
    mkdir -p /var/lib/tailscale /run/tailscale &&
    (env $env tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock $flags </dev/null >/tmp/tailscaled.log 2>&1 &) &&
    for _ in \$(seq 1 30); do tailscale status >/dev/null 2>&1; [ \$? -ne 1 ] && break; sleep 1; done; true"
}
request() {
  local vm=$1 extra=$2
  in_vm "$vm" "curl -sS -m 30 $extra -H \"X-Token: \$TOKEN\" https://$echo_host/headers"
}
assert_value() {
  [[ $1 == *'"value-from-file"'* ]] || fail "$echo_host did not receive the credential value: $1"
  [[ $1 != *SMOL_PLACEHOLDER* ]] || fail "the placeholder left the machine: $1"
}
# Packets the exit node translated onto its own network: tailscaled
# masquerades what it forwards as an exit node.
exit_forwarded() {
  in_vm "$exit_vm" "iptables -t nat -L ts-postrouting -v -n -x 2>/dev/null | awk '/MASQUERADE/ {n += \$1} END {print n + 0}'"
}

# --- the exit node ------------------------------------------------------------------
# Off the 100.64.0.0/10 range Tailscale uses, so the guest keeps its gateway.
"$binary" machine create --name "$exit_vm" --image "${registry}alpine:3.23" --guest-subnet 10.231.0.0/24 -- sleep infinity >/dev/null
"$binary" machine start --name "$exit_vm" >/dev/null
start_tailscaled "$exit_vm"
in_vm "$exit_vm" "sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 &&
  $ts_up --hostname tsexit-$suffix --advertise-exit-node >/dev/null"
exit_v4=$(in_vm "$exit_vm" "tailscale ip -4")
exit_v6=$(in_vm "$exit_vm" "tailscale ip -6")
node=$(hs nodes list -o json | python3 -c "import json,sys; print([n['id'] for n in json.load(sys.stdin) if n.get('given_name','').startswith('tsexit') or n.get('name','').startswith('tsexit')][0])")
hs nodes approve-routes -i "$node" -r 0.0.0.0/0,::/0 >/dev/null
# The "tailnet host": the echo host's HTTPS from the exit node's tailnet
# addresses.
in_vm "$exit_vm" "(socat TCP4-LISTEN:443,bind=$exit_v4,fork,reuseaddr TCP4:$echo_host:443 </dev/null >/dev/null 2>&1 &);
  (socat TCP6-LISTEN:443,bind=[$exit_v6],fork,reuseaddr TCP4:$echo_host:443 </dev/null >/dev/null 2>&1 &)"

# --- kernel mode (tailscale0) ------------------------------------------------------
current=kernel
"$binary" machine create --name "$kernel_vm" --image "${registry}alpine:3.23" --guest-subnet 10.232.0.0/24 \
  "${credential[@]}" -- sleep infinity >/dev/null
"$binary" machine start --name "$kernel_vm" >/dev/null
start_tailscaled "$kernel_vm"
in_vm "$kernel_vm" "$ts_up --hostname tskernel-$suffix >/dev/null"
in_vm "$kernel_vm" "ip route get $exit_v4 | grep -q tailscale0" || fail "the tailnet host is not routed through tailscale0"
current=kernel_tailnet_v4
assert_value "$(request "$kernel_vm" "--resolve $echo_host:443:$exit_v4")"
pass "a credential host on the tailnet (IPv4), through tailscale0, got the value"
current=kernel_tailnet_v6
assert_value "$(request "$kernel_vm" "--resolve $echo_host:443:[$exit_v6]")"
pass "a credential host on the tailnet (IPv6), through tailscale0, got the value"
current=kernel_exit_node
in_vm "$kernel_vm" "tailscale set --exit-node=$exit_v4 --exit-node-allow-lan-access"
echo_ip=$(in_vm "$kernel_vm" "getent ahostsv4 $echo_host | head -1 | cut -d' ' -f1")
in_vm "$kernel_vm" "ip route get $echo_ip | grep -q tailscale0" || fail "the exit node does not carry $echo_host"
before=$(exit_forwarded)
assert_value "$(request "$kernel_vm" "")"
after=$(exit_forwarded)
(( after > before )) || fail "the request did not leave through the exit node ($before -> $after)"
pass "every host through an exit node: the credential host got the value, through the exit node"

# --- kernel mode, firewall rules in legacy iptables ---------------------------------------
# tailscaled drops its own address range arriving anywhere but tailscale0; a
# redirected connection's replies arrive on loopback, so the agent exempts
# them in whichever iptables the workload uses.
current=kernel_legacy
"$binary" machine create --name "$legacy_vm" --image "${registry}alpine:3.23" --guest-subnet 10.234.0.0/24 \
  "${credential[@]}" -- sleep infinity >/dev/null
"$binary" machine start --name "$legacy_vm" >/dev/null
in_vm "$legacy_vm" "apk add -q iptables ip6tables iptables-legacy >/dev/null && mkdir -p /usr/local/sbin &&
  ln -sf \$(command -v iptables-legacy) /usr/local/sbin/iptables &&
  ln -sf \$(command -v ip6tables-legacy) /usr/local/sbin/ip6tables"
start_tailscaled "$legacy_vm" "" "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TS_DEBUG_FIREWALL_MODE=iptables"
in_vm "$legacy_vm" "$ts_up --hostname tslegacy-$suffix >/dev/null"
in_vm "$legacy_vm" "iptables-legacy -S ts-input | grep -q DROP" || fail "tailscaled did not put its rules in legacy iptables"
for target in "$exit_v4" "[$exit_v6]"; do
  assert_value "$(request "$legacy_vm" "--resolve $echo_host:443:$target")"
done
pass "with tailscaled's rules in legacy iptables, tailnet hosts over IPv4 and IPv6 got the value"

# --- userspace mode (SOCKS5 and HTTP proxies) ------------------------------------------
current=userspace
"$binary" machine create --name "$user_vm" --image "${registry}alpine:3.23" --guest-subnet 10.233.0.0/24 \
  "${credential[@]}" -- sleep infinity >/dev/null
"$binary" machine start --name "$user_vm" >/dev/null
start_tailscaled "$user_vm" "--tun=userspace-networking --socks5-server=localhost:1055 --outbound-http-proxy-listen=localhost:1056"
in_vm "$user_vm" "$ts_up --hostname tsuser-$suffix --exit-node=$exit_v4 >/dev/null"
in_vm "$user_vm" "! ip link show tailscale0 2>/dev/null" || fail "userspace mode created a TUN"
# The exit path can take a moment after tailscale up returns; wait for a plain
# HTTP request through the proxy before measuring.
for _ in $(seq 1 60); do
  in_vm "$user_vm" "curl -s -4 -m 5 -o /dev/null --proxy socks5h://localhost:1055 http://$echo_host/get" && break
  sleep 1
done
# socks5:// has curl resolve the name itself; -4 keeps it to an address the
# exit node can reach (this host has no IPv6 route to the internet).
for proxy in socks5h://localhost:1055 socks5://localhost:1055 http://localhost:1056; do
  current="userspace ${proxy%%:*}"
  before=$(exit_forwarded)
  assert_value "$(request "$user_vm" "-4 --proxy $proxy")"
  after=$(exit_forwarded)
  (( after > before )) || fail "the request did not leave through the exit node ($before -> $after)"
  pass "through tailscaled's $proxy proxy to the exit node, the credential host got the value"
done
current=userspace_unbound
issuer=$(in_vm "$user_vm" "echo | openssl s_client -proxy localhost:1056 -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer")
[[ -n $issuer && $issuer != *"smolvm machine credentials"* ]] || fail "an unbound host through the proxy lost its certificate: $issuer"
pass "an unbound host through the proxy keeps its own certificate"

echo "all passed: ${passed[*]}"
