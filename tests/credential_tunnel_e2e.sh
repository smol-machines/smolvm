#!/usr/bin/env bash
# A --credential binding applies to HTTPS the workload routes through a TUN
# device (Tailscale's tailscale0, a WireGuard or OpenVPN interface), not only
# through the machine's NIC.
#
# Two machines: "exit" is a userspace VPN peer that forwards to the internet,
# like a Tailscale exit node; "client" holds the credential and routes the
# echo host through tun0. The request must arrive with the real value, its
# upstream must leave through the exit peer, and an unbound host must keep its
# own certificate.
#
# Run after building smolvm on Linux KVM with an agent rootfs carrying the
# matching agent. Needs internet access (Alpine packages and the echo host).
#   SMOLVM_E2E_BIN     smolvm binary (default target/debug/smolvm)
#   E2E_ECHO_HOST      HTTPS host that echoes request headers at /headers
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${SMOLVM_E2E_BIN:-"$repo/target/debug/smolvm"}
echo_host=${E2E_ECHO_HOST:-httpbin.org}
[[ -x $binary ]] || { echo "Missing smolvm binary: $binary" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo 'This test requires Linux KVM' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Missing host tool: python3' >&2; exit 1; }

suffix=$$
exit_vm=cred-tunnel-exit-$suffix
client_vm=cred-tunnel-client-$suffix
tmp=$(mktemp -d /tmp/smolvm-credtun-XXXXXXXX)
vpn_port=$((21000 + RANDOM % 20000))
relay_port=$((vpn_port + 1))
relay_pid=
host_ip=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])')

cleanup() {
  for vm in "$client_vm" "$exit_vm"; do
    "$binary" machine delete --name "$vm" -f >/dev/null 2>&1 || true
  done
  if [[ -n $relay_pid ]]; then kill "$relay_pid" 2>/dev/null || true; fi
  case $tmp in /tmp/smolvm-credtun-*) rm -rf "$tmp" ;; esac
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
in_vm() { local vm=$1; shift; "$binary" machine exec --name "$vm" -- sh -c "$*"; }

# smolvm publishes a guest's UDP port on host loopback; relay the host's LAN
# address to it so the other machine can reach the exit peer.
python3 - "$relay_port" "$vpn_port" <<'EOF' &
import selectors, socket, sys
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); front.bind(("0.0.0.0", int(sys.argv[1])))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); back.connect(("127.0.0.1", int(sys.argv[2])))
peer = None
sel = selectors.DefaultSelector()
sel.register(front, selectors.EVENT_READ); sel.register(back, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        if key.fileobj is front:
            data, peer = front.recvfrom(65535); back.send(data)
        elif peer is not None:
            front.sendto(back.recv(65535), peer)
EOF
relay_pid=$!

printf %s value-from-file > "$tmp/token"
"$binary" machine create --name "$exit_vm" --image alpine:3.20 --net \
  -p "$vpn_port:1194/udp" -- sleep infinity >/dev/null
"$binary" machine create --name "$client_vm" --image alpine:3.20 \
  --credential "t=TOKEN@$echo_host" --secret-file "TOKEN=$tmp/token" -- sleep infinity >/dev/null
"$binary" machine start --name "$exit_vm" >/dev/null
"$binary" machine start --name "$client_vm" >/dev/null

vpn="openvpn --dev tun0 --proto udp --secret /vpn.key --cipher AES-256-CBC --daemon --log /tmp/openvpn.log"
in_vm "$exit_vm" "apk add -q openvpn iptables >/dev/null && openvpn --genkey secret /vpn.key 2>/dev/null"
"$binary" machine cp "$exit_vm:/vpn.key" "$tmp/vpn.key" >/dev/null 2>&1
"$binary" machine cp --mode 600 "$tmp/vpn.key" "$client_vm:/vpn.key" >/dev/null 2>&1
in_vm "$exit_vm" "sysctl -qw net.ipv4.ip_forward=1 &&
  iptables -t nat -A POSTROUTING -s 10.67.0.0/24 -o eth0 -j MASQUERADE &&
  $vpn --lport 1194 --ifconfig 10.67.0.2 10.67.0.1"
in_vm "$client_vm" "apk add -q openvpn curl openssl >/dev/null &&
  $vpn --remote $host_ip $relay_port --ifconfig 10.67.0.1 10.67.0.2"
for _ in $(seq 1 30); do
  in_vm "$client_vm" "ping -c1 -W1 10.67.0.2 >/dev/null 2>&1" && break
  sleep 1
done
in_vm "$client_vm" "ping -c1 -W2 10.67.0.2 >/dev/null" || fail "the VPN between the machines did not come up"
# Route the echo host and an unbound host through tun0, as tailscaled routes a
# tailnet host or an exit node through tailscale0.
in_vm "$client_vm" "for h in $echo_host example.com; do
  for ip in \$(getent ahostsv4 \$h | cut -d' ' -f1 | sort -u); do ip route replace \$ip/32 dev tun0; done; done"
route=$(in_vm "$client_vm" "ip route get \$(getent ahostsv4 $echo_host | head -1 | cut -d' ' -f1)")
[[ $route == *"dev tun0"* ]] || fail "$echo_host does not route through tun0: $route"

nat_packets() {
  in_vm "$exit_vm" "iptables -t nat -L POSTROUTING -v -n -x | awk '/MASQUERADE/ {print \$1}'"
}
before=$(nat_packets)
seen=$(in_vm "$client_vm" "curl -sS -m 20 -H \"X-Token: \$TOKEN\" https://$echo_host/headers")
after=$(nat_packets)
[[ $seen == *'"value-from-file"'* ]] || fail "$echo_host did not receive the credential value: $seen"
[[ $seen != *SMOL_PLACEHOLDER* ]] || fail "the placeholder left the machine: $seen"
(( after > before )) || fail "the upstream did not leave through the exit peer ($before -> $after NAT packets)"
echo "PASS: a credential host routed through tun0 got the value; the upstream left through the exit peer"

issuer=$(in_vm "$client_vm" "echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer")
[[ $issuer != *"smolvm machine credentials"* && -n $issuer ]] || fail "an unbound host through tun0 lost its certificate: $issuer"
code=$(in_vm "$client_vm" "curl -s -o /dev/null -m 20 -w '%{http_code}' https://example.com/")
[[ $code == 200 ]] || fail "an unbound host through tun0 answered $code"
echo "PASS: an unbound host routed through tun0 kept its own certificate"
