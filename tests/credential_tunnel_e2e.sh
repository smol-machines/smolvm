#!/usr/bin/env bash
# A --credential binding applies to HTTPS the machine's NIC would not carry in
# the clear: a VPN route (Tailscale's tailscale0, WireGuard, OpenVPN), traffic
# forwarded for a container or network namespace, a tunnel inside a
# namespace, a VPN whose far end sends traffic back out the NIC, and the same
# on the TSI backend. Real Tailscale, kernel and userspace, is covered by
# tests/credential_tailscale_e2e.sh.
#
# An "exit" machine runs userspace VPN peers that forward to the internet,
# like a Tailscale exit node; "client" machines hold the credential and route
# the echo host through a tunnel. Each case checks that the request arrived
# with the real value and, where the route matters, that it left through the
# path the workload chose.
#
# Run after building smolvm on Linux KVM with an agent rootfs carrying the
# matching agent. Needs internet access (Alpine packages, the echo host).
#   SMOLVM_E2E_BIN   smolvm binary (default target/debug/smolvm)
#   E2E_ECHO_HOST    HTTPS host that echoes request headers at /headers
#   E2E_CASES        space-separated subset of the cases below
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${SMOLVM_E2E_BIN:-"$repo/target/debug/smolvm"}
echo_host=${E2E_ECHO_HOST:-httpbin.org}
all_cases="ipv4 ipv6 flush netns_forward netns_tunnel back_out_nic ssh_socks docker tsi"
cases=${E2E_CASES:-$all_cases}
[[ -x $binary ]] || { echo "Missing smolvm binary: $binary" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo 'This test requires Linux KVM' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Missing host tool: python3' >&2; exit 1; }

suffix=$$
exit_vm=credtun-exit-$suffix
client_vm=credtun-client-$suffix
docker_vm=credtun-docker-$suffix
tsi_vm=credtun-tsi-$suffix
tmp=$(mktemp -d /tmp/smolvm-credtun-XXXXXXXX)
base=$((21000 + RANDOM % 20000))
# One exit-side VPN instance per client: (name, guest port, tunnel subnet).
vpn_a=$base vpn_c=$((base + 2)) vpn_t=$((base + 4)) ssh_port=$((base + 6))
relay_pid= tcp_relay_pid=
host_ip=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])')
passed=()

cleanup() {
  [[ ${E2E_KEEP:-0} == 1 ]] && { echo "kept machines (suffix $suffix), relay pids $relay_pid $tcp_relay_pid"; return; }
  for vm in "$client_vm" "$docker_vm" "$tsi_vm" "$exit_vm"; do
    "$binary" machine delete --name "$vm" -f >/dev/null 2>&1 || true
  done
  if [[ -n $relay_pid ]]; then kill "$relay_pid" 2>/dev/null || true; fi
  if [[ -n $tcp_relay_pid ]]; then kill "$tcp_relay_pid" 2>/dev/null || true; fi
  case $tmp in /tmp/smolvm-credtun-*) rm -rf "$tmp" ;; esac
}
trap cleanup EXIT
fail() { echo "FAIL [$current]: $*" >&2; exit 1; }
in_vm() { local vm=$1; shift; "$binary" machine exec --name "$vm" -- sh -c "$*"; }
want() { [[ " $cases " == *" $1 "* ]]; }
current=setup

# smolvm publishes a guest's UDP port on host loopback; relay the host's LAN
# address (guest port + 1) to it so the client machines can reach the peers.
python3 - "$vpn_a" "$vpn_c" "$vpn_t" <<'EOF' &
import selectors, socket, sys
sel = selectors.DefaultSelector()
for port in map(int, sys.argv[1:]):
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); front.bind(("0.0.0.0", port + 1))
    back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); back.connect(("127.0.0.1", port))
    pair = {"front": front, "back": back, "peer": None}
    sel.register(front, selectors.EVENT_READ, ("front", pair))
    sel.register(back, selectors.EVENT_READ, ("back", pair))
while True:
    for key, _ in sel.select():
        side, pair = key.data
        if side == "front":
            data, pair["peer"] = pair["front"].recvfrom(65535); pair["back"].send(data)
        elif pair["peer"] is not None:
            pair["front"].sendto(pair["back"].recv(65535), pair["peer"])
EOF
relay_pid=$!
# The same for the exit's SSH server, over TCP.
python3 - "$ssh_port" <<'EOF' &
import socket, sys, threading
port = int(sys.argv[1])
def pump(a, b):
    try:
        while data := a.recv(65536):
            b.sendall(data)
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except OSError: pass
front = socket.socket(); front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
front.bind(("0.0.0.0", port + 1)); front.listen(16)
while True:
    client, _ = front.accept()
    back = socket.create_connection(("127.0.0.1", port))
    threading.Thread(target=pump, args=(client, back), daemon=True).start()
    threading.Thread(target=pump, args=(back, client), daemon=True).start()
EOF
tcp_relay_pid=$!

printf %s value-from-file > "$tmp/token"
credential=(--credential "t=TOKEN@$echo_host" --secret-file "TOKEN=$tmp/token")
# Static-key OpenVPN: OpenVPN 2.7 wants the deprecation acknowledged, 2.6
# does not know the option. Evaluated in the guest.
vpn_flags='--proto udp --secret /vpn.key --cipher AES-256-CBC --daemon $(openvpn --version 2>/dev/null | head -1 | grep -qE "OpenVPN 2\.[0-6]\." || echo --allow-deprecated-insecure-static-crypto)'

# --- the exit machine -------------------------------------------------------
"$binary" machine create --name "$exit_vm" --image alpine:3.20 --net \
  -p "$vpn_a:1194/udp" -p "$vpn_c:1196/udp" -p "$vpn_t:1197/udp" -p "$ssh_port:22" -- sleep infinity >/dev/null
"$binary" machine start --name "$exit_vm" >/dev/null
in_vm "$exit_vm" "apk add -q openvpn iptables ip6tables socat >/dev/null && openvpn --genkey secret /vpn.key 2>/dev/null"
"$binary" machine cp "$exit_vm:/vpn.key" "$tmp/vpn.key" >/dev/null 2>&1
in_vm "$exit_vm" "sysctl -qw net.ipv4.ip_forward=1 &&
  iptables -t nat -A POSTROUTING -s 10.64.0.0/12 -o eth0 -j MASQUERADE &&
  openvpn --dev tuna $vpn_flags --log /tmp/a.log --lport 1194 --ifconfig 10.67.0.2 10.67.0.1 --ifconfig-ipv6 fd67::2/64 fd67::1 &&
  openvpn --dev tunc $vpn_flags --log /tmp/c.log --lport 1196 --ifconfig 10.69.0.2 10.69.0.1 &&
  openvpn --dev tunt $vpn_flags --log /tmp/t.log --lport 1197 --ifconfig 10.70.0.2 10.70.0.1"
# The host has no IPv6 route to the internet, so the exit relays the echo
# host's HTTPS from its tunnel IPv6 address over IPv4: TLS passes through
# untouched and the real certificate is still verified.
in_vm "$exit_vm" "sleep 1; (socat TCP6-LISTEN:443,bind=[fd67::2],fork,reuseaddr TCP4:$echo_host:443 </dev/null >/dev/null 2>&1 &)"
nat_packets() {
  in_vm "$exit_vm" "iptables -t nat -L POSTROUTING -v -n -x | awk '/MASQUERADE/ {print \$1}'"
}

# A client machine with the credential and a VPN to the exit.
start_client() {
  local vm=$1; shift
  local workload=(-- sleep infinity)
  [[ ${1:-} == --image-workload ]] && { workload=(); shift; }
  "$binary" machine create --name "$vm" "$@" "${credential[@]}" "${workload[@]}" >/dev/null
  "$binary" machine start --name "$vm" >/dev/null
  "$binary" machine cp --mode 600 "$tmp/vpn.key" "$vm:/vpn.key" >/dev/null 2>&1
}
vpn_up() {
  local vm=$1 dev=$2 port=$3 local_ip=$4 remote_ip=$5 extra=${6:-} netns=${7:-}
  local run=""; [[ -n $netns ]] && run="ip netns exec $netns"
  in_vm "$vm" "$run openvpn --dev $dev $vpn_flags --nobind --log /tmp/$dev.log --remote $host_ip $((port + 1)) --ifconfig $local_ip $remote_ip $extra"
  for _ in $(seq 1 30); do
    in_vm "$vm" "$run ping -c1 -W1 $remote_ip >/dev/null 2>&1" && return 0
    sleep 1
  done
  fail "the VPN $dev did not come up"
}
echo_ips() { in_vm "$1" "getent ahostsv4 $echo_host | cut -d' ' -f1 | sort -u | tr '\n' ' '"; }
# Route the echo host through `dev` (in `netns`, when given).
route_via() {
  local vm=$1 dev=$2 netns=${3:-} run=""
  [[ -n $netns ]] && run="ip netns exec $netns"
  in_vm "$vm" "for ip in $(echo_ips "$vm"); do $run ip route replace \$ip/32 dev $dev; done"
}
# Ask the echo host for its headers with the placeholder, from `run`.
request() {
  local vm=$1 run=${2:-} extra=${3:-}
  in_vm "$vm" "$run curl -sS -m 20 $extra -H \"X-Token: \$TOKEN\" https://$echo_host/headers"
}
assert_value() {
  [[ $1 == *'"value-from-file"'* ]] || fail "$echo_host did not receive the credential value: $1"
  [[ $1 != *SMOL_PLACEHOLDER* ]] || fail "the placeholder left the machine: $1"
}
assert_through_exit() {
  (( $2 > $1 )) || fail "the upstream did not leave through the exit peer ($1 -> $2 NAT packets)"
}
pass() { echo "PASS [$current]: $*"; passed+=("$current"); }

needs_client=0
for c in ipv4 ipv6 flush netns_forward netns_tunnel back_out_nic ssh_socks; do want "$c" && needs_client=1; done
if (( needs_client )); then
  start_client "$client_vm" --image alpine:3.20
  in_vm "$client_vm" "apk add -q openvpn curl openssl iproute2 iptables nftables >/dev/null"
  vpn_up "$client_vm" tun0 "$vpn_a" 10.67.0.1 10.67.0.2 "--ifconfig-ipv6 fd67::1/64 fd67::2"
fi

# --- a host routed through a VPN, IPv4 ---------------------------------------
if want ipv4; then
  current=ipv4
  route_via "$client_vm" tun0
  before=$(nat_packets); seen=$(request "$client_vm"); after=$(nat_packets)
  assert_value "$seen"; assert_through_exit "$before" "$after"
  in_vm "$client_vm" "for ip in \$(getent ahostsv4 example.com | cut -d' ' -f1 | sort -u); do ip route replace \$ip/32 dev tun0; done"
  issuer=$(in_vm "$client_vm" "echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer")
  [[ -n $issuer && $issuer != *"smolvm machine credentials"* ]] || fail "an unbound host lost its certificate: $issuer"
  pass "a credential host routed through tun0 got the value through the exit; unbound hosts keep their certificate"
fi

# --- the same over IPv6 --------------------------------------------------------
if want ipv6; then
  current=ipv6
  seen=$(request "$client_vm" "" "--resolve $echo_host:443:[fd67::2]")
  assert_value "$seen"
  pass "a credential host reached over IPv6 through tun0 got the value"
fi

# --- a workload that flushes or deletes the rules ------------------------------
if want flush; then
  current=flush
  route_via "$client_vm" tun0
  out=$(in_vm "$client_vm" "nft flush ruleset; nft delete table ip smolvm_credentials 2>&1; nft delete table ip6 smolvm_credentials 2>&1; iptables -t nat -F; true")
  [[ $out == *"Operation not permitted"* ]] || fail "deleting the redirect table was not refused: $out"
  in_vm "$client_vm" "nft list table ip smolvm_credentials >/dev/null" || fail "the redirect table is gone"
  assert_value "$(request "$client_vm")"
  pass "nft flush ruleset leaves the redirect, deleting it is refused, and the value still arrives"
fi

# --- a network namespace behind a bridge, forwarded through the VPN ------------
if want netns_forward; then
  current=netns_forward
  in_vm "$client_vm" "ip netns add cns && ip link add brt type bridge && ip link set brt up &&
    ip addr add 10.88.0.1/24 dev brt && ip link add cnsa type veth peer name cnsb &&
    ip link set cnsa master brt up && ip link set cnsb netns cns &&
    ip netns exec cns ip addr add 10.88.0.2/24 dev cnsb && ip netns exec cns ip link set cnsb up &&
    ip netns exec cns ip link set lo up && ip netns exec cns ip route add default via 10.88.0.1 &&
    sysctl -qw net.ipv4.ip_forward=1 && iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o tun0 -j MASQUERADE"
  route_via "$client_vm" tun0
  before=$(nat_packets)
  seen=$(request "$client_vm" "ip netns exec cns" "--resolve $echo_host:443:$(echo_ips "$client_vm" | cut -d' ' -f1)")
  after=$(nat_packets)
  assert_value "$seen"; assert_through_exit "$before" "$after"
  pass "HTTPS a bridged namespace forwards through tun0 got the value, and still left through the exit"
fi

# --- a VPN inside a network namespace -------------------------------------------
if want netns_tunnel; then
  current=netns_tunnel
  in_vm "$client_vm" "ip netns add tns && ip link add tnsa type veth peer name tnsb && ip link set tnsb netns tns &&
    ip addr add 10.91.0.1/30 dev tnsa && ip link set tnsa up &&
    ip netns exec tns ip addr add 10.91.0.2/30 dev tnsb && ip netns exec tns ip link set tnsb up &&
    ip netns exec tns ip link set lo up && ip netns exec tns ip route add default via 10.91.0.1 &&
    sysctl -qw net.ipv4.ip_forward=1 && iptables -t nat -A POSTROUTING -s 10.91.0.0/30 -o eth0 -j MASQUERADE"
  vpn_up "$client_vm" tun5 "$vpn_c" 10.69.0.1 10.69.0.2 "" tns
  route_via "$client_vm" tun5 tns
  before=$(nat_packets)
  seen=$(request "$client_vm" "ip netns exec tns" "--resolve $echo_host:443:$(echo_ips "$client_vm" | cut -d' ' -f1)")
  after=$(nat_packets)
  assert_value "$seen"; assert_through_exit "$before" "$after"
  pass "HTTPS through a VPN running inside a namespace got the value, through that namespace's tunnel"
fi

# --- a VPN whose far end sends the traffic back out the NIC in the clear --------
if want back_out_nic; then
  current=back_out_nic
  # The far end runs in a namespace of the same machine; what it decrypts
  # comes back to the root namespace and leaves on eth0 unencrypted.
  in_vm "$client_vm" "ip netns add xns && ip link add vxa type veth peer name vxb && ip link set vxb netns xns &&
    ip addr add 10.90.0.1/30 dev vxa && ip link set vxa up &&
    ip netns exec xns ip addr add 10.90.0.2/30 dev vxb && ip netns exec xns ip link set vxb up &&
    ip netns exec xns ip link set lo up && ip netns exec xns ip route add default via 10.90.0.1 &&
    ip netns exec xns sysctl -qw net.ipv4.ip_forward=1 &&
    ip netns exec xns iptables -t nat -A POSTROUTING -s 10.68.0.0/24 -o vxb -j MASQUERADE &&
    ip netns exec xns openvpn --dev tun7 $vpn_flags --log /tmp/tun7.log --lport 1195 --ifconfig 10.68.0.2 10.68.0.1 &&
    sysctl -qw net.ipv4.ip_forward=1 && iptables -t nat -A POSTROUTING -s 10.90.0.0/30 -o eth0 -j MASQUERADE &&
    gw=\$(ip route show default | awk '{print \$3; exit}') &&
    ip route add default via \$gw dev eth0 table 100 && ip rule add iif vxa lookup 100"
  in_vm "$client_vm" "openvpn --dev tun6 $vpn_flags --nobind --log /tmp/tun6.log --remote 10.90.0.2 1195 --ifconfig 10.68.0.1 10.68.0.2"
  for _ in $(seq 1 30); do in_vm "$client_vm" "ping -c1 -W1 10.68.0.2 >/dev/null 2>&1" && break; sleep 1; done
  route_via "$client_vm" tun6
  xns_before=$(in_vm "$client_vm" "ip netns exec xns iptables -t nat -L POSTROUTING -v -n -x | awk '/MASQUERADE/ {print \$1}'")
  seen=$(request "$client_vm")
  xns_after=$(in_vm "$client_vm" "ip netns exec xns iptables -t nat -L POSTROUTING -v -n -x | awk '/MASQUERADE/ {print \$1}'")
  assert_value "$seen"
  (( xns_after > xns_before )) || fail "the request did not go through the in-machine VPN ($xns_before -> $xns_after)"
  pass "a VPN that hands the traffic back out the NIC in the clear: the value arrived once, through the VPN"
fi

# --- a local SOCKS proxy that tunnels over SSH ------------------------------------
if want ssh_socks; then
  current=ssh_socks
  # ssh -D: the client speaks SOCKS5 to a local port and the bytes leave
  # inside SSH, encrypted, through the NIC.
  in_vm "$exit_vm" "apk add -q openssh >/dev/null && ssh-keygen -A >/dev/null && mkdir -p /root/.ssh &&
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT && /usr/sbin/sshd -o AllowTcpForwarding=yes"
  in_vm "$client_vm" "apk add -q openssh-client >/dev/null && ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 && cat /root/.ssh/id_ed25519.pub" >"$tmp/client.pub"
  "$binary" machine cp "$tmp/client.pub" "$exit_vm:/root/.ssh/authorized_keys" >/dev/null 2>&1
  in_vm "$exit_vm" "chmod 600 /root/.ssh/authorized_keys"
  in_vm "$client_vm" "for ip in $(echo_ips "$client_vm"); do ip route del \$ip/32 2>/dev/null; done; true"
  in_vm "$client_vm" "ssh -f -N -D 127.0.0.1:1080 -p $((ssh_port + 1)) -o StrictHostKeyChecking=no root@$host_ip"
  sleep 1
  ssh_443() { in_vm "$exit_vm" "iptables -L OUTPUT -v -n -x | awk '/dpt:443/ {print \$1}'"; }
  for proxy in socks5h socks5; do
    before=$(ssh_443)
    seen=$(request "$client_vm" "" "-4 --proxy $proxy://127.0.0.1:1080")
    after=$(ssh_443)
    assert_value "$seen"
    (( after > before )) || fail "the request did not leave through the SSH tunnel ($before -> $after)"
  done
  pass "through an ssh -D SOCKS proxy (by name and by address), the value arrived, through the SSH server"
fi

# --- containers on a Docker bridge network --------------------------------------
if want docker; then
  current=docker
  # dockerd is the image's own workload.
  start_client "$docker_vm" --image-workload --image docker:29-dind --cpus 2 --mem 2048 \
    --storage 20 -v /var/lib/docker
  in_vm "$docker_vm" "apk add -q openvpn curl iproute2 >/dev/null"
  for _ in $(seq 1 60); do in_vm "$docker_vm" "docker info >/dev/null 2>&1" && break; sleep 1; done
  in_vm "$docker_vm" "docker info >/dev/null" || fail "dockerd did not start"
  # Containers run an image made from the machine's own userland: no pull.
  in_vm "$docker_vm" "tar -C / -c bin etc lib sbin usr 2>/dev/null | docker import - local/curl >/dev/null &&
    docker network create --subnet 10.89.0.0/24 credtest >/dev/null"
  vpn_up "$docker_vm" tun0 "$vpn_a" 10.67.0.1 10.67.0.2
  route_via "$docker_vm" tun0
  in_vm "$docker_vm" "iptables -t nat -A POSTROUTING -s 10.89.0.0/24 -o tun0 -j MASQUERADE"
  for network in bridge credtest; do
    before=$(nat_packets)
    seen=$(in_vm "$docker_vm" "docker run --rm --network $network -e TOKEN=\$TOKEN -v /run/smolvm/ca-bundle.pem:/ca.pem:ro local/curl \
      sh -c 'curl -sS -m 20 --cacert /ca.pem -H \"X-Token: \$TOKEN\" https://$echo_host/headers'")
    after=$(nat_packets)
    assert_value "$seen"; assert_through_exit "$before" "$after"
  done
  pass "containers on Docker's default and a user bridge network, routed through tun0, got the value"
fi

# --- the TSI backend ---------------------------------------------------------------
if want tsi; then
  current=tsi
  start_client "$tsi_vm" --image alpine:3.20 --net-backend tsi
  in_vm "$tsi_vm" "apk add -q openvpn curl iproute2 >/dev/null"
  vpn_up "$tsi_vm" tun0 "$vpn_t" 10.70.0.1 10.70.0.2
  route_via "$tsi_vm" tun0
  before=$(nat_packets); seen=$(request "$tsi_vm"); after=$(nat_packets)
  assert_value "$seen"; assert_through_exit "$before" "$after"
  pass "on the TSI backend, a credential host routed through tun0 got the value through the exit"
fi

echo "all passed: ${passed[*]}"
