#!/bin/sh
# Inside a TSI machine (Alpine): a local caching resolver (unbound on
# 127.0.0.1:53, forwarding to the machine's resolver) answers dig, Python and
# Go lookups once resolv.conf points at it.
set -u
fail=0
apk add -q unbound bind-tools python3 go >/dev/null 2>&1 || { echo "FAIL: apk add"; exit 1; }
is_ip() { printf '%s' "$1" | grep -Eq '^([0-9]+[.]){3}[0-9]+$|^[0-9a-fA-F]*:[0-9a-fA-F:]+$'; }
upstream=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
cat > /tmp/unbound.conf <<CONF
server:
  interface: 127.0.0.1
  access-control: 127.0.0.0/8 allow
  do-daemonize: no
  username: ""
  chroot: ""
  use-syslog: no
  do-ip6: no
  verbosity: 0
forward-zone:
  name: "."
  forward-addr: $upstream
CONF
unbound -d -c /tmp/unbound.conf &
sleep 1
answer=$(dig +short +time=3 +tries=2 @127.0.0.1 example.com A | head -1)
is_ip "$answer" && echo "PASS: dig @127.0.0.1 example.com -> $answer" || { echo "FAIL: dig @127.0.0.1: $answer"; fail=1; }

cp /etc/resolv.conf /tmp/resolv.conf.orig
echo "nameserver 127.0.0.1" > /etc/resolv.conf
answer=$(dig +short +time=3 +tries=2 example.org A | head -1)
is_ip "$answer" && echo "PASS: dig via resolv.conf -> $answer" || { echo "FAIL: dig via resolv.conf: $answer"; fail=1; }
answer=$(python3 -c 'import socket; print(socket.getaddrinfo("example.net", 80, socket.AF_INET)[0][4][0])' 2>&1)
is_ip "$answer" && echo "PASS: Python getaddrinfo -> $answer" || { echo "FAIL: Python getaddrinfo: $(echo "$answer" | tail -1)"; fail=1; }
cat > /tmp/lookup.go <<'GO'
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	r := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.edu")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println(addrs[0])
}
GO
answer=$(cd /tmp && GOCACHE=/tmp/gocache go run lookup.go 2>&1)
is_ip "$answer" && echo "PASS: Go resolver -> $answer" || { echo "FAIL: Go resolver: $(echo "$answer" | head -1)"; fail=1; }
cp /tmp/resolv.conf.orig /etc/resolv.conf

[ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$fail"
