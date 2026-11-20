#!/bin/sh
# Inside a TSI machine running dockerd (docker:dind): UDP between containers,
# the machine and a published port. /t holds udp_check.py.
set -u
fail=0
IMG=${PY_IMAGE:-python:3.12-alpine}
check() { "$@" || fail=1; }
py() { docker run --rm -v /t:/t "$@"; }
docker pull -q "$IMG" >/dev/null || { echo "FAIL: pull $IMG"; exit 1; }
docker network create tsiudp >/dev/null 2>&1
docker rm -f udps udph >/dev/null 2>&1
docker run -d --name udps --network tsiudp -p 7101:7001/udp -v /t:/t "$IMG" python3 /t/udp_check.py serve 0.0.0.0 7001 >/dev/null
docker run -d --name udph --network host -v /t:/t "$IMG" python3 /t/udp_check.py serve 0.0.0.0 7201 >/dev/null
sleep 2
ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' udps)
gw=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' tsiudp)
echo "container $ip, bridge gateway $gw"
# container -> container by name (Docker's embedded DNS) and by address
check py --network tsiudp "$IMG" python3 /t/udp_check.py ask udps 7001
check py --network tsiudp "$IMG" python3 /t/udp_check.py ask "$ip" 7001 connect
# machine (host network) -> published port on loopback, and -> container address
check py --network host "$IMG" python3 /t/udp_check.py ask 127.0.0.1 7101
check py --network host "$IMG" python3 /t/udp_check.py ask 127.0.0.1 7101 connect
check py --network host "$IMG" python3 /t/udp_check.py ask "$ip" 7001
# container -> a server on the machine, through the bridge gateway
check py --network tsiudp "$IMG" python3 /t/udp_check.py ask "$gw" 7201
check py --network tsiudp "$IMG" python3 /t/udp_check.py ask "$gw" 7201 connect
# outside DNS from a container still works
check py --network tsiudp "$IMG" python3 -c '
import socket, sys
try:
    print("PASS: container lookup ->", socket.getaddrinfo("example.com", 80, socket.AF_INET)[0][4][0])
except OSError as err:
    print("FAIL: container lookup:", err)
    sys.exit(1)
'
docker rm -f udps udph >/dev/null 2>&1
docker network rm tsiudp >/dev/null 2>&1
[ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$fail"
