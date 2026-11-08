#!/bin/sh
# Inside a TSI machine (Alpine): UDP between sockets of one machine, across a
# container-style network namespace, and outbound UDP to the outside.
set -u
fail=0
apk add -q python3 iproute2 >/dev/null 2>&1 || { echo "FAIL: apk add python3 iproute2"; exit 1; }
PY="python3 /t/udp_check.py"
check() { "$@" || fail=1; }
own=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
echo "machine address: ${own:-none}"

# Echo servers on the machine.
$PY serve 0.0.0.0 7001 &
$PY serve :: 7001 &
sleep 1
for addr in 127.0.0.1 ::1 $own; do
    check $PY ask "$addr" 7001
    check $PY ask "$addr" 7001 connect
done

# A container-style network namespace on a veth pair, default route via the machine.
if ip netns add tsiudp 2>/dev/null; then
    ip link add tsiudp0 type veth peer name tsiudp1
    ip link set tsiudp1 netns tsiudp
    ip addr add 10.77.0.1/24 dev tsiudp0
    ip link set tsiudp0 up
    ip netns exec tsiudp sh -c 'ip link set lo up; ip addr add 10.77.0.2/24 dev tsiudp1; ip link set tsiudp1 up; ip route add default via 10.77.0.1'
    # container -> machine: its gateway address, connected and not, and the
    # machine's own address. A reply to that one leaves from the gateway
    # address (the source the route picks, as on any Linux host), so only an
    # unconnected client, which takes replies from any source, sees it.
    check ip netns exec tsiudp $PY ask 10.77.0.1 7001
    check ip netns exec tsiudp $PY ask 10.77.0.1 7001 connect
    [ -n "$own" ] && check ip netns exec tsiudp $PY ask "$own" 7001
    # machine -> container, and loopback inside the container
    ip netns exec tsiudp $PY serve 0.0.0.0 7002 &
    sleep 1
    check $PY ask 10.77.0.2 7002
    check $PY ask 10.77.0.2 7002 connect
    check ip netns exec tsiudp $PY ask 127.0.0.1 7002
    check ip netns exec tsiudp $PY ask 127.0.0.1 7002 connect
else
    echo "FAIL: could not create a network namespace"
    fail=1
fi

# Outbound UDP to the outside still goes through the host.
ns=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
check $PY dns "$ns"
check $PY dns "$ns" connect

[ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$fail"
