"""UDP between sockets inside one machine, run inside the guest.

Each check sends datagrams from a client to an echo server inside the same
machine and expects every reply back. The server is event-driven (selectors:
epoll on Linux), as DNS stubs, statsd mocks and QUIC servers are; clients use
both connected and unconnected sockets. Prints one PASS/FAIL line per check
and exits non-zero on any failure.

    python3 udp_check.py serve ADDR PORT         # echo server, forever
    python3 udp_check.py ask ADDR PORT [connect]  # one round of 5 datagrams
    python3 udp_check.py dns SERVER [connect]     # an A query to SERVER:53
"""

import selectors
import socket
import sys
import time


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve(addr, port):
    sock = socket.socket(family(addr), socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family(addr) == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((addr, port))
    sock.setblocking(False)
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)
    print(f"serving {addr}:{port} with {type(sel).__name__}", flush=True)
    while True:
        for _ in sel.select():
            while True:
                try:
                    data, peer = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                sock.sendto(b"echo:" + data, peer)


def ask(addr, port, connect):
    sock = socket.socket(family(addr), socket.SOCK_DGRAM)
    sock.settimeout(2)
    got = 0
    try:
        if connect:
            sock.connect((addr, port))
        for i in range(5):
            msg = f"ping{i}".encode()
            if connect:
                sock.send(msg)
            else:
                sock.sendto(msg, (addr, port))
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            got += data == b"echo:" + msg
    except OSError as err:
        print(f"  {addr}:{port}: {err}", flush=True)
    return got


def dns(server, connect):
    """Send one A query for example.com and return the answer count."""
    query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
    sock = socket.socket(family(server), socket.SOCK_DGRAM)
    sock.settimeout(3)
    for _ in range(3):
        try:
            if connect:
                sock.connect((server, 53))
                sock.send(query)
            else:
                sock.sendto(query, (server, 53))
            data = sock.recv(4096)
        except OSError:
            continue
        if data[:2] == b"\x12\x34":
            return int.from_bytes(data[6:8], "big")
    return -1


if __name__ == "__main__":
    if sys.argv[1] == "dns":
        connect = len(sys.argv) > 3 and sys.argv[3] == "connect"
        answers = dns(sys.argv[2], connect)
        mode = "connected" if connect else "unconnected"
        verdict = "PASS" if answers > 0 else "FAIL"
        print(f"{verdict}: {mode} DNS query to {sys.argv[2]}:53: {answers} answers", flush=True)
        sys.exit(0 if answers > 0 else 1)
    if sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]))
    else:
        addr, port = sys.argv[2], int(sys.argv[3])
        connect = len(sys.argv) > 4 and sys.argv[4] == "connect"
        start = time.monotonic()
        got = ask(addr, port, connect)
        ms = (time.monotonic() - start) * 1000
        mode = "connected" if connect else "unconnected"
        verdict = "PASS" if got == 5 else "FAIL"
        print(f"{verdict}: {mode} client -> {addr}:{port}: {got}/5 replies in {ms:.0f} ms", flush=True)
        sys.exit(0 if got == 5 else 1)
