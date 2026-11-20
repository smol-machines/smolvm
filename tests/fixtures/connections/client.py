#!/usr/bin/env python3
"""Guest-side connection probe for tests/test_connections.sh (stdlib only).

    client.py hold  HOST PORT[-LAST] COUNT HOLD_SECONDS
        Open COUNT TCP connections at once, keep them all open, then send one
        byte on each and wait for its echo, which proves every flow reaches
        the host end to end. Prints one JSON line.
    client.py churn HOST PORT[-LAST] TOTAL CONCURRENCY
        Open and close TOTAL connections, CONCURRENCY at a time, each one
        echoing a byte before it closes. Prints one JSON line.
    client.py http HOST PORT TOTAL CONCURRENCY
        TOTAL short HTTP/1.1 GETs to a real server, CONCURRENCY at a time
        (1 = one after another), each read to EOF and checked for a complete
        response with a status below 400. Half ask the server to close first (Connection: close);
        the other half half-close their own side right after the request. A
        reset or a short body fails. Prints one JSON line.

Connections rotate over the ports so a long churn is not capped by the
TIME-WAIT tuples of a single destination. $INFLIGHT bounds the connects in
flight at once (a macOS host's listen queue holds 128); $RATE, when set,
caps new connections per second in a churn (a macOS host keeps each closed
connection's local port in TIME-WAIT for 30 s out of a range of 16384).
"""
import collections
import errno
import json
import os
import resource
import selectors
import socket
import sys
import time

try:
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
except (ValueError, OSError):
    pass

mode, host, port_spec = sys.argv[1], sys.argv[2], sys.argv[3]
first, _, last = port_spec.partition("-")
ports = list(range(int(first), int(last or first) + 1))
inflight_cap = int(os.environ.get("INFLIGHT", "2048"))
rate = float(os.environ.get("RATE", "0"))
counter = 0
result = collections.Counter()


def errname(code):
    return errno.errorcode.get(code, str(code))


def start():
    global counter
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    counter += 1
    return sock, sock.connect_ex((host, ports[counter % len(ports)]))


def hold(count, seconds):
    selector = selectors.DefaultSelector()
    socks = []
    pending = 0
    began = time.time()

    def settle(timeout):
        nonlocal pending
        for key, _ in selector.select(timeout=timeout):
            err = key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            result["connected" if err == 0 else "connect:" + errname(err)] += 1
            selector.unregister(key.fileobj)
            pending -= 1

    for _ in range(count):
        try:
            sock, rc = start()
        except OSError as e:
            result["socket:" + errname(e.errno)] += 1
            continue
        socks.append(sock)
        if rc == 0:
            result["connected"] += 1
        elif rc in (errno.EINPROGRESS, errno.EAGAIN):
            selector.register(sock, selectors.EVENT_WRITE)
            pending += 1
        else:
            result["connect:" + errname(rc)] += 1
        while pending >= inflight_cap:
            settle(1)
    deadline = time.time() + 120
    while pending and time.time() < deadline:
        settle(1)
    result["connect_timeout"] += pending
    connect_seconds = time.time() - began

    time.sleep(seconds)
    echo = selectors.DefaultSelector()
    for sock in socks:
        try:
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                sock.send(b"x")
                echo.register(sock, selectors.EVENT_READ)
        except OSError as e:
            result["send:" + errname(e.errno)] += 1
    waiting = len(echo.get_map())
    deadline = time.time() + 120
    while waiting and time.time() < deadline:
        for key, _ in echo.select(timeout=1):
            try:
                data = key.fileobj.recv(16)
            except OSError as e:
                data = b""
                result["recv:" + errname(e.errno)] += 1
            result["echoed" if data == b"x" else "no_echo"] += 1
            echo.unregister(key.fileobj)
            waiting -= 1
    result["echo_timeout"] += waiting
    for sock in socks:
        sock.close()
    return {"connect_seconds": round(connect_seconds, 2)}


def churn(total, concurrency):
    selector = selectors.DefaultSelector()
    started = inflight = 0
    began = time.time()
    while started < total or inflight:
        while started < total and inflight < concurrency:
            if rate and started >= rate * (time.time() - began):
                break
            started += 1
            try:
                sock, rc = start()
            except OSError as e:
                result["socket:" + errname(e.errno)] += 1
                continue
            if rc in (0, errno.EINPROGRESS, errno.EAGAIN):
                selector.register(sock, selectors.EVENT_WRITE, "connecting")
                inflight += 1
            else:
                result["connect:" + errname(rc)] += 1
                sock.close()
        events = selector.select(timeout=0.05 if rate and inflight == 0 else 30)
        if not events and rate and inflight == 0:
            continue
        if not events:
            result["stalled"] += inflight
            break
        for key, _ in events:
            sock = key.fileobj
            if key.data == "connecting":
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    try:
                        sock.send(b"x")
                        selector.modify(sock, selectors.EVENT_READ, "echo")
                        continue
                    except OSError as e:
                        result["send:" + errname(e.errno)] += 1
                else:
                    result["connect:" + errname(err)] += 1
            else:
                try:
                    data = sock.recv(16)
                except OSError as e:
                    data = b""
                    result["recv:" + errname(e.errno)] += 1
                result["echoed" if data == b"x" else "no_echo"] += 1
            selector.unregister(sock)
            sock.close()
            inflight -= 1
    seconds = time.time() - began
    return {"seconds": round(seconds, 1), "per_second": round(total / max(seconds, 0.001))}


def http(total, concurrency):
    import concurrent.futures
    import re

    host_port = int(ports[0])

    def one(index):
        half_close = index % 2 == 1
        request = (
            "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: smolvm-test\r\n"
            "Connection: close\r\n\r\n" % host
        ).encode()
        try:
            sock = socket.create_connection((host, host_port), timeout=20)
        except OSError as e:
            return "connect:" + (errname(e.errno) if e.errno else type(e).__name__)
        try:
            sock.sendall(request)
            if half_close:
                sock.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError as e:
            return "recv:" + (errname(e.errno) if e.errno else type(e).__name__)
        finally:
            sock.close()
        head, _, body = data.partition(b"\r\n\r\n")
        status = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        if not status or int(status.group(1)) >= 400:
            return "status:" + (head[:12].decode(errors="replace") or "empty")
        length = re.search(rb"(?im)^content-length:\s*(\d+)", head)
        if length and len(body) != int(length.group(1)):
            return "short_body"
        return "ok_half_closed" if half_close else "ok_server_closed"

    began = time.time()
    with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
        for outcome in pool.map(one, range(total)):
            result[outcome] += 1
    return {"seconds": round(time.time() - began, 1)}


if mode == "hold":
    extra = hold(int(sys.argv[4]), float(sys.argv[5]))
elif mode == "http":
    extra = http(int(sys.argv[4]), int(sys.argv[5]))
else:
    extra = churn(int(sys.argv[4]), int(sys.argv[5]))
print(json.dumps({"mode": mode, "result": dict(result), **extra}), flush=True)
