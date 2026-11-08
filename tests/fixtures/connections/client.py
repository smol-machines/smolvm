#!/usr/bin/env python3
"""Guest-side connection probe for tests/test_connections.sh (stdlib only).

    client.py hold  HOST PORT[-LAST] COUNT HOLD_SECONDS
        Open COUNT TCP connections at once, keep them all open, then send one
        byte on each and wait for its echo, which proves every flow reaches
        the host end to end. Prints one JSON line.
    client.py churn HOST PORT[-LAST] TOTAL CONCURRENCY
        Open and close TOTAL connections, CONCURRENCY at a time, each one
        echoing a byte before it closes. Prints one JSON line.

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


if mode == "hold":
    extra = hold(int(sys.argv[4]), float(sys.argv[5]))
else:
    extra = churn(int(sys.argv[4]), int(sys.argv[5]))
print(json.dumps({"mode": mode, "result": dict(result), **extra}), flush=True)
