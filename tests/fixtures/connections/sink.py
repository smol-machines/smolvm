#!/usr/bin/env python3
"""Host-side TCP sink for tests/test_connections.sh.

Listens on every port given, echoes whatever a connection sends and holds it
until the peer closes. Prints "ready" once listening. On SIGUSR1 it writes
"open=N peak=N total=N" (connections open now, most open at once, accepted in
all) to the file named by $SINK_REPORT.

    sink.py PORT [PORT...]
"""
import os
import resource
import selectors
import signal
import socket
import sys

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
for wanted in (hard, 1 << 20, 262144, 65536, 24576, 10240):
    if wanted == resource.RLIM_INFINITY:
        continue
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
        break
    except (ValueError, OSError):
        continue

selector = selectors.DefaultSelector()
listeners = set()
for arg in sys.argv[1:]:
    listener = socket.create_server(("0.0.0.0", int(arg)), backlog=65535)
    listener.setblocking(False)
    selector.register(listener, selectors.EVENT_READ)
    listeners.add(listener)

open_now = peak = total = 0


def report(*_):
    with open(os.environ["SINK_REPORT"], "w") as out:
        out.write(f"open={open_now} peak={peak} total={total}\n")


signal.signal(signal.SIGUSR1, report)
print("ready", flush=True)
while True:
    for key, _ in selector.select(timeout=1):
        sock = key.fileobj
        if sock in listeners:
            for _ in range(512):
                try:
                    conn, _ = sock.accept()
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                conn.setblocking(False)
                selector.register(conn, selectors.EVENT_READ)
                open_now += 1
                total += 1
                peak = max(peak, open_now)
            continue
        try:
            data = sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            continue
        except OSError:
            data = b""
        if data:
            try:
                sock.send(data)
            except OSError:
                pass
            continue
        selector.unregister(sock)
        sock.close()
        open_now -= 1
