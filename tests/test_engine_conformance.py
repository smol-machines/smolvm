#!/usr/bin/env python3
"""Docker API conformance: replay real client traffic against `smolvm engine`.

The fixtures in tests/fixtures/engine/ are the requests the docker CLI,
Docker Compose, Testcontainers (Node) and the Dev Containers CLI sent to the
engine, each with the status and JSON answer it got, recorded with
`SMOLVM_ENGINE_RECORD=<file> smolvm engine serve`. This test sends the same
requests, in the same order, to an engine and checks that every answer has
the recorded status and the recorded shape: every field the recorded answer
had is there, with the same JSON type. Values (ids, times, addresses) are not
compared; ids the engine hands out are carried into the requests that use
them.

Requests that stream (attach, exec, logs, events, wait) run alongside the
rest, as the clients run them, and only their status is checked.

    python3 tests/test_engine_conformance.py SOCKET [FIXTURE...]

SOCKET is the engine's Unix socket. The images the fixtures use (alpine,
nginx:alpine, postgres:16-alpine, python:3.12-alpine, node:22-alpine,
testcontainers/ryuk:0.14.0) are pulled on the way, as the clients pulled them.

To re-record a fixture: run the engine with SMOLVM_ENGINE_RECORD set, run the
client, then replace host paths with the placeholders below.
"""
import io
import json
import os
import re
import socket
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "engine")


class Conn:
    """One HTTP/1.1 exchange over the engine's Unix socket."""

    def __init__(self, path, timeout=600):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.buf = b""

    def send(self, method, target, body=b"", headers=None):
        lines = [f"{method} {target} HTTP/1.1", "Host: docker"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if body or method in ("POST", "PUT"):
            lines.append(f"Content-Length: {len(body)}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError
        self.buf += chunk

    def head(self):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        raw, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = raw.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        return status, headers

    def body(self, headers):
        if "content-length" in headers:
            n = int(headers["content-length"])
            while len(self.buf) < n:
                self._fill()
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        if headers.get("transfer-encoding") == "chunked":
            out = b""
            while True:
                while b"\r\n" not in self.buf:
                    self._fill()
                size_line, self.buf = self.buf.split(b"\r\n", 1)
                size = int(size_line.split(b";")[0], 16)
                while len(self.buf) < size + 2:
                    self._fill()
                out += self.buf[:size]
                self.buf = self.buf[size + 2 :]
                if size == 0:
                    return out
        return b""

    def drain(self):
        try:
            while True:
                self._fill()
        except (EOFError, OSError):
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def kind(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    return type(v).__name__


def shape_errors(recorded, actual, where="$"):
    """Fields of `recorded` that `actual` lacks or carries with another type."""
    errors = []
    if recorded is None:
        return errors
    if kind(recorded) != kind(actual):
        return [f"{where}: recorded {kind(recorded)}, got {kind(actual)}"]
    if isinstance(recorded, dict):
        for k, v in recorded.items():
            # Maps keyed by ids or names (labels, networks, ports) have
            # data-dependent keys; their values are checked by the type rule.
            if k not in actual:
                if re.fullmatch(r"[0-9a-f]{64}", k) or "/" in k or "." in k:
                    continue
                errors.append(f"{where}.{k}: missing")
                continue
            errors.extend(shape_errors(v, actual[k], f"{where}.{k}"))
    elif isinstance(recorded, list) and recorded and actual:
        errors.extend(shape_errors(recorded[0], actual[0], f"{where}[0]"))
    return errors


def tiny_tar(name="file.txt", data=b"conformance\n"):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


class Replay:
    def __init__(self, socket_path, workspace):
        self.socket = socket_path
        self.ids = {}
        self.values = {
            "{{SOCKET}}": socket_path,
            "{{WORKSPACE}}": workspace,
            "{{PROJECT}}": workspace,
            "{{HOME}}": os.path.dirname(workspace),
            "{{ENGINE_ROOT}}": workspace,
        }
        self.failures = []
        self.threads = []

    def substitute(self, text, encoded=False):
        for k, v in self.values.items():
            if encoded:
                text = text.replace(urllib.parse.quote(k, safe=""), urllib.parse.quote(v, safe=""))
            text = text.replace(k, v)
        for old, new in self.ids.items():
            text = text.replace(old, new)
        return text

    def learn(self, recorded, actual):
        if isinstance(recorded, dict) and isinstance(actual, dict):
            old, new = recorded.get("Id"), actual.get("Id")
            if isinstance(old, str) and isinstance(new, str) and old != new:
                self.ids[old] = new
                if len(old) >= 12 and len(new) >= 12:
                    self.ids[old[:12]] = new[:12]

    def request(self, r, upload_name="file.txt"):
        target = self.substitute(r["path"])
        query = self.substitute(r["query"], encoded=True)
        if query:
            target += "?" + query
        headers = {}
        body = b""
        if r["method"] == "PUT" and r["path"].endswith("/archive"):
            body = tiny_tar(upload_name)
            headers["Content-Type"] = "application/x-tar"
        elif r.get("body") is not None:
            body = self.substitute(json.dumps(r["body"])).encode()
            headers["Content-Type"] = "application/json"
        if r.get("upgrade"):
            headers["Connection"] = "Upgrade"
            headers["Upgrade"] = "tcp"
        return r["method"], target, body, headers

    def stream(self, index, r):
        method, target, body, headers = self.request(r)
        conn = Conn(self.socket, timeout=90)
        try:
            conn.send(method, target, body, headers)
            status, _ = conn.head()
            if status != r["status"]:
                self.failures.append(f"#{index} {method} {r['path']}: status {status}, recorded {r['status']}")
            if r.get("upgrade"):
                # The client's input ends; output runs until the process does.
                conn.sock.shutdown(socket.SHUT_WR)
            conn.drain()
        except (socket.timeout, OSError, EOFError):
            pass
        finally:
            conn.close()

    @staticmethod
    def upload_name(rows, index):
        """The file an archive upload carried: the one the client asks for
        next on the same container (uploads are not recorded byte for byte)."""
        container = rows[index]["path"].split("/archive")[0]
        for later in rows[index + 1 :]:
            if later["path"].startswith(container) and later["path"].endswith("/archive"):
                q = urllib.parse.parse_qs(later["query"]).get("path", [""])[0]
                if q:
                    return os.path.basename(q.rstrip("/")) or "file.txt"
        return "file.txt"

    def run(self, rows):
        waits = []
        for index, r in enumerate(rows):
            if r.get("streaming") or r.get("upgrade"):
                t = threading.Thread(target=self.stream, args=(index, r), daemon=True)
                t.start()
                if r["path"].endswith("/wait"):
                    waits.append(t)
                else:
                    self.threads.append(t)
                # Give the stream a moment to open, as the client's next
                # request (a start after an attach) relies on it.
                time.sleep(0.2)
                continue
            if r["method"] == "DELETE" or "prune" in r["path"]:
                # A client that waited for a container did so before it went
                # on to remove things (`docker run --rm`, then `volume rm`).
                for t in waits:
                    t.join(timeout=15)
                waits = [t for t in waits if t.is_alive()]
            name = self.upload_name(rows, index) if r["method"] == "PUT" else "file.txt"
            method, target, body, headers = self.request(r, name)
            if os.environ.get("VERBOSE"):
                print(f"  #{index} {method} {target[:100]}", flush=True)
            conn = Conn(self.socket, timeout=180)
            try:
                conn.send(method, target, body, headers)
                status, rh = conn.head()
                raw = b"" if method == "HEAD" or status in (204, 304) else conn.body(rh)
            except (socket.timeout, OSError, EOFError) as e:
                self.failures.append(f"#{index} {method} {r['path']}: no answer ({e})")
                continue
            finally:
                conn.close()
            if status != r["status"]:
                self.failures.append(
                    f"#{index} {method} {r['path']}: status {status}, recorded {r['status']}: {raw[:200]!r}"
                )
                continue
            if r.get("response") is not None and "json" in rh.get("content-type", ""):
                try:
                    actual = json.loads(raw)
                except ValueError:
                    self.failures.append(f"#{index} {method} {r['path']}: answer is not JSON")
                    continue
                self.learn(r["response"], actual)
                for e in shape_errors(r["response"], actual):
                    self.failures.append(f"#{index} {method} {r['path']}: {e}")
        for t in self.threads + waits:
            t.join(timeout=120)


def cleanup(socket_path, ids):
    for new in set(ids.values()):
        if len(new) != 64:
            continue
        for path in (f"/containers/{new}?force=1&v=1", f"/networks/{new}"):
            conn = Conn(socket_path, timeout=60)
            try:
                conn.send("DELETE", path)
                conn.head()
            except (OSError, EOFError):
                pass
            finally:
                conn.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    socket_path = sys.argv[1]
    names = sys.argv[2:] or sorted(f for f in os.listdir(FIXTURES) if f.endswith(".jsonl"))
    failed = 0
    for name in names:
        path = name if os.path.sep in name else os.path.join(FIXTURES, name)
        rows = [json.loads(l) for l in open(path) if l.strip()]
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            os.makedirs(os.path.join(workspace, ".devcontainer"))
            with open(os.path.join(workspace, "marker.txt"), "w") as f:
                f.write("hello-from-host\n")
            with open(os.path.join(workspace, ".devcontainer", "devcontainer.json"), "w") as f:
                f.write('{"image": "node:22-alpine"}\n')
            replay = Replay(socket_path, workspace)
            started = time.time()
            try:
                replay.run(rows)
            finally:
                cleanup(socket_path, replay.ids)
            took = time.time() - started
        if replay.failures:
            failed += 1
            print(f"FAIL {os.path.basename(path)}: {len(rows)} requests, {len(replay.failures)} mismatches ({took:.1f}s)")
            for f in replay.failures[:30]:
                print("   ", f)
        else:
            print(f"PASS {os.path.basename(path)}: {len(rows)} requests ({took:.1f}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
