#!/usr/bin/env python3
"""exec/interactive over a real machine: argument vector and `tty=false` pipes.

Run against a dedicated local serve:

    python3 tests/test_api_exec_interactive.py URL [IMAGE]

Creates one small machine (bare, or from IMAGE to cover image machines, which run
the command in a container), checks the endpoint, and deletes the machine. The
WebSocket client is the few dozen lines of RFC 6455 this needs, so the test has no
dependencies.

`tty=false` must be a reliable byte pipe in both directions: a large or bursty
stdin arrives intact (a PTY's line discipline and the guest agent's unpaced write
to it lost most of it), and input reaches the command at once rather than at the
next tick of the session loop's poll.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class WebSocket:
    """A minimal client: binary and text frames, masking, close."""

    def __init__(self, url, path):
        parts = urllib.parse.urlsplit(url)
        self.sock = socket.create_connection((parts.hostname, parts.port), timeout=30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f'GET {path} HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\n'
            f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        self.buffer = b''
        head = self._until(b'\r\n\r\n')
        status = head.split(b'\r\n')[0]
        assert b' 101 ' in status, head
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        assert accept.encode() in head, head

    def _until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(65536)
            assert chunk, 'connection closed during the handshake'
            self.buffer += chunk
        head, _, self.buffer = self.buffer.partition(marker)
        return head + marker

    def _exactly(self, count):
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError('connection closed')
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def _send(self, opcode, payload):
        header = bytes([0x80 | opcode])
        if len(payload) < 126:
            header += bytes([0x80 | len(payload)])
        elif len(payload) < 65536:
            header += bytes([0x80 | 126]) + struct.pack('>H', len(payload))
        else:
            header += bytes([0x80 | 127]) + struct.pack('>Q', len(payload))
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_binary(self, data):
        self._send(2, data)

    def close(self):
        try:
            self._send(8, b'')
        except OSError:
            pass
        self.sock.close()

    def receive(self):
        """The next message: ('binary', bytes), ('text', str), or ('close', None)."""
        message = b''
        kind = None
        while True:
            first, second = self._exactly(2)
            opcode, final = first & 0x0F, first & 0x80
            length = second & 0x7F
            if length == 126:
                length = struct.unpack('>H', self._exactly(2))[0]
            elif length == 127:
                length = struct.unpack('>Q', self._exactly(8))[0]
            payload = self._exactly(length)
            if opcode == 8:
                return 'close', None
            if opcode in (9, 10):
                continue
            if opcode in (1, 2):
                kind = 'text' if opcode == 1 else 'binary'
            message += payload
            if final:
                return kind, message.decode() if kind == 'text' else message


def session(base, machine, **query):
    parameters = []
    for name, value in query.items():
        for item in value if isinstance(value, list) else [value]:
            parameters.append((name, item))
    path = f'/api/v1/machines/{machine}/exec/interactive?' + urllib.parse.urlencode(parameters)
    return WebSocket(base, path)


def transcript(ws):
    """Everything up to the exit frame: stdout bytes, stderr text, exit code."""
    stdout, stderr, code = b'', '', None
    while True:
        kind, message = ws.receive()
        if kind == 'binary':
            stdout += message
        elif kind == 'text':
            frame = json.loads(message)
            if frame['type'] == 'stderr':
                stderr += frame['data']
            elif frame['type'] == 'exit':
                code = frame['code']
        else:
            return stdout, stderr, code


def receive(ws, count):
    data = b''
    while len(data) < count:
        kind, message = ws.receive()
        assert kind == 'binary', (kind, message)
        data += message
    return data


def pattern(length, seed):
    return bytes((seed + i) % 251 for i in range(length))


def main():
    base = sys.argv[1].rstrip('/')
    image = sys.argv[2] if len(sys.argv) > 2 else None
    api = base + '/api/v1/machines'

    def call(method, path, body=None):
        request = urllib.request.Request(api + path, method=method,
            data=json.dumps(body or {}).encode() if method == 'POST' else None,
            headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b'{}')

    name = 'exec-ws-' + uuid.uuid4().hex[:10]
    spec = {'name': name, 'cpus': 1, 'memoryMb': 512, 'storageGb': 2, 'overlayGb': 1}
    if image:
        spec.update({'image': image, 'network': True, 'cmd': ['sleep', 'infinity']})
    try:
        status, result = call('POST', '', spec)
        assert status == 200, result
        status, result = call('POST', '/' + name + '/start')
        assert status == 200, result

        # The argument vector reaches the program, an empty argument included.
        ws = session(base, name, tty='false', cmd='/bin/sh',
                     arg=['-c', 'printf %s "$1|$2"', 'x', 'one two', ''])
        stdout, stderr, code = transcript(ws)
        assert (stdout, stderr, code) == (b'one two|', '', 0), (stdout, stderr, code)
        print('PASS argument vector', flush=True)

        # Standard error stays out of the byte stream.
        ws = session(base, name, tty='false', cmd='/bin/sh',
                     arg=['-c', 'printf out; printf err >&2; exit 7'])
        stdout, stderr, code = transcript(ws)
        assert (stdout, stderr, code) == (b'out', 'err', 7), (stdout, stderr, code)
        print('PASS stderr is its own frame, exit code reported', flush=True)

        ws = session(base, name, tty='false', cmd='/bin/cat')
        try:
            # The messages a PTY delivered a fraction of.
            large = pattern(256 * 1024, 7)
            ws.send_binary(large)
            assert receive(ws, len(large)) == large
            burst = b''
            for i in range(50):
                piece = pattern(1000, i)
                ws.send_binary(piece)
                burst += piece
            assert receive(ws, len(burst)) == burst
            every_byte = bytes(range(256))
            ws.send_binary(every_byte)
            assert receive(ws, 256) == every_byte
            print('PASS stdin arrives intact: 256 KiB, 50 x 1000 B, every byte value', flush=True)

            # Input is forwarded at once. Jittered gaps keep any timer from
            # phase-locking with the session loop's poll.
            trips = []
            for i in range(30):
                time.sleep(0.02 + ((i * 37) % 61) / 1000)
                message = pattern(100, i)
                began = time.perf_counter()
                ws.send_binary(message)
                assert receive(ws, len(message)) == message
                trips.append((time.perf_counter() - began) * 1000)
            trips.sort()
            print(f'idle echo round trip over 30 messages: min {trips[0]:.1f} ms, '
                  f'median {trips[15]:.1f} ms, p90 {trips[27]:.1f} ms, max {trips[29]:.1f} ms',
                  flush=True)
            assert trips[15] < 40, f'median {trips[15]:.1f} ms: input waits for the poll timeout'
            print('PASS prompt echo without any tick from the guest', flush=True)
        finally:
            ws.close()

        # A terminal session is unchanged: cooked mode echoes what it is sent.
        ws = session(base, name, cmd='/bin/cat')
        try:
            ws.send_binary(b'hi\n')
            assert receive(ws, 8) == b'hi\r\nhi\r\n'
            print('PASS tty=true is a terminal', flush=True)
        finally:
            ws.close()
    finally:
        status, result = call('DELETE', '/' + name + '?force=true')
        assert status == 200, result


if __name__ == '__main__':
    main()
