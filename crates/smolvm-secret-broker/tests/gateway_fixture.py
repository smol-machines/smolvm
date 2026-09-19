#!/usr/bin/env python3
"""Synthetic upstream and credentials, generated INSIDE the test gateway only."""
import http.server
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys

ROOT = Path("/root/gateway-qa")
PUBLIC = Path("/opt/gateway-client")


def setup():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    PUBLIC.mkdir(mode=0o755, exist_ok=True)
    def run(*args):
        subprocess.run(args, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ROOT / "ca.key"),
        "-out", str(PUBLIC / "ca.pem"), "-days", "1", "-subj", "/CN=Gateway QA CA",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ROOT / "server.key"),
        "-out", str(ROOT / "server.csr"), "-subj", "/CN=localhost")
    (ROOT / "extensions").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", str(ROOT / "server.csr"), "-CA", str(PUBLIC / "ca.pem"),
        "-CAkey", str(ROOT / "ca.key"), "-CAcreateserial", "-out", str(ROOT / "server.pem"),
        "-days", "1", "-extfile", str(ROOT / "extensions"))
    secret = secrets.token_hex(32)
    access = secrets.token_hex(32)
    for name, value in {"expected": secret, "access": access, ".env": "EXAMPLE_API_KEY=" + secret + "\n"}.items():
        (ROOT / name).write_text(value)
        (ROOT / name).chmod(0o600)
    (ROOT / "server.key").chmod(0o600)
    run("/usr/local/bin/dotenvx", "encrypt", "--no-native", "--no-armor", "--no-1password", "--no-bitwarden",
        "-f", str(ROOT / ".env"), "-fk", str(ROOT / ".env.keys"))
    assert secret not in (ROOT / ".env").read_text()
    (ROOT / ".env.keys").chmod(0o600)
    (ROOT / "config.json").write_text(json.dumps({
        "listen": None, "unix_socket": "/run/credential-gateway/proxy.sock", "allow_bearer_only": True,
        "certificate": str(ROOT / "server.pem"), "private_key": str(ROOT / "server.key"),
        "upstream_ca": str(PUBLIC / "ca.pem"), "access_token_file": str(ROOT / "access"),
        "grants": [{"host": "localhost", "port": 9443, "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
                    "header": "authorization", "secret_env": "EXAMPLE_API_KEY"}]
    }))
    # These are the ONLY values exported to the desktop, never a real API key.
    (PUBLIC / "client.json").write_text(json.dumps({"access_token": access, "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY"}))
    print("gateway fixture ready; credentials generated inside VM")


def serve():
    expected = (ROOT / "expected").read_text()
    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with (ROOT / "requests").open("a") as log:
                log.write("request\n")
            authorized = self.headers.get("Authorization") == "Bearer " + expected
            payload = b'{"authorized":true}' if authorized else b'{"authorized":false}'
            self.send_response(200 if authorized else 403)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 9443), Upstream)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / "server.pem", ROOT / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    {"setup": setup, "serve": serve}[sys.argv[1]]()
