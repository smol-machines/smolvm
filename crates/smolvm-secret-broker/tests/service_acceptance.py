#!/usr/bin/env python3
"""Scoped root-only Linux service-isolation acceptance. Synthetic credentials.

Creates one transient DynamicUser systemd service, stops it in finally, and
removes only its /run fixture directory. Does not install users or services.
"""
import argparse
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

from acceptance import run, write_private, PLACEHOLDER


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--observer-uid", type=int, required=True)
    parser.add_argument("--observer-gid", type=int, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "this test requires root for transient service administration"
    assert args.observer_uid != 0
    unit = "smol-broker-qa-" + secrets.token_hex(6) + ".service"
    with tempfile.TemporaryDirectory(prefix="smol-broker-service-qa-", dir="/run") as directory:
        root = Path(directory)
        root.chmod(0o755)
        private = root / "private"
        private.mkdir(mode=0o700)
        binary = root / "broker"
        shutil.copyfile(args.broker, binary)
        binary.chmod(0o755)
        ca, ca_key = private / "ca.pem", private / "ca.key"
        key, csr, leaf = private / "key.pem", private / "leaf.csr", private / "leaf.pem"
        extensions = private / "extensions"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
            "-out", str(ca), "-days", "1", "-subj", "/CN=Smol service QA CA", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
        extensions.write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(leaf), "-days", "1", "-extfile", str(extensions))
        secret, token = secrets.token_hex(24), secrets.token_hex(24)
        write_private(private / "secret", secret)
        write_private(private / "access", token)
        seen = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                seen.append(self.headers.get("Authorization") == "Bearer " + secret)
                payload = b'{"authorized":true}'
                self.send_response(200 if seen[-1] else 403)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(leaf, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        credential_dir = Path("/run") / unit.removesuffix(".service")
        config = private / "config"
        write_private(config, json.dumps({
            "listen": "127.0.0.1:0", "certificate": str(credential_dir / "leaf"),
            "private_key": str(credential_dir / "key"), "access_token_file": str(credential_dir / "access"),
            "upstream_ca": str(credential_dir / "ca"),
            "grants": [{"host": "localhost", "port": server.server_port, "header": "authorization",
                        "placeholder": PLACEHOLDER, "secret_file": str(credential_dir / "secret")}],
        }))
        log = private / "service.log"
        command = ["systemd-run", "--quiet", "--collect", "--unit=" + unit]
        for prop in ["DynamicUser=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                     "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes",
                     "RestrictSUIDSGID=yes", "CapabilityBoundingSet=", "LimitCORE=0", "UMask=0077",
                     "MemoryMax=256M", "TasksMax=96", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                     "RuntimeDirectory=" + unit.removesuffix(".service"), "RuntimeDirectoryMode=0700",
                     "StandardOutput=append:" + str(log), "StandardError=append:" + str(log)]:
            command.extend(["--property", prop])
        for name, source in {"config": config, "key": key, "leaf": leaf, "ca": ca,
                             "access": private / "access", "secret": private / "secret"}.items():
            command.extend(["--property", f"LoadCredential={name}:{source}"])
        command.extend(["/bin/sh", "-c", 'set -eu; for item in config key leaf ca access secret; do install -m 600 "$CREDENTIALS_DIRECTORY/$item" "$RUNTIME_DIRECTORY/$item"; done; exec "$1" "$RUNTIME_DIRECTORY/config"', "_", str(binary)])
        started = False
        try:
            run(*command)
            started = True
            deadline = time.monotonic() + 15
            port = None
            while time.monotonic() < deadline:
                lines = log.read_text().splitlines() if log.exists() else []
                ready = [line for line in lines if line.startswith("credential broker listening on ")]
                if ready:
                    port = int(ready[-1].rsplit(":", 1)[1])
                    break
                time.sleep(0.1)
            assert port, "isolated service failed to become ready: " + log.read_text()
            pid = int(run("systemctl", "show", unit, "-p", "MainPID", "--value").stdout)
            uid_line = next(line for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:"))
            service_uid = int(uid_line.split()[1])
            assert service_uid not in (0, args.observer_uid)
            for path in [private / "secret", credential_dir / "secret", credential_dir / "key", Path(f"/proc/{pid}/environ")]:
                denied = subprocess.run(["setpriv", "--reuid", str(args.observer_uid), "--regid", str(args.observer_gid),
                                         "--clear-groups", "test", "-r", str(path)], check=False)
                assert denied.returncode == 1, "unprivileged observer can read protected credential state"
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=ssl.create_default_context(cafile=ca), timeout=10)
            connection.set_tunnel("localhost", server.server_port, headers={"Proxy-Authorization": "Basic " + base64.b64encode(("smol:" + token).encode()).decode()})
            connection.request("GET", "/", headers={"Authorization": "Bearer " + PLACEHOLDER})
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b'{"authorized":true}'
            connection.close()
            assert seen == [True]
            print(json.dumps({"isolated_service": "passed", "service_uid": service_uid,
                              "observer_uid": args.observer_uid, "private_source_and_runtime_files": "denied",
                              "process_environment": "denied", "https_substitution": "passed",
                              "caveat": "does not protect against root or an actor allowed to use sudo"}, indent=2))
        finally:
            if started:
                stopped = subprocess.run(["systemctl", "stop", unit], capture_output=True)
                assert stopped.returncode in (0, 5), "failed to stop owned service"
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
