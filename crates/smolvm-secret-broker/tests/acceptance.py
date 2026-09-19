#!/usr/bin/env python3
"""Offline HTTPS acceptance; optional real Smol VM, synthetic credentials only.

python3 acceptance.py --broker /path/to/smolvm-secret-broker [--smolvm /path/to/smolvm]
Requires openssl; no third-party Python modules, accounts, or public APIs.
"""
import argparse
import base64
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import ssl
import subprocess
import tempfile
import threading

PLACEHOLDER = "SMOL_PLACEHOLDER_ACCEPTANCE_TOKEN"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=180, **kwargs)


def write_private(path, text):
    path.write_text(text)
    path.chmod(0o600)


def stop(process):
    # Every broker/wrapper is started in its own session. Stop the complete
    # owned group, including the child of `dotenvx run`, never other brokers.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--smolvm")
    parser.add_argument("--backend", choices=["virtio-net", "tsi"], default="virtio-net")
    parser.add_argument("--dotenvx", help="Test encrypted dotenvx host-environment credentials")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="smol-broker-qa-") as directory:
        root = Path(directory)
        public = root / "public"
        public.mkdir(mode=0o755)
        # Only the public cert is ever copied/mounted into the VM.
        cert, key = public / "ca.pem", root / "key.pem"
        leaf, csr, extensions = root / "leaf.pem", root / "leaf.csr", root / "extensions"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "ca.key"),
            "-out", str(cert), "-days", "1", "-subj", "/CN=Smol synthetic test CA",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(csr), "-subj", "/CN=localhost")
        extensions.write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(cert), "-CAkey", str(root / "ca.key"),
            "-CAcreateserial", "-out", str(leaf), "-days", "1", "-extfile", str(extensions))
        key.chmod(0o600)
        access, credential = root / "access", root / "credential"
        token, real = secrets.token_hex(24), secrets.token_hex(24)
        write_private(access, token)
        write_private(credential, real)
        seen = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                seen.append(dict(self.headers))
                if self.path == "/reflect":
                    payload = self.headers.get("Authorization", "").encode()
                elif self.path == "/large":
                    payload = b"x" * (4 * 1024 * 1024 + 1)
                else:
                    payload = json.dumps({"authorized": self.headers.get("Authorization") == "Bearer " + credential.read_text()}).encode()
                self.send_response(302 if self.path == "/redirect" else 200)
                if self.path == "/redirect":
                    self.send_header("Location", "https://not-authorized.invalid/")
                if self.path == "/encoded":
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(payload)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(leaf, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_port
        config = root / "config.json"
        socket_path = root / "broker.sock"
        env_file = root / ".env"
        if args.dotenvx:
            write_private(env_file, "SMOL_BROKER_QA_UPSTREAM_KEY=" + real + "\n")
            run(args.dotenvx, "encrypt", "--no-native", "--no-armor", "--no-1password", "--no-bitwarden",
                "-f", str(env_file), "-fk", str(root / ".env.keys"), cwd=root)
            assert real not in env_file.read_text() and "encrypted:" in env_file.read_text()
            (root / ".env.keys").chmod(0o600)

        def launch(path):
            command = [args.broker, str(path)]
            if args.dotenvx:
                command = [args.dotenvx, "run", "--quiet", "--strict", "--no-native", "--no-armor",
                           "--no-1password", "--no-bitwarden", "-f", str(env_file), "-fk", str(root / ".env.keys"), "--", *command]
            environment = os.environ.copy()
            environment.pop("SMOL_BROKER_QA_UPSTREAM_KEY", None)
            return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    start_new_session=True, env=environment)

        config.write_text(json.dumps({
            "listen": "127.0.0.1:0", "certificate": str(leaf), "private_key": str(key),
            "access_token_file": str(access), "upstream_ca": str(cert),
            "unix_socket": str(socket_path) if args.backend == "tsi" else None,
            "grants": [{"host": "localhost", "port": port, "placeholder": PLACEHOLDER,
                        "header": "authorization", **({"secret_env": "SMOL_BROKER_QA_UPSTREAM_KEY"} if args.dotenvx else {"secret_file": str(credential)})}],
        }))
        process = launch(config)
        name = "broker-qa-" + secrets.token_hex(6)
        created = False
        checks = []
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=10), "broker did not become ready within ten seconds"
            line = process.stdout.readline().strip()
            assert line.startswith("credential broker listening on "), line or process.stderr.read()
            proxy_port = int(line.rsplit(":", 1)[1])
            context = ssl.create_default_context(cafile=cert)
            auth = "Basic " + base64.b64encode(("smol:" + token).encode()).decode()

            def connect(password=auth, host="localhost"):
                conn = http.client.HTTPSConnection("127.0.0.1", proxy_port, context=context, timeout=10)
                conn.set_tunnel(host, port, headers={"Proxy-Authorization": password})
                return conn

            def request(path="/", header_value="Bearer " + PLACEHOLDER, extra=None, body=None, method="GET", connection=None):
                conn = connection or connect()
                headers = {"Authorization": header_value, **(extra or {})}
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                result = response.status, response.read()
                if not connection:
                    conn.close()
                assert real.encode() not in result[1]
                return result

            initial = request()
            assert initial == (200, b'{"authorized": true}'), initial
            checks.append("HTTPS substitution with verified upstream TLS")
            assert all("Proxy-Authorization" not in headers for headers in seen)
            checks.append("proxy authorization never forwarded")
            for kwargs in [{"password": "Basic invalid"}, {"host": "not-authorized.invalid"}]:
                conn = connect(**kwargs)
                try:
                    conn.connect()
                    raise AssertionError("unauthorized tunnel accepted")
                except OSError as error:
                    assert "Tunnel connection failed" in str(error)
                finally:
                    conn.close()
            checks.append("wrong capability and destination denied")
            count = len(seen)
            for kwargs, expected in [
                ({"header_value": "Bearer wrong"}, 403),
                ({"extra": {"Host": "other.invalid"}}, 400),
                ({"extra": {"X-Other": PLACEHOLDER}}, 403),
                ({"path": "/?token=" + PLACEHOLDER}, 403),
                ({"body": PLACEHOLDER, "method": "POST"}, 403),
                ({"body": "x" * (1024 * 1024 + 1), "method": "POST"}, 413),
                ({"extra": {"Upgrade": "websocket"}}, 400),
            ]:
                assert request(**kwargs)[0] == expected, kwargs.keys()
            assert len(seen) == count
            checks.append("authority, placeholder location, body size, and upgrade checks")
            assert request("/reflect")[0] == 502
            assert request("/encoded")[0] == 502
            assert request("/large")[0] == 502
            checks.append("response reflection, encoding, and size refused")
            count = len(seen)
            assert request("/redirect")[0] == 302
            assert len(seen) == count + 1
            checks.append("redirect not followed")
            persistent = connect()
            assert request(connection=persistent)[0] == 200
            write_private(access, secrets.token_hex(24))
            assert request(connection=persistent)[0] == 403
            persistent.close()
            write_private(access, token)
            checks.append("revocation on an already-established TLS connection")
            if args.dotenvx:
                checks.append("dotenvx encrypted .env decrypted only into host broker environment")
            else:
                write_private(credential, secrets.token_hex(24))
                assert request() == (200, b'{"authorized": true}')
                credential.unlink()
                assert request()[0] == 502
                write_private(credential, real)
                checks.append("credential rotation and removal without restarting")

            # Trusting the proxy must not implicitly trust the upstream. With
            # the private upstream CA omitted, the same request must fail.
            untrusted = root / "untrusted-upstream.json"
            untrusted_config = json.loads(config.read_text())
            del untrusted_config["upstream_ca"]
            untrusted_config.pop("unix_socket", None)
            untrusted.write_text(json.dumps(untrusted_config))
            negative = launch(untrusted)
            original_port = proxy_port
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(negative.stdout, selectors.EVENT_READ)
                    assert ready.select(timeout=10)
                negative_line = negative.stdout.readline().strip()
                assert negative_line.startswith("credential broker listening on ")
                proxy_port = int(negative_line.rsplit(":", 1)[1])
                before = len(seen)
                assert request()[0] == 502
                assert len(seen) == before
                checks.append("untrusted upstream TLS rejected before credential-bearing HTTP")
            finally:
                proxy_port = original_port
                stop(negative)

            if args.smolvm:
                # Existing machine verbs only. No real credential is passed to
                # the CLI, guest, mount, or proxy environment.
                # Existing host-owned exact-port bridge; do not expose all host
                # loopback services or weaken the network's internal-IP floor.
                if args.backend == "tsi":
                    os.environ.pop("SMOLVM_GUEST_HOST_SERVICE", None)
                    bridge = ["--mount-socket", str(socket_path) + ":/run/smol-broker.sock"]
                    proxy_host = "127.0.0.1"
                else:
                    os.environ["SMOLVM_GUEST_HOST_SERVICE"] = f"7443:{proxy_port}"
                    os.environ["SMOLVM_EGRESS_FLOOR"] = "strict"
                    bridge = []
                    proxy_host = "100.96.0.1"
                run(args.smolvm, "machine", "create", "--name", name, "--cpus", "1", "--mem", "512",
                    "--storage", "2", "--overlay", "1", "--net-backend", args.backend, "--net", "--image", "alpine:3.20", *bridge)
                created = True
                run(args.smolvm, "machine", "start", "--name", name)
                run(args.smolvm, "machine", "exec", "--name", name, "--", "apk", "add", "--no-cache", "curl", "socat")
                run(args.smolvm, "machine", "cp", str(cert), name + ":/tmp/broker-ca.pem")
                if args.backend == "tsi":
                    run(args.smolvm, "machine", "exec", "--name", name, "--detach", "--", "socat",
                        "TCP4-LISTEN:7443,bind=127.0.0.1,reuseaddr,fork", "UNIX-CONNECT:/run/smol-broker.sock")
                    run(args.smolvm, "machine", "exec", "--name", name, "--", "sh", "-c",
                        "for i in 1 2 3 4 5; do nc -z 127.0.0.1 7443 && exit 0; sleep 0.2; done; exit 1")
                script = f"""set -eu
export https_proxy=http://smol:{token}@{proxy_host}:7443
export HTTPS_PROXY="$https_proxy"
export no_proxy= NO_PROXY=
export CURL_CA_BUNDLE=/tmp/broker-ca.pem
export TEST_API_KEY={PLACEHOLDER}
test "$TEST_API_KEY" = {PLACEHOLDER}
curl --fail --silent --show-error --max-time 15 -H "Authorization: Bearer $TEST_API_KEY" https://localhost:{port}/
"""
                try:
                    result = run(args.smolvm, "machine", "exec", "--name", name, "--", "sh", "-c", script)
                except subprocess.CalledProcessError as error:
                    raise RuntimeError("guest request failed: " + error.stderr) from None
                assert '"authorized": true' in result.stdout, result.stdout + result.stderr
                checks.append("real VM: unchanged curl HTTPS request with placeholder environment")
                if args.backend == "virtio-net":
                    before = len(seen)
                    denied = subprocess.run([args.smolvm, "machine", "exec", "--name", name, "--", "curl",
                        "--noproxy", "*", "--silent", "--show-error", "--max-time", "2", "--insecure",
                        f"https://100.96.0.1:{port}/"], text=True, capture_output=True, timeout=15)
                    assert denied.returncode != 0 and len(seen) == before
                    checks.append("real VM: strict egress blocks unrelated host service")
                else:
                    run(args.smolvm, "machine", "exec", "--name", name, "--", "sh", "-c",
                        "test -S /run/smol-broker.sock && test ! -e " + str(key))
                    checks.append("real VM: TSI broker uses mounted socket, not host-network listener exposure")
                guest_env = run(args.smolvm, "machine", "exec", "--name", name, "--", "env")
                assert real not in guest_env.stdout
                if args.dotenvx:
                    access.unlink()
                    expected_status = "407"
                else:
                    credential.unlink()
                    expected_status = "502"
                failed = subprocess.run([args.smolvm, "machine", "exec", "--name", name, "--", "sh", "-c", script], text=True, capture_output=True, timeout=30)
                assert failed.returncode in (22, 56) and expected_status in failed.stderr, "guest must receive an explicit broker denial"
                checks.append("real VM: removed access/credential fails closed")
            print(json.dumps({"passed": checks, "real_vm": bool(args.smolvm), "backend": args.backend,
                              "dotenvx": bool(args.dotenvx), "production_ready": False}, indent=2))
        finally:
            try:
                if created:
                    run(args.smolvm, "machine", "delete", "--name", name, "-f")
            finally:
                stop(process)
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
