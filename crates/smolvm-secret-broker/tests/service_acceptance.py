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
import socket
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
    parser.add_argument("--smolvm", help="Also test a real VMM through process-bound Unix transport")
    parser.add_argument("--dotenvx", help="Run the isolated broker under real dotenvx")
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
        if args.dotenvx:
            dotenvx = root / "dotenvx"
            shutil.copyfile(args.dotenvx, dotenvx)
            dotenvx.chmod(0o755)
            write_private(private / "env", "SMOL_BROKER_QA_UPSTREAM_KEY=" + secret + "\n")
            run(str(dotenvx), "encrypt", "--no-native", "--no-armor", "--no-1password", "--no-bitwarden",
                "-f", str(private / "env"), "-fk", str(private / "envkeys"), cwd=private)
            assert secret not in (private / "env").read_text()
            (private / "envkeys").chmod(0o600)
        seen = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
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
        server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(leaf, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        credential_dir = Path("/run") / unit.removesuffix(".service")
        config = private / "config"
        write_private(config, json.dumps({
            "allow_bearer_only": not bool(args.smolvm),
            "listen": None if args.smolvm else "127.0.0.1:0", "certificate": str(credential_dir / "leaf"),
            "unix_socket": str(credential_dir / "broker.sock") if args.smolvm else None,
            "peer_identity_file": str(credential_dir / "identity") if args.smolvm else None,
            "private_key": str(credential_dir / "key"), "access_token_file": str(credential_dir / "access"),
            "upstream_ca": str(credential_dir / "ca"),
            "grants": [{"host": "localhost", "port": server.server_port, "header": "authorization",
                        "placeholder": PLACEHOLDER, **({"secret_env": "SMOL_BROKER_QA_UPSTREAM_KEY"} if args.dotenvx
                                                       else {"secret_file": str(credential_dir / "secret")})}],
        }))
        log = private / "service.log"
        command = ["systemd-run", "--quiet", "--collect", "--unit=" + unit]
        for prop in ["DynamicUser=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                     "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes",
                     "RestrictSUIDSGID=yes", "CapabilityBoundingSet=", "LimitCORE=0", "UMask=0077",
                     "MemoryMax=256M", "TasksMax=96", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                     "RuntimeDirectory=" + unit.removesuffix(".service"),
                     "RuntimeDirectoryMode=" + ("0711" if args.smolvm else "0700"),
                     "StandardOutput=append:" + str(log), "StandardError=append:" + str(log)]:
            command.extend(["--property", prop])
        for name, source in {"config": config, "key": key, "leaf": leaf, "ca": ca,
                             "access": private / "access", "secret": private / "secret"}.items():
            command.extend(["--property", f"LoadCredential={name}:{source}"])
        credential_names = "config key leaf ca access secret"
        launch = [str(binary), str(credential_dir / "config")]
        if args.dotenvx:
            command.extend(["--property", "Environment=HOME=" + str(credential_dir / "home")])
            for item in ["env", "envkeys"]:
                command.extend(["--property", f"LoadCredential={item}:{private / item}"])
            credential_names += " env envkeys"
            launch = [str(dotenvx), "run", "--quiet", "--strict", "--no-native", "--no-armor",
                      "--no-1password", "--no-bitwarden", "-f", str(credential_dir / "env"),
                      "-fk", str(credential_dir / "envkeys"), "--", *launch]
        command.extend(["/bin/sh", "-c", 'set -eu; install -d -m 700 "$RUNTIME_DIRECTORY/home"; for item in ' + credential_names + '; do install -m 600 "$CREDENTIALS_DIRECTORY/$item" "$RUNTIME_DIRECTORY/$item"; done; exec "$@"', "_", *launch])
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
                    port = True if args.smolvm else int(ready[-1].rsplit(":", 1)[1])
                    break
                time.sleep(0.1)
            assert port, "isolated service failed to become ready: " + log.read_text()
            pid = int(run("systemctl", "show", unit, "-p", "MainPID", "--value").stdout)
            uid_line = next(line for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:"))
            service_uid = int(uid_line.split()[1])
            assert service_uid not in (0, args.observer_uid)
            protected = [private / "secret", credential_dir / "secret", credential_dir / "key", Path(f"/proc/{pid}/environ")]
            if args.dotenvx:
                protected.extend([private / "envkeys", credential_dir / "envkeys"])
            cgroup = run("systemctl", "show", unit, "-p", "ControlGroup", "--value").stdout.strip()
            for member in (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.procs").read_text().split():
                protected.append(Path(f"/proc/{member}/environ"))
            for path in protected:
                denied = subprocess.run(["setpriv", "--reuid", str(args.observer_uid), "--regid", str(args.observer_gid),
                                         "--clear-groups", "test", "-r", str(path)], check=False)
                assert denied.returncode == 1, "unprivileged observer can read protected credential state"
            if args.smolvm:
                validate_vm(args, credential_dir, service_uid, ca, server.server_port, token, seen)
                return
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


def validate_vm(args, runtime, service_uid, ca, upstream_port, token, seen):
    """No proxy token/header can replace the kernel-observed VMM identity."""
    name = "broker-bound-" + secrets.token_hex(6)
    child = name + "-child"
    identity_path = runtime / "identity"

    def authorize(machine):
        record = json.loads(run(args.smolvm, "machine", "status", "--name", machine, "--json").stdout)
        pid = int(record["pid"])
        write_private(identity_path, run(args.broker, "identity", str(pid)).stdout.strip())
        os.chown(identity_path, service_uid, service_uid)

    def guest(machine, *command):
        return run(args.smolvm, "machine", "exec", "--name", machine, "--", *command)

    script = f'''export https_proxy=http://smol:{token}@127.0.0.1:7443
export HTTPS_PROXY="$https_proxy" no_proxy= NO_PROXY= CURL_CA_BUNDLE=/tmp/broker-ca.pem
curl --fail --silent --show-error --max-time 5 -H 'Authorization: Bearer {PLACEHOLDER}' https://localhost:{upstream_port}/'''

    def request(machine, allowed):
        before = len(seen)
        result = subprocess.run([args.smolvm, "machine", "exec", "--name", machine, "--", "sh", "-c", script],
                                text=True, capture_output=True, timeout=20)
        if allowed:
            assert result.returncode == 0 and '"authorized":true' in result.stdout, result.stderr
            assert len(seen) == before + 1 and seen[-1]
        else:
            assert result.returncode != 0 and len(seen) == before, "unauthorized VM reached upstream"

    created = False
    try:
        run(args.smolvm, "machine", "create", "--name", name, "--cpus", "1", "--mem", "512",
            "--storage", "2", "--overlay", "1", "--net", "--net-backend", "tsi",
            "--image", "alpine:3.20", "--mount-socket", str(runtime / "broker.sock") + ":/run/smol-broker.sock")
        created = True
        run(args.smolvm, "machine", "start", "--branchable", "--name", name)
        guest(name, "apk", "add", "--no-cache", "curl", "socat", "python3")
        run(args.smolvm, "machine", "cp", str(ca), name + ":/tmp/broker-ca.pem")
        run(args.smolvm, "machine", "exec", "--name", name, "--detach", "--", "socat",
            "TCP4-LISTEN:7443,bind=127.0.0.1,reuseaddr,fork", "UNIX-CONNECT:/run/smol-broker.sock")
        guest(name, "sh", "-c", "for i in 1 2 3 4 5; do nc -z 127.0.0.1 7443 && exit 0; sleep 0.2; done; exit 1")
        request(name, False)
        authorize(name)
        request(name, True)
        identity_path.chmod(0o644)
        request(name, False)
        identity_path.chmod(0o600)
        write_private(identity_path, "invalid authorization record")
        request(name, False)
        authorize(name)
        request(name, True)
        checkpoint = subprocess.run([args.smolvm, "machine", "checkpoint", "--name", name,
                                     "--output", str(runtime / "unsupported.smolcheckpoint")],
                                    text=True, capture_output=True, timeout=30)
        assert checkpoint.returncode != 0 and "published sockets" in checkpoint.stderr
        assert not (runtime / "unsupported.smolcheckpoint").exists()
        # Keep a real TLS session live across the branch, not just a copied token.
        probe = f'''
import base64,http.client,pathlib,ssl,time
c=http.client.HTTPSConnection("127.0.0.1",7443,context=ssl.create_default_context(cafile="/tmp/broker-ca.pem"),timeout=5)
c.set_tunnel("localhost",{upstream_port},headers={{"Proxy-Authorization":"Basic "+base64.b64encode(b"smol:{token}").decode()}})
def request():
    c.request("GET","/",headers={{"Authorization":"Bearer {PLACEHOLDER}"}})
    r=c.getresponse(); r.read(); return r.status
assert request()==200
pathlib.Path("/tmp/broker-session-ready").touch()
while not pathlib.Path("/tmp/broker-session-go").exists(): time.sleep(.05)
try: outcome=str(request())
except Exception: outcome="denied"
pathlib.Path("/tmp/broker-session-result").write_text(outcome)
c.close()
'''
        run(args.smolvm, "machine", "exec", "--name", name, "--detach", "--", "python3", "-c", probe)
        guest(name, "sh", "-c", "for i in $(seq 1 50); do test -f /tmp/broker-session-ready && exit 0; sleep .1; done; exit 1")
        # A host client holding the same token is not the VMM process.
        with socket.socket(socket.AF_UNIX) as unrelated:
            unrelated.settimeout(5)
            unrelated.connect(str(runtime / "broker.sock"))
            try:
                auth = base64.b64encode(("smol:" + token).encode()).decode()
                unrelated.sendall((f"CONNECT localhost:{upstream_port} HTTP/1.1\r\n"
                                   f"Host: localhost:{upstream_port}\r\nProxy-Authorization: Basic {auth}\r\n\r\n").encode())
                assert unrelated.recv(4096) == b""
            except ConnectionResetError:
                pass
        run(args.smolvm, "machine", "branch", "--from", name, "--name", child)
        before = len(seen)
        guest(child, "touch", "/tmp/broker-session-go")
        guest(child, "sh", "-c", "for i in $(seq 1 70); do test -f /tmp/broker-session-result && exit 0; sleep .1; done; exit 1")
        assert guest(child, "cat", "/tmp/broker-session-result").stdout.strip() != "200"
        assert len(seen) == before, "child inherited an authorized live session"
        guest(name, "touch", "/tmp/broker-session-go")
        guest(name, "sh", "-c", "for i in $(seq 1 70); do test -f /tmp/broker-session-result && exit 0; sleep .1; done; exit 1")
        assert guest(name, "cat", "/tmp/broker-session-result").stdout.strip() == "200"
        request(child, False)
        request(name, True)
        authorize(child)
        request(child, True)
        request(name, False)
        run(args.smolvm, "machine", "stop", "--name", child)
        run(args.smolvm, "machine", "start", "--name", child)
        run(args.smolvm, "machine", "exec", "--name", child, "--detach", "--", "socat",
            "TCP4-LISTEN:7443,bind=127.0.0.1,reuseaddr,fork", "UNIX-CONNECT:/run/smol-broker.sock")
        run(args.smolvm, "machine", "cp", str(ca), child + ":/tmp/broker-ca.pem")
        guest(child, "sh", "-c", "for i in 1 2 3 4 5; do nc -z 127.0.0.1 7443 && exit 0; sleep 0.2; done; exit 1")
        request(child, False)
        authorize(child)
        request(child, True)
        identity_path.unlink()
        request(child, False)
        print(json.dumps({"isolated_service_real_vm": "passed", "backend": "tsi",
                          "missing_authorization": "denied", "authorized_parent": "passed",
                          "copied_token_in_child": "denied", "explicit_child_authorization": "passed",
                          "inherited_live_tls_session": "denied",
                          "portable_attachment_capture": "explicitly_rejected",
                          "invalid_or_public_authorization_record": "denied",
                          "unrelated_host_process": "denied", "restart_requires_reauthorization": "passed",
                          "dotenvx": bool(args.dotenvx), "revocation": "passed"}, indent=2))
    finally:
        if created:
            run(args.smolvm, "machine", "delete", "--name", name, "-f", "--cascade")


if __name__ == "__main__":
    main()
