#!/usr/bin/env python3
"""Desktop client -> private socket -> gateway VM -> synthetic HTTPS API.

Requires a Linux GNU broker binary, Linux dotenvx binary, working Smol runtime,
openssl/curl/socat on the desktop, KVM, and network for Ubuntu packages.
Only synthetic credentials are used; generated and decrypted INSIDE the VM.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

from acceptance import run, stop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--dotenvx", required=True)
    parser.add_argument("--smolvm", required=True)
    parser.add_argument("--desktop-uid", type=int, help="Root-only: run desktop requests as this unprivileged UID")
    parser.add_argument("--desktop-gid", type=int)
    args = parser.parse_args()
    name = "desktop-gateway-" + secrets.token_hex(6)
    here = Path(__file__).resolve().parent
    created, bridge = False, None
    isolated = args.desktop_uid is not None
    if isolated:
        assert os.geteuid() == 0 and args.desktop_uid > 0 and args.desktop_gid is not None
    desktop_prefix = (["setpriv", "--reuid", str(args.desktop_uid), "--regid", str(args.desktop_gid), "--clear-groups"] if isolated else [])
    with contextlib.ExitStack() as stack:
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="desktop-gateway-"))
        root = Path(directory)
        host_socket = root / "proxy.sock"
        if isolated:
            root.chmod(0o711)
            data_dir = stack.enter_context(tempfile.TemporaryDirectory(prefix="gateway-admin-", dir="/var/tmp"))
            os.environ["SMOLVM_DATA_DIR"] = data_dir

        def guest(*command):
            return run(args.smolvm, "machine", "exec", "--name", name, "--", *command)

        def copy(source, dest):
            run(args.smolvm, "machine", "cp", str(source), name + ":" + dest)

        def launch_gateway():
            run(args.smolvm, "machine", "exec", "--name", name, "--detach", "--",
                "/usr/local/bin/smolvm-credential-gateway", "/root/gateway-qa")
            guest("sh", "-c", "for i in $(seq 1 100); do test -S /run/credential-gateway/proxy.sock && exit 0; sleep .1; done; exit 1")

        def launch_upstream():
            run(args.smolvm, "machine", "exec", "--name", name, "--detach", "--",
                "python3", "/root/gateway_fixture.py", "serve")
            guest("python3", "-c", "import socket,time\nfor i in range(100):\n try:\n  socket.create_connection(('127.0.0.1',9443),timeout=.1).close();break\n except OSError:time.sleep(.1)\nelse:raise RuntimeError('upstream not ready')")

        try:
            run(args.smolvm, "machine", "create", "--name", name, "--image", "ubuntu:24.04",
                "--net", "--net-backend", "tsi", "--cpus", "1", "--mem", "768", "--storage", "3", "--overlay", "1",
                "--expose-socket", "/run/credential-gateway/proxy.sock" + ("" if isolated else ":" + str(host_socket)))
            created = True
            if isolated:
                host_socket = Path(run(args.smolvm, "machine", "data-dir", "--name", name).stdout.strip()) / "proxy.sock"
            run(args.smolvm, "machine", "start", "--name", name)
            guest("sh", "-c", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 openssl ca-certificates")
            copy(args.broker, "/usr/local/bin/smolvm-secret-broker")
            copy(args.dotenvx, "/usr/local/bin/dotenvx")
            copy(here.parent / "deploy/smolvm-credential-gateway", "/usr/local/bin/smolvm-credential-gateway")
            copy(here / "gateway_fixture.py", "/root/gateway_fixture.py")
            guest("chmod", "0755", "/usr/local/bin/smolvm-secret-broker", "/usr/local/bin/dotenvx", "/usr/local/bin/smolvm-credential-gateway")
            guest("python3", "/root/gateway_fixture.py", "setup")
            launch_upstream()
            launch_gateway()
            for filename in ["client.json", "ca.pem"]:
                run(args.smolvm, "machine", "cp", name + ":/opt/gateway-client/" + filename, str(root / filename))
                if isolated:
                    os.chown(root / filename, args.desktop_uid, args.desktop_gid)
                    (root / filename).chmod(0o600)
            if isolated:
                denied = subprocess.run([*desktop_prefix, args.smolvm, "machine", "exec", "--name", name,
                                         "--", "cat", "/root/gateway-qa/.env.keys"], text=True, capture_output=True, timeout=15)
                assert denied.returncode != 0, "desktop identity has gateway administration access"
                record = json.loads(run(args.smolvm, "machine", "status", "--name", name, "--json").stdout)
                for protected in [host_socket.parent, Path(f"/proc/{record['pid']}/mem")]:
                    # A nonexistent filename would give a meaningless negative.
                    assert protected.exists(), protected
                    unreadable = subprocess.run([*desktop_prefix, "test", "-r", str(protected)], check=False)
                    assert unreadable.returncode == 1, "desktop identity can read gateway state"
            client = json.loads((root / "client.json").read_text())
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            bridge = subprocess.Popen(["socat", f"TCP4-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork", "UNIX-CONNECT:" + str(host_socket)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
            for _ in range(100):
                assert bridge.poll() is None, "desktop bridge failed"
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=.1).close()
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError("desktop bridge not ready")

            def request(token=None, host="localhost", method="GET"):
                env = os.environ.copy()
                env.update(https_proxy=f"http://smol:{token or client['access_token']}@127.0.0.1:{port}",
                           HTTPS_PROXY=f"http://smol:{token or client['access_token']}@127.0.0.1:{port}",
                           no_proxy="", NO_PROXY="", CURL_CA_BUNDLE=str(root / "ca.pem"),
                           EXAMPLE_API_KEY=client["placeholder"])
                return subprocess.run([*desktop_prefix, "curl", "--fail", "--silent", "--show-error", "--max-time", "5",
                                       "-X", method, "-H", "Authorization: Bearer " + client["placeholder"],
                                       f"https://{host}:9443/"], env=env, text=True, capture_output=True, timeout=10)

            def allowed():
                result = request()
                assert result.returncode == 0 and result.stdout == '{"authorized":true}', result.stderr

            allowed()
            before = guest("cat", "/root/gateway-qa/requests").stdout
            for kwargs in [{"token": "wrong-capability"}, {"host": "not-allowed.invalid"}, {"method": "DELETE"}]:
                assert request(**kwargs).returncode != 0
            assert guest("cat", "/root/gateway-qa/requests").stdout == before
            # Revoking the token in the gateway denies desktop requests immediately.
            guest("mv", "/root/gateway-qa/access", "/root/gateway-qa/access.revoked")
            assert request().returncode != 0
            assert guest("cat", "/root/gateway-qa/requests").stdout == before
            guest("mv", "/root/gateway-qa/access.revoked", "/root/gateway-qa/access")
            allowed()
            # Stopped VM: no host-side credential fallback. Start and recover.
            run(args.smolvm, "machine", "stop", "--name", name)
            assert request().returncode != 0
            run(args.smolvm, "machine", "start", "--name", name)
            launch_upstream()
            launch_gateway()
            allowed()
            # Only explicit public/client material was exported to the desktop.
            assert sorted(p.name for p in root.iterdir()) == (["ca.pem", "client.json"] if isolated else ["ca.pem", "client.json", "proxy.sock"])
            guest("python3", "-c", "from pathlib import Path\nr=Path('/root/gateway-qa');s=(r/'expected').read_text();assert s not in (r/'.env').read_text();assert s not in Path('/opt/gateway-client/client.json').read_text()")
            print(json.dumps({"desktop_application": "host curl, no agent wrapper", "gateway": "real Ubuntu Smol VM",
                              "dotenvx": "decryption inside gateway only", "upstream": "synthetic HTTPS fixture inside gateway",
                              "authorized_request": "passed", "wrong_token_host_method": "denied",
                              "revocation": "passed", "stop_start": "passed",
                              "desktop_cannot_administer_gateway": "passed" if isolated else "not tested",
                              "host_exports": ["public CA", "proxy capability", "placeholder"]}, indent=2))
        finally:
            if bridge:
                stop(bridge)
            if created:
                run(args.smolvm, "machine", "delete", "--name", name, "-f")


if __name__ == "__main__":
    main()
