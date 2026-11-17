#!/usr/bin/env python3
"""Exercise HTTP deletion and pool retirement with real Linux or macOS VMs.

Run as a non-root user with a working VM backend and matching runtime assets:
  SMOLVM_LIB_DIR=/path/to/lib SMOLVM_AGENT_ROOTFS=/path/to/agent-rootfs \
    python3 tests/test_api_delete_cleanup.py /path/to/smolvm

The binary needs its normal disk templates beside it. This script starts its own
server with private state, induces host permission errors, and deletes only its
own machines. Logs and JSON observations remain in the printed /tmp directory.
Use --expect-bug against the previous implementation to record the regression.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def process_identity(pid):
    if sys.platform == "linux":
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except FileNotFoundError:
            return None
    # macOS has no /proc. Record the start time as well as the PID so an
    # unrelated process reusing that PID is not reported as our surviving VM.
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="],
                            capture_output=True, text=True, check=False)
    if result.returncode == 1 and not result.stdout.strip():
        return None
    result.check_returncode()
    return result.stdout.strip() or None


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=120)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Campaign:
    def __init__(self, binary, expect_bug):
        self.binary = str(Path(binary).resolve())
        self.expect_bug = expect_bug
        self.root = Path(tempfile.mkdtemp(prefix="sv-delete-", dir="/tmp"))
        self.env = os.environ.copy()
        for key, child in [("SMOLVM_DATA_DIR", "data"),
                           ("XDG_CONFIG_HOME", "config"),
                           ("XDG_CACHE_HOME", "cache"), ("TMPDIR", "tmp")]:
            path = self.root / child
            path.mkdir()
            self.env[key] = str(path)
        if sys.platform == "darwin":
            # SMOLVM_DATA_DIR is Linux-only. Configure a private home only for
            # the child server; never modify the test runner's environment.
            self.env["HOME"] = str(self.root / "data")
            self.machine_root = self.root / "data/Library/Caches/smolvm/vms"
        else:
            self.machine_root = self.root / "data/.cache/smolvm/vms"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.env["SMOLVM_GUEST_ROLLOUT_HOST_PORT"] = str(sock.getsockname()[1])
        self.env["RUST_LOG"] = "warn"
        self.server = None
        self.log = (self.root / "server.log").open("ab")
        self.protected = []
        self.events = []
        self.vm_processes = set()
        print(f"Evidence: {self.root}", flush=True)

    def record(self, **event):
        self.events.append(event)
        (self.root / "observations.json").write_text(json.dumps(self.events, indent=2) + "\n")
        print(json.dumps(event), flush=True)

    def call(self, method, path, payload=None, allowed=(200,)):
        connection = UnixConnection(self.root / "api.sock")
        connection.request(method, "/api/v1/" + path,
                           None if payload is None else json.dumps(payload),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        status, body = response.status, response.read()
        connection.close()
        result = json.loads(body) if body else None
        assert status in allowed, (method, path, status, result)
        return status, result

    def wait(self, check, label):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.25)
        raise AssertionError(f"timed out: {label}")

    def start(self):
        self.server = subprocess.Popen(
            [self.binary, "serve", "start", "-l", f"unix://{self.root}/api.sock"],
            env=self.env, stdout=self.log, stderr=self.log,
        )

        def ready():
            assert self.server.poll() is None, "server exited; inspect server.log"
            try:
                self.call("GET", "machines")
                return True
            except OSError:
                return False

        self.wait(ready, "server startup")

    def stop(self):
        if self.server is not None and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                # Only kill the server this test started, then reap it.
                self.server.kill()
                self.server.wait(timeout=10)
        self.server = None

    def create(self, name, restart=False):
        payload = {"name": name, "cpus": 1, "memoryMb": 256,
                   "storageGb": 1, "overlayGb": 1, "network": False}
        if restart:
            payload["restart"] = {"policy": "always"}
        self.call("POST", "machines", payload)
        self.call("POST", f"machines/{name}/start?branchable=true", {})
        self.remember_process(self.call("GET", f"machines/{name}")[1])

    def remember_process(self, info):
        pid = info.get("pid")
        if pid:
            identity = process_identity(pid)
            if identity is not None:
                self.vm_processes.add((pid, identity))

    def directory(self, name):
        paths = [path.parent for path in self.machine_root.glob("*/name")
                 if path.read_text().strip() == name]
        assert len(paths) == 1, paths
        return paths[0]

    def protect(self, name):
        self.remember_process(self.call("GET", f"machines/{name}")[1])
        path = self.directory(name)
        self.protected.append((path, path.stat().st_mode & 0o777))
        path.chmod(0o500)
        return path

    def execute(self, name, command):
        _, result = self.call("POST", f"machines/{name}/exec",
                              {"command": ["/bin/sh", "-c", command], "timeoutSecs": 30})
        assert result["exitCode"] == 0, result

    def direct(self):
        name = "delete-test"
        self.create(name, restart=True)
        self.execute(name, "printf retained > /workspace/cleanup-test")
        path = self.protect(name)
        status, result = self.call("DELETE", f"machines/{name}", allowed=(200, 500))
        observed, info = self.call("GET", f"machines/{name}", allowed=(200, 404))
        self.record(scenario="direct-failure", status=status, response=result,
                    machine_status=observed, files_remaining=len(list(path.iterdir())))
        assert any(path.iterdir()), "fault did not retain files"
        if self.expect_bug:
            assert status == 200 and observed == 404
            return
        assert status == 500 and observed == 200
        assert info["state"] == "stopped" and info.get("pid") is None, info
        # Allow several supervisor ticks; an always-restart policy must stay stopped.
        time.sleep(6)
        _, info = self.call("GET", f"machines/{name}")
        assert info["state"] == "stopped" and info.get("pid") is None, info
        self.stop()
        self.start()
        _, info = self.call("GET", f"machines/{name}")
        assert info["state"] == "stopped" and info.get("pid") is None, info
        self.record(scenario="restart-recovery", machine=info)
        path.chmod(0o700)
        self.call("DELETE", f"machines/{name}")
        self.call("GET", f"machines/{name}", allowed=(404,))
        assert not path.exists()
        self.record(scenario="direct-retry", files_absent=True, machine_absent=True)

    def pool(self):
        self.create("pool-source")
        self.execute("pool-source", "printf original > /workspace/pool-test; "
                     "smolvm-branch-ready </dev/null >/tmp/branch-ready.log 2>&1 &")
        self.call("POST", "pools", {"name": "cleanup", "source": "pool-source",
                  "desiredReady": 1, "maxActive": 1, "shareWeights": False,
                  "autoAdmission": False, "leaseTtlSecs": 120, "readyTimeoutSecs": 30})
        self.wait(lambda: self.call("GET", "pools/cleanup")[1]["ready"] == 1, "pool ready")
        _, lease = self.call("POST", "pools/cleanup/leases", {"idempotencyKey": "fault"})
        name = lease["machine"]
        self.execute(name, 'test "$(cat /workspace/pool-test)" = original')
        self.call("POST", f'pools/cleanup/leases/{lease["id"]}/heartbeat', {})
        path = self.protect(name)
        self.call("POST", f'pools/cleanup/leases/{lease["id"]}/complete', {})
        retiring = 0 if self.expect_bug else 1

        def retirement_observed():
            _, current_pool = self.call("GET", "pools/cleanup")
            status, machine = self.call("GET", f"machines/{name}", allowed=(200, 404))
            if current_pool["retiring"] != retiring or current_pool["active"] != 0:
                return False
            if self.expect_bug:
                return status == 404
            # A retiring slot alone does not prove the controller tried deletion.
            # Wait for its error for this worker and the resulting stopped state.
            logged_failure = any(
                "failed to retire fork pool worker" in line and name in line
                for line in (self.root / "server.log").read_text().splitlines()
            )
            return (logged_failure and status == 200 and machine["state"] == "stopped"
                    and machine.get("pid") is None)

        self.wait(retirement_observed, "controller deletion attempt")
        _, pool = self.call("GET", "pools/cleanup")
        status, info = self.call("GET", f"machines/{name}", allowed=(200, 404))
        self.record(scenario="pool-failure", pool=pool, machine_status=status,
                    files_remaining=len(list(path.iterdir())))
        assert pool["retiring"] == retiring and any(path.iterdir())
        if self.expect_bug:
            assert status == 404
            return
        assert status == 200 and info["state"] == "stopped", info
        path.chmod(0o700)
        self.wait(lambda: self.call("GET", "pools/cleanup")[1]["retiring"] == 0,
                  "automatic cleanup retry")
        self.call("GET", f"machines/{name}", allowed=(404,))
        assert not path.exists()
        self.record(scenario="pool-retry", files_absent=True, retiring=0)

    def cleanup(self):
        for path, mode in self.protected:
            if path.exists():
                path.chmod(mode)
        try:
            if self.server is not None and self.server.poll() is None:
                self.call("DELETE", "pools/cleanup?force=true", allowed=(200, 404))
                self.wait(lambda: self.call("GET", "pools")[1]["pools"] == [], "pool deletion")
                _, inventory = self.call("GET", "machines")
                for machine in inventory["machines"]:
                    self.remember_process(machine)
                    assert machine["name"] in ("delete-test", "pool-source") or machine["name"].startswith("pool-cleanup-")
                    self.call("DELETE", "machines/" + machine["name"], allowed=(200, 404))
                assert self.call("GET", "machines")[1] == {"machines": []}
                # Old code loses tracking: explicitly remove only our fault paths.
                for path, _ in self.protected:
                    if path.exists():
                        shutil.rmtree(path)
                remaining = [p.name for p in self.machine_root.iterdir()
                             if p.is_dir() and p.name != "_shared"]
                assert not remaining, remaining
                for pid, started in self.vm_processes:
                    assert process_identity(pid) != started, f"VM process {pid} survived cleanup"
                self.record(scenario="cleanup", machines=[], machine_directories=[],
                            tracked_vm_processes_gone=len(self.vm_processes))
        finally:
            try:
                self.stop()
            finally:
                self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--expect-bug", action="store_true")
    args = parser.parse_args()
    if sys.platform not in ("linux", "darwin") or os.geteuid() == 0:
        parser.error("requires a non-root Linux or macOS user")
    if sys.platform == "linux" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("requires read/write access to /dev/kvm")
    campaign = Campaign(args.binary, args.expect_bug)
    try:
        campaign.start()
        campaign.direct()
        campaign.pool()
    finally:
        campaign.cleanup()
    print("Expected pre-fix behavior reproduced" if args.expect_bug else "All cleanup checks passed")


if __name__ == "__main__":
    main()
