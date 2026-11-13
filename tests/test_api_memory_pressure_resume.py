#!/usr/bin/env python3
"""Verify the memory pressure guard resumes a branch child it paused.

Starts a dedicated server with private state in its own systemd user scope, so
the test can move the scope's MemoryMax: the guard reads memory.max minus
memory.current as the host's available memory. Lowering it below half the
reserve makes the guard pause the newest branch child; raising it gives the
margin at which the guard resumes that child. The child keeps a file in its
RAM-backed /dev/shm across the pause, so a resume is told apart from a reboot.

  SMOLVM_LIB_DIR=/path/to/lib SMOLVM_AGENT_ROOTFS=/path/to/agent-rootfs \\
    python3 tests/test_api_memory_pressure_resume.py /path/to/smolvm

Linux only, with KVM and a systemd user manager that delegates the memory
controller (systemd-run --user). No image pull. Use --expect-bug against the
previous implementation to record its failure: the guard's resume finds the
VM lock still held by the server and the child stays paused.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

MIB = 1024 * 1024
RESERVE_MIB = 1024
LOCK_HELD = "another process is already starting or running this VM"


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def systemctl(*args):
    return subprocess.run(["systemctl", "--user", *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--expect-bug", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux":
        print("SKIP the memory pressure guard runs only on Linux")
        return
    probe = ["systemctl", "--user", "show", "--property=Version"]
    if shutil.which("systemd-run") is None or subprocess.run(probe, capture_output=True).returncode:
        print("SKIP no systemd user manager to run the server in its own scope")
        return

    with tempfile.TemporaryDirectory(prefix="pressure-") as directory:
        root = Path(directory)
        port, rollout_port = free_port(), free_port()
        while rollout_port == port:
            rollout_port = free_port()
        base = f"http://127.0.0.1:{port}"
        scope = f"smolvm-pressure-test-{os.getpid()}.scope"
        env = dict(os.environ, HOME=directory, SMOLVM_DATA_DIR=directory,
                   SMOLVM_GUEST_ROLLOUT_HOST_PORT=str(rollout_port),
                   SMOLVM_MEMORY_PRESSURE_GUARD="1",
                   SMOLVM_MEMORY_PRESSURE_RESERVE_MIB=str(RESERVE_MIB))
        source, child = "pressure-source", "pressure-child"

        def call(method, path, payload=None):
            data = json.dumps(payload or {}).encode() if method == "POST" else None
            request = urllib.request.Request(base + path, method=method, data=data,
                                             headers={"Content-Type": "application/json"})
            try:
                response = urllib.request.urlopen(request, timeout=300)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read()
                return response.status, json.loads(body) if body else None

        def machine(name):
            status, info = call("GET", f"/api/v1/machines/{name}")
            assert status == 200, info
            return info

        def exec_in(name, script):
            status, result = call("POST", f"/api/v1/machines/{name}/exec",
                                  {"command": ["sh", "-ec", script]})
            assert status == 200 and result["exitCode"] == 0, result
            return result["stdout"]

        def wait(condition, what, timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                assert server.poll() is None, "isolated server exited"
                if condition():
                    return
                time.sleep(1)
            raise AssertionError(f"timed out waiting for {what}")

        def memory_file(name):
            return Path("/sys/fs/cgroup") / cgroup.lstrip("/") / name

        def headroom(mib):
            # The guard sees memory.max - memory.current; set it to about `mib`.
            current = int(memory_file("memory.current").read_text())
            systemctl("set-property", "--runtime", scope, f"MemoryMax={current + mib * MIB}")

        def resume_failures():
            return log_path.read_text(errors="replace").count(LOCK_HELD)

        log_path = root / "serve.log"
        with log_path.open("w+") as log:
            server = subprocess.Popen(
                ["systemd-run", "--user", "--scope", "--quiet", f"--unit={scope}",
                 "-p", "Delegate=yes", "-p", "MemorySwapMax=0", "--",
                 args.binary, "serve", "start", "--listen", f"127.0.0.1:{port}"],
                env=env, stdout=log, stderr=log)
            try:
                for _ in range(300):
                    assert server.poll() is None, "isolated server exited"
                    try:
                        if call("GET", "/api/v1/machines")[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                else:
                    raise AssertionError("isolated server did not become ready")
                cgroup = systemctl("show", "-p", "ControlGroup", "--value", scope)
                if not memory_file("memory.max").exists():
                    print("SKIP the user manager does not delegate the memory controller")
                    return

                status, result = call("POST", "/api/v1/machines", {
                    "name": source, "cpus": 1, "memoryMb": 512, "storageGb": 1})
                assert status < 300, result
                status, result = call("POST", f"/api/v1/machines/{source}/start",
                                      {"branchable": True})
                assert status == 200, result
                status, result = call("POST", f"/api/v1/machines/{source}/branches",
                                      {"name": child})
                assert status < 300, result
                exec_in(child, "echo witness >/dev/shm/pressure-witness")

                # Below half the reserve the guard pauses the newest branch child.
                headroom(RESERVE_MIB // 4)
                wait(lambda: machine(child)["state"] == "paused", "the guard's pause", 300)
                assert "host memory pressure" in (machine(child).get("stateReason") or "")
                assert machine(source)["state"] == "running", "the guard paused the source"

                # Twice the reserve plus the child's RAM is the guard's resume margin.
                headroom(RESERVE_MIB * 4)
                if args.expect_bug:
                    wait(lambda: resume_failures() >= 3, "the guard's failed resumes", 120)
                    assert machine(child)["state"] == "paused"
                    print("PASS expected pre-fix behavior reproduced: the guard's resume "
                          "finds the VM lock held and the child stays paused")
                    return
                wait(lambda: machine(child)["state"] == "running", "the guard's resume", 120)
                info = machine(child)
                assert info.get("stateReason") is None, info
                assert exec_in(child, "cat /dev/shm/pressure-witness") == "witness\n"
                assert resume_failures() == 0, "a guard resume failed on the VM lock"
                print("PASS the guard pauses a branch child under pressure and "
                      "resumes the same execution when memory recovers")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                try:
                    for name in (child, source):
                        try:
                            call("DELETE", f"/api/v1/machines/{name}?force=true")
                        except OSError:
                            pass
                finally:
                    server.terminate()
                    server.wait(timeout=60)
                    # A resumed VMM is detached from the server; end the scope too.
                    subprocess.run(["systemctl", "--user", "stop", scope], capture_output=True)


if __name__ == "__main__":
    main()
