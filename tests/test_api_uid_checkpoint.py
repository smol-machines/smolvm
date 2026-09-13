#!/usr/bin/env python3
"""Run as root against a dedicated local serve with default isolation enabled.

Usage: sudo python3 tests/test_api_uid_checkpoint.py http://127.0.0.1:8080
Creates uniquely named Ubuntu machines; deletes only those machines afterward.
The server must run on this host so its VMM credentials and artifact paths can
be inspected. No host policy or existing service configuration is changed.
"""

import json
import os
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path


def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root to validate the privileged service path")
    base = sys.argv[1].rstrip("/") + "/api/v1/machines"
    names = ["uid-qa-" + uuid.uuid4().hex[:12] + suffix
             for suffix in ("-source", "-child", "-grandchild", "-restore")]

    def call(method, path, payload=None):
        data = json.dumps(payload or {}).encode() if method == "POST" else None
        request = urllib.request.Request(base + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=300) as response:
            result = json.load(response)
        if "exitCode" in result:
            assert result["exitCode"] == 0, result
        return result

    def host_uid(name):
        info = call("GET", "/" + name)
        status = Path(f'/proc/{info["pid"]}/status').read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        ids = list(map(int, uid_line.split()[1:]))
        assert len(set(ids)) == 1 and ids[0] >= 2_000_000, ids
        assert "Seccomp:\t2" in status, "seccomp must be enabled"
        cgroup = Path(f'/proc/{info["pid"]}/cgroup').read_text()
        assert "smolvm-vm-" in cgroup and ".scope" in cgroup, cgroup
        return ids[0]

    def marker(name):
        return call("POST", f"/{name}/exec", {
            "command": ["sh", "-c", "cat /root/uid-qa /dev/shm/uid-qa"]})["stdout"]

    source, child, grandchild, restored = names
    try:
        call("POST", "", {"name": source, "image": "ubuntu:24.04",
             "network": True, "cpus": 2, "memoryMb": 1024,
             "storageGb": 4, "overlayGb": 2})
        call("POST", f"/{source}/start?branchable=true")
        uid = host_uid(source)
        call("POST", f"/{source}/exec", {"command": ["sh", "-c",
             "echo disk >/root/uid-qa; echo ram >/dev/shm/uid-qa"]})
        expected = marker(source)
        for parent, target in [(source, child), (child, grandchild)]:
            call("POST", f"/{parent}/branches", {"name": target, "branchable": True})
            assert host_uid(target) == uid, "nested branch changed lineage UID"
            assert marker(target) == expected

        with tempfile.TemporaryDirectory(prefix="smolvm-uid-qa-") as directory:
            artifact = Path(directory, "state.smolcheckpoint")
            request = urllib.request.Request(base + f"/{source}/checkpoint", method="POST")
            with urllib.request.urlopen(request, timeout=300) as response, artifact.open("wb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            assert marker(source) == expected, "source failed to continue after SAVE"
            call("POST", "", {"name": restored, "from": str(artifact)})
            call("POST", f"/{restored}/start")
            assert marker(restored) == expected, "disk or RAM was not restored"
            call("POST", f"/{restored}/exec", {"command": ["sh", "-c",
                 "echo changed >/root/uid-qa; echo changed >/dev/shm/uid-qa"]})
            assert marker(source) == expected, "restore mutated the source"
        print("PASS: isolated nested branches, checkpoint, restore, and source continuation")
    finally:
        for name in reversed(names):
            try:
                call("DELETE", f"/{name}?force=true")
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    print(f"cleanup failed for {name}: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
