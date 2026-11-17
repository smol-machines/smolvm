#!/usr/bin/env python3
"""Check warm-base ownership on an isolated, socket-activated macOS engine.

Set DOCKER_HOST and SMOLVM_ENGINE_TEST_ROOT, as for test_engine_lifecycle.py;
this test must not run concurrently with other tests on that engine.
"""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

if sys.platform != "darwin":
    raise SystemExit("warm-base lifecycle requires macOS")

ROOT = Path(os.environ["SMOLVM_ENGINE_TEST_ROOT"]).resolve()
SOCKET_DIR = Path(os.environ["DOCKER_HOST"].removeprefix("unix://")).parent
DB = Path.home() / "Library/Application Support/smolvm/server/smolvm.db"
PREFIX = f"smol-warm-lifetime-{os.getpid()}"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=90).strip()


def records():
    with sqlite3.connect(f"file:{DB}?mode=ro", uri=True) as db:
        return {name: json.loads(data) for name, data in db.execute("SELECT name, data FROM vms")}


def eventually(check, timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError("condition did not become true")


ids = []
try:
    assert Path(docker("info", "--format", "{{.DockerRootDir}}")).resolve() == ROOT
    for i in range(3):
        ids.append(docker("run", "-d", "--name", f"{PREFIX}-{i}", "alpine", "sleep", "300"))
    def ready_base():
        return next(((name, vm) for name, vm in records().items()
                     if vm.get("labels", {}).get("smolvm.engine/base-engine") == str(ROOT)
                     and vm.get("labels", {}).get("smolvm.engine/base-ready") == "true"), None)
    base, vm = eventually(ready_base)
    child = docker("run", "-d", "--name", PREFIX + "-branch", "alpine", "sleep", "300")
    ids.append(child)
    assert records()[f"docker-{child[:12]}"]["golden"] == base, "container did not branch"
    owner = vm["labels"]["smolvm.engine/base-owner"]
    assert owner in ids
    docker("rm", "-f", owner)
    time.sleep(12)  # Its original workload is gone, but its base must stay alive.
    assert (SOCKET_DIR / f"w-{owner[:24]}.sock").exists(), "base owner exited with a live branch"
    assert docker("exec", child, "echo", "alive") == "alive"
    print("PASS: a warm branch survives removal of its owner's workload", flush=True)
finally:
    for cid in ids:
        subprocess.run(["docker", "rm", "-f", cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

eventually(lambda: all(not (SOCKET_DIR / f"w-{cid[:24]}.sock").exists() for cid in ids))
assert base not in records(), "unused warm base was not collected"
print("PASS: warm base and its supervisor exit after the final branch", flush=True)
