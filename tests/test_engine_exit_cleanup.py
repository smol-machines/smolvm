#!/usr/bin/env python3
"""Check slow exit cleanup, auto-removal, restart and eventual supervisor exit.

Set DOCKER_HOST and SMOLVM_ENGINE_TEST_ROOT to an isolated socket-activated
engine. The test holds its network lock, so do not use an engine with other
workloads. Requires a native VM runtime and the Docker CLI.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(os.environ["SMOLVM_ENGINE_TEST_ROOT"]).resolve()


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=90).strip()


def eventually(check, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError("condition did not become true")


def owns_lock(path):
    # Observe kernel ownership without making an API call that wakes the worker.
    with path.open("rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
    return False


def delayed_cleanup(mode):
    options = {"remove": ["--rm"], "retain": [], "restart": ["--restart", "on-failure:1"]}
    command = "sleep 14; echo cleanup-ready"
    if mode == "restart":
        command = ("if [ ! -e /attempt ]; then touch /attempt; sleep 14; exit 1; "
                   "else echo restarted; sleep 300; fi")
    cid = docker("create", *options[mode], "--network", "none", "alpine:3.24",
                 "sh", "-c", command)
    try:
        check_cleanup(cid, mode)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=90)


def check_cleanup(cid, mode):
    docker("start", cid)
    config = ROOT / "containers" / cid / "config.json"
    owner = ROOT / f"{cid}.lock"
    with (ROOT / "network.lock").open("a+b") as network:
        fcntl.flock(network, fcntl.LOCK_EX)
        eventually(lambda: json.loads(config.read_text())["state"]["status"] == "exited")
        # Keep teardown blocked longer than the ten-second idle timeout.
        # No client traffic or inspection may extend the supervisor's lifetime.
        time.sleep(12)
        assert owns_lock(owner), "idle exit abandoned pending container cleanup"
        assert config.exists(), "container was removed before network cleanup"
    if mode == "remove":
        eventually(lambda: not config.exists(), timeout=15)
    elif mode == "restart":
        eventually(lambda: json.loads(config.read_text())["state"]["status"] == "running")
        assert json.loads(config.read_text())["restart_count"] == 1
        assert "restarted" in docker("logs", cid)
        docker("stop", "-t", "1", cid)
    eventually(lambda: not owns_lock(owner))
    if mode != "remove":
        assert json.loads(config.read_text())["state"]["status"] == "exited"
    print(f"PASS: {mode} finishes delayed cleanup and releases its supervisor", flush=True)


assert Path(docker("info", "--format", "{{.DockerRootDir}}")).resolve() == ROOT
for mode in ["remove", "retain", "restart"]:
    delayed_cleanup(mode)
