#!/usr/bin/env python3
"""Exercise an isolated, socket-activated engine, including SIGKILL and idle exit.

Set DOCKER_HOST to its socket and SMOLVM_ENGINE_TEST_ROOT to its state directory;
never point this test at an engine with workloads you want to keep.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

ROOT = Path(os.environ["SMOLVM_ENGINE_TEST_ROOT"]).resolve()
PREFIX = f"smol-lifetime-{os.getpid()}"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=90).strip()


def inspect(name):
    return json.loads(docker("inspect", name))[0]


def eventually(check, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise AssertionError("condition did not become true")


def kill_adapter():
    # Confirm that the Docker endpoint is the isolated engine before touching its PID.
    assert Path(docker("info", "--format", "{{.DockerRootDir}}")).resolve() == ROOT
    pid = int((ROOT / "engine.pid").read_text())
    os.kill(pid, signal.SIGKILL)
    return pid


def absent():
    # A SIGKILL can leave a PID file; PID liveness, not file presence, matters.
    try:
        pid = int((ROOT / "engine.pid").read_text())
        os.kill(pid, 0)
        return False
    except (FileNotFoundError, ProcessLookupError):
        return True


names = []
network = PREFIX + "-net"
try:
    docker("network", "create", network)
    web = PREFIX + "-web"
    names.append(web)
    cid = docker("run", "-d", "--name", web, "--network", network,
                 "--network-alias", "web", "-p", "127.0.0.1::8080",
                 "--health-cmd", "test -e /tmp/ready", "--health-interval", "1s",
                 "alpine", "sh", "-c", "touch /tmp/ready; while true; do "
                 "printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\nalive\\n' | nc -l -p 8080; done")
    state = inspect(web)
    vm_pid = state["State"]["Pid"]
    port = state["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
    peer = PREFIX + "-peer"
    names.append(peer)
    peer_id = docker("run", "-d", "--name", peer, "--network", network, "alpine", "sh", "-c",
                     "while true; do wget -q -O - http://web:8080; sleep 1; done")
    restart = PREFIX + "-restart"
    names.append(restart)
    docker("run", "-d", "--name", restart, "--restart", "on-failure:2", "alpine", "sh", "-c",
           "n=$(cat /attempt 2>/dev/null || echo 0); n=$((n+1)); echo $n >/attempt; "
           "echo attempt-$n; if [ $n -lt 3 ]; then sleep 3; exit 1; fi; sleep 300")
    exec_id = json.loads(subprocess.check_output([
        "curl", "-fsS", "--unix-socket", os.environ["DOCKER_HOST"].removeprefix("unix://"),
        "-H", "Content-Type: application/json", "-d", '{"Cmd":["echo","retained"],"AttachStdout":true}',
        f"http://localhost/containers/{cid}/exec"], text=True))["Id"]
    # Reserved collection-route words are valid container names too.
    reserved = "create"
    docker("run", "-d", "--name", reserved, "alpine", "sleep", "300")
    names.append(reserved)
    reserved_pid = inspect(reserved)["State"]["Pid"]
    kill_adapter()
    time.sleep(9)  # The supervisor must perform both restarts and health probes alone.
    assert absent(), "API adapter remained running without clients"
    with urllib.request.urlopen(f"http://127.0.0.1:{port}", timeout=5) as response:
        assert response.read() == b"alive\n"
    peer_log = ROOT / "containers" / peer_id / f"{peer_id}-json.log"
    assert peer_log.read_text().count("alive") >= 3, "cross-machine networking stopped with the adapter"
    assert inspect(web)["State"]["Pid"] == vm_pid, "reconnecting restarted the VM"
    assert inspect(reserved)["State"]["Pid"] == reserved_pid, "reserved name bypassed its supervisor"
    assert inspect(web)["State"]["Health"]["Status"] == "healthy"
    assert inspect(restart)["RestartCount"] == 2
    assert docker("exec", web, "echo", "reconnected") == "reconnected"
    output = subprocess.check_output([
        "curl", "-fsS", "--unix-socket", os.environ["DOCKER_HOST"].removeprefix("unix://"),
        "-H", "Content-Type: application/json", "-d", '{"Detach":false,"Tty":false}',
        f"http://localhost/exec/{exec_id}/start"])
    assert b"retained" in output, "an exec created before adapter death was lost"
    print("PASS: SIGKILL leaves ports, networking, health, restarts, logs and exec intact", flush=True)
    eventually(absent)  # No API traffic: running workloads must not pin the adapter.
    assert inspect(web)["State"]["Pid"] == vm_pid
    print("PASS: idle adapter exits and a new connection reactivates it", flush=True)
    created = PREFIX + "-created"
    names.append(created)
    docker("create", "--name", created, "--restart", "always", "alpine", "sleep", "300")
    assert inspect(created)["State"]["Status"] == "created", "inspection started an unstarted workload"
    # A failed start must terminate the attach opened by `docker run`.
    failed = PREFIX + "-failed"
    names.append(failed)
    result = subprocess.run(["docker", "run", "--name", failed, "alpine", "/missing-command"],
                            capture_output=True, timeout=30)
    assert result.returncode != 0
    # An abandoned pre-start attach must release its connection without an exit event.
    attached = PREFIX + "-attached"
    names.append(attached)
    attached_id = docker("create", "--name", attached, "alpine", "sleep", "300")
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(10)
    client.connect(os.environ["DOCKER_HOST"].removeprefix("unix://"))
    client.sendall((f"POST /containers/{attached_id}/attach?stream=1&stdout=1 HTTP/1.1\r\n"
                    "Host: localhost\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n").encode())
    assert b"101" in client.recv(4096)
    client.close()
    socket_dir = Path(os.environ["DOCKER_HOST"].removeprefix("unix://")).parent
    eventually(lambda: not (socket_dir / f"w-{attached_id[:24]}.sock").exists())
    contested = PREFIX + "-contested"
    names.append(contested)
    def create_same_name(_):
        return subprocess.run(["docker", "create", "--name", contested, "alpine", "true"],
                              capture_output=True, timeout=30).returncode
    with ThreadPoolExecutor(max_workers=4) as clients:
        assert list(clients.map(create_same_name, range(4))).count(0) == 1
    ids = [inspect(name)["Id"] for name in names]
    for name in names:
        docker("rm", "-f", name)
    names.clear()
    docker("network", "rm", network)
    eventually(absent)
    # Private supervisor sockets are removed when their owning processes exit.
    socket_dir = Path(os.environ["DOCKER_HOST"].removeprefix("unix://")).parent
    eventually(lambda: all(not (socket_dir / f"w-{cid[:24]}.sock").exists() for cid in ids))
    print("PASS: no API or workload supervisors remain after cleanup", flush=True)
finally:
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
