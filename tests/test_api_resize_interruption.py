#!/usr/bin/env python3
"""Recover a live resize interrupted after backend growth, before metadata commit.

Usage: python3 tests/test_api_resize_interruption.py /path/to/smolvm memory|disk
Add --restart-vm to stop/start the VM before retrying the interrupted request.
Requires Linux KVM and hotplug-capable runtime/guest bundles, supplied using
SMOLVM_LIB_DIR and SMOLVM_AGENT_ROOTFS. Uses normal managed memory limits.
Only the dedicated test API is killed; no existing machine is touched.
SQLite locking holds the real completion boundary without a runtime failpoint.
A missed boundary is a test failure, not a passing crash-recovery test.
"""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tempfile
import sys
import argparse
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('kind', choices=('memory', 'disk'))
parser.add_argument('--restart-vm', action='store_true')
args = parser.parse_args()
if sys.platform != 'linux':
    parser.error('this interruption test requires Linux KVM')
binary = args.binary.resolve(strict=True)
kind = args.kind
restart_vm = args.restart_vm
root = Path(tempfile.mkdtemp(prefix='resize-crash-boundary-', dir='/var/tmp'))
root.chmod(0o711)
name = root.name
env = dict(os.environ, XDG_DATA_HOME=str(root/'data'), XDG_CACHE_HOME=str(root/'cache'),
    SMOLVM_DATA_DIR=str(root/'node'), SMOLVM_VM_USE_SCOPE='1',
    KRUN_PROTOTYPE_CPU_GROWTH='1', KRUN_PROTOTYPE_MEMORY_GROWTH='1')

def cli(*args, check=True):
    p = subprocess.run([str(binary), 'machine', *args], env=env, text=True,
        capture_output=True, timeout=120)
    print(json.dumps({'cli':args, 'rc':p.returncode, 'out':p.stdout, 'err':p.stderr}), flush=True)
    if check:
        p.check_returncode()
    return p.stdout.strip()

def guest(command):
    return cli('exec', '--name', name, '--', 'sh', '-ec', command)

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    env['SMOLVM_GUEST_ROLLOUT_HOST_PORT'] = str(sock.getsockname()[1])

def api(method, payload=None):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=60)
    try:
        c.request(method, '/api/v1/machines/'+name+('/resize' if method == 'POST' else ''),
            body=json.dumps(payload) if payload else None, headers={'Content-Type':'application/json'})
        r = c.getresponse()
        return r.status, json.loads(r.read())
    finally:
        c.close()

server = None
db = None
log = open(root/'node.log', 'x')
os.chmod(root/'node.log', 0o600)

def start_api():
    p = subprocess.Popen([str(binary), 'serve', 'start', '--listen', f'127.0.0.1:{port}'],
        env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        assert p.poll() is None
        try:
            if api('GET')[0] == 200:
                return p
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.05)
    p.terminate()
    p.wait(timeout=15)
    raise AssertionError('QA API did not become ready')

try:
    print(json.dumps({'root':str(root), 'kind':kind, 'restart_vm':restart_vm}), flush=True)
    cli('create', '--name', name, '--cpus', '2', '--mem', '1024', '--storage', '1', '--overlay', '1')
    cli('start', '--name', name)
    boot = guest('cat /proc/sys/kernel/random/boot_id')
    guest('echo disk-marker >/storage/marker; echo ram-marker >/dev/shm/marker; sync')
    server = start_api()
    status, info = api('GET')
    assert status == 200
    identity = info['runtime']
    target = {'memoryMb':1280} if kind == 'memory' else {'storageGb':2, 'overlayGb':2}
    request = dict(target, expectedRuntime=identity, operationId='qa-interrupted-growth')
    paths = list(root.rglob('smolvm.db'))
    assert len(paths) == 1, paths
    db = sqlite3.connect(paths[0], timeout=.1, isolation_level=None)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(api, 'POST', request)
        deadline = time.monotonic()+15
        while True:
            pending = db.execute('SELECT data FROM vm_resize_intents WHERE name=?', (name,)).fetchone()
            if pending:
                db.execute('BEGIN IMMEDIATE')
                pending = db.execute('SELECT data FROM vm_resize_intents WHERE name=?', (name,)).fetchone()
                if pending:
                    break
                db.execute('ROLLBACK')
            assert not response.done(), 'missed interruption boundary; do not count this as crash coverage'
            assert time.monotonic() < deadline
            time.sleep(.001)
        # The real resize is now unable to publish/finish through SQLite. Wait
        # for evidence of backend growth, then kill only our node API process.
        control = list(root.rglob('control.sock'))
        disks = list(root.rglob('storage.raw')) + list(root.rglob('storage.qcow2'))
        while True:
            if kind == 'memory':
                assert len(control) == 1, control
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(5)
                    s.connect(str(control[0]))
                    s.sendall(b'PROTOTYPE_MEMORY_INFO\n')
                    evidence = s.recv(4096).decode()
                grown = re.search(r'mapped[ =:]268435456\b', evidence) is not None
            else:
                assert len(disks) == 1, disks
                if disks[0].suffix == '.raw':
                    evidence = disks[0].stat().st_size
                else:
                    with open(disks[0], 'rb') as f:
                        header = f.read(32)
                    assert header[:4] == b'QFI\xfb', header[:4]
                    evidence = int.from_bytes(header[24:32], 'big')
                grown = evidence == 2*1024**3
            if grown:
                break
            assert time.monotonic() < deadline, ('backend did not grow', evidence)
            time.sleep(.005)
        print(json.dumps({'captured_boundary':kind, 'backend':evidence, 'journal':json.loads(pending[0])}), flush=True)
        server.kill()
        server.wait(timeout=15)
        db.execute('ROLLBACK')
        try:
            result = response.result(timeout=10)
            assert result[0] != 200, result
        except (OSError, http.client.HTTPException):
            pass
    assert db.execute('SELECT count(*) FROM vm_resize_intents WHERE name=?', (name,)).fetchone()[0] == 1
    assert guest('cat /proc/sys/kernel/random/boot_id') == boot
    if restart_vm:
        cli('stop', '--name', name)
        cli('start', '--name', name)
        assert guest('cat /proc/sys/kernel/random/boot_id') != boot
    server = start_api()
    if restart_vm:
        status, result = api('POST', request)
        assert status == 409, ('stale runtime request was not rejected', status, result)
        status, info = api('GET')
        assert status == 200
        assert info['runtime'] != identity
        identity = info['runtime']
        request = dict(target, expectedRuntime=identity, operationId='qa-restarted-growth')
    status, result = api('POST', request)
    assert status == 200, (status, result)
    assert result['runtime'] == identity
    for k, v in target.items():
        assert result[k] == v, result
    assert db.execute('SELECT count(*) FROM vm_resize_intents WHERE name=?', (name,)).fetchone()[0] == 0
    guest('test "$(cat /storage/marker)" = disk-marker')
    if not restart_vm:
        guest('test "$(cat /dev/shm/marker)" = ram-marker')
    if kind == 'memory':
        guest('mount -o remount,size=1150M /dev/shm; dd if=/dev/zero of=/dev/shm/growth bs=1M count=1060')
    else:
        guest("test $(df -k /storage | tail -1 | awk '{print $2}') -gt 1900000; test $(df -k / | tail -1 | awk '{print $2}') -gt 1900000")
    print(json.dumps({'passed':kind,'root':str(root),'restart_vm':restart_vm}), flush=True)
finally:
    if db is not None:
        if db.in_transaction:
            db.execute('ROLLBACK')
        db.close()
    if server is not None and server.poll() is None:
        server.terminate()
        server.wait(timeout=15)
    cli('delete', '--name', name, '--force', check=False)
    log.close()
