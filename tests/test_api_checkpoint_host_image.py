#!/usr/bin/env python3
"""Checkpoint a machine with no network whose registry image the host fetched,
and restore it on a host that never fetched that image.

Run against two dedicated privileged local serves with separate data dirs, the
second one never having fetched the image:
    python3 tests/test_api_checkpoint_host_image.py http://127.0.0.1:8080 http://127.0.0.1:8081
Passing one URL restores on the same host. Only uniquely named test machines
are deleted. Requires registry access on the host.
"""
import json
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

IMAGE = 'python:3.12-slim-bookworm'


def client(url):
    base = url.rstrip('/') + '/api/v1/machines'

    def call(method, path, payload=None):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(payload or {}).encode() if method == 'POST' else None,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=600) as response:
            return json.load(response)

    def execute(name, command):
        return call('POST', '/' + name + '/exec', {'command': ['sh', '-c', command]})

    return base, call, execute


def main():
    source_url = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else source_url
    source_base, source_call, source_exec = client(source_url)
    target_base, target_call, target_exec = client(target_url)
    prefix = 'checkpoint-host-image-' + uuid.uuid4().hex[:10]
    source, restored = prefix + '-source', prefix + '-restored'
    try:
        source_call('POST', '', {'name': source, 'image': IMAGE, 'network': False,
            'cpus': 1, 'memoryMb': 1024, 'storageGb': 4, 'overlayGb': 2})
        source_call('POST', '/' + source + '/start?forkable=true')
        result = source_exec(source, 'echo disk >/root/marker; echo ram >/dev/shm/marker')
        assert result['exitCode'] == 0, result

        with tempfile.TemporaryFile() as artifact:
            request = urllib.request.Request(source_base + '/' + source + '/checkpoint',
                method='POST')
            try:
                with urllib.request.urlopen(request, timeout=600) as response:
                    while block := response.read(1024 * 1024):
                        artifact.write(block)
            except urllib.error.HTTPError as error:
                raise AssertionError('capture failed: ' + error.read().decode()) from None
            artifact.seek(0)
            request = urllib.request.Request(target_base + '/' + restored + '/checkpoint',
                method='PUT', data=artifact.read(),
                headers={'Content-Type': 'application/vnd.smolmachines.checkpoint'})
            try:
                with urllib.request.urlopen(request, timeout=600) as response:
                    info = json.load(response)
            except urllib.error.HTTPError as error:
                raise AssertionError('restore failed: ' + error.read().decode()) from None
        # The checkpoint names the registry image at the digest the source
        # host fetched, never that host's archive.
        assert info['image'].startswith(IMAGE + '@sha256:'), info
        assert not info.get('network'), info

        target_call('POST', '/' + restored + '/start?forkable=true')
        result = target_exec(restored, 'cat /root/marker /dev/shm/marker')
        assert result['exitCode'] == 0 and result['stdout'] == 'disk\nram\n', result
        result = target_exec(restored, 'python3 -c "print(6 * 7)"')
        assert result['exitCode'] == 0 and result['stdout'] == '42\n', result
        result = target_exec(restored, 'python3 -c "import socket; '
            'socket.create_connection((\'1.1.1.1\', 53), timeout=3)"')
        assert result['exitCode'] != 0, 'restored machine reached the network: %s' % result
        # The restored machine keeps working after its first exec.
        result = target_exec(restored, 'echo again >>/root/marker && cat /root/marker')
        assert result['exitCode'] == 0 and result['stdout'] == 'disk\nagain\n', result
        print('PASS: a no-network host-fetched image machine was checkpointed and restored '
              'with its disk and RAM, without network')
    finally:
        for call, name in ((target_call, restored), (source_call, source)):
            try:
                call('DELETE', '/' + name + '?force=true')
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    print('cleanup failed:', name, error.read().decode(), file=sys.stderr)


if __name__ == '__main__':
    main()
