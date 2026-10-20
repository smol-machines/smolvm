#!/usr/bin/env python3
"""Restore one fresh incremental checkpoint from the node cache many times at once.

Run against a dedicated privileged local serve:
    python3 tests/test_api_concurrent_chunked_restore.py http://127.0.0.1:8080
Only uniquely named test machines are deleted. Requires registry access.
"""
import concurrent.futures
import json
import sys
import urllib.error
import urllib.request
import uuid

RESTORES = 8


def main():
    base = sys.argv[1].rstrip('/') + '/api/v1/machines'
    prefix = 'chunked-restore-' + uuid.uuid4().hex[:10]
    source = prefix + '-source'
    key = 'ckpt-' + uuid.uuid4().hex
    children = [f'{prefix}-child{n}' for n in range(RESTORES)]

    def request(method, path, data=None, content_type='application/json'):
        request = urllib.request.Request(base + path, method=method, data=data,
            headers={'Content-Type': content_type})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def call(method, path, payload=None):
        status, body = request(method, path, json.dumps(payload or {}).encode())
        assert status < 300, (path, status, body)
        return json.loads(body) if body else None

    def restore(name):
        return name, *request('PUT', f'/{name}/checkpoint?cache_key={key}', b'',
            'application/vnd.smolmachines.checkpoint')

    try:
        call('POST', '', {'name': source, 'image': 'alpine', 'cpus': 1,
            'memoryMb': 512, 'storageGb': 2, 'overlayGb': 1})
        call('POST', f'/{source}/start?branchable=true')
        result = call('POST', f'/{source}/exec',
            {'command': ['sh', '-c', 'echo restored >/root/marker']})
        assert result['exitCode'] == 0, result
        # A fresh incremental capture is chunked and not yet materialized, so
        # every restore below races to prepare the same shared tree.
        status, body = request('POST', f'/{source}/checkpoint?cache_key={key}&incremental=true')
        assert status == 200 and body, (status, body[:200])
        with concurrent.futures.ThreadPoolExecutor(RESTORES) as pool:
            results = list(pool.map(restore, children))
        failed = [(name, status, body[:200]) for name, status, body in results if status >= 300]
        assert not failed, failed
        for name in children:
            call('POST', f'/{name}/start')
            result = call('POST', f'/{name}/exec', {'command': ['cat', '/root/marker']})
            assert result['stdout'] == 'restored\n', (name, result)
        print(f'PASS: {RESTORES} overlapping restores of one fresh chunked checkpoint')
    finally:
        for name in children + [source]:
            request('DELETE', f'/{name}?force=true')


if __name__ == '__main__':
    main()
