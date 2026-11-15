import os
from pathlib import Path
import stat
import tempfile
import unittest

from runtime_bundle import seal_runtime


@unittest.skipUnless(os.name == 'posix', 'macOS bundle permissions require POSIX')
class RuntimeBundleTests(unittest.TestCase):
    def test_signed_resources_remain_readable_and_executable_but_not_writable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'engine'
            root.mkdir()
            executable = root / 'smolvm'
            executable.write_text('#!/bin/sh\nexit 0\n')
            executable.chmod(0o755)
            nested = root / 'runtime'
            nested.mkdir()
            template = nested / 'storage-template.ext4.zst'
            template.write_bytes(b'compressed fixture')
            seal_runtime(root)
            self.assertTrue(os.access(executable, os.X_OK))
            self.assertEqual(template.read_bytes(), b'compressed fixture')
            self.assertEqual(stat.S_IMODE(root.stat().st_mode) & 0o222, 0)
            self.assertEqual(stat.S_IMODE(nested.stat().st_mode) & 0o222, 0)
            if os.geteuid() != 0:
                with self.assertRaises(PermissionError):
                    (root / 'storage-template.ext4').write_bytes(b'expanded')
                with self.assertRaises(PermissionError):
                    template.write_bytes(b'changed')

    def test_guest_symlinks_do_not_change_host_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'engine'
            root.mkdir()
            outside = base / 'outside'
            outside.mkdir()
            payload = outside / 'host-file'
            payload.write_bytes(b'untouched')
            directory_mode = outside.stat().st_mode
            file_mode = payload.stat().st_mode
            (root / 'guest-directory').symlink_to(outside, target_is_directory=True)
            (root / 'guest-file').symlink_to(payload)
            (root / 'guest-missing').symlink_to(base / 'missing')
            seal_runtime(root)
            self.assertEqual(outside.stat().st_mode, directory_mode)
            self.assertEqual(payload.stat().st_mode, file_mode)
            self.assertEqual(payload.read_bytes(), b'untouched')


if __name__ == '__main__':
    unittest.main()
