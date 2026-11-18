"""Check integrity boundaries for the guest runtime's source build."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "crun_builder", Path(__file__).resolve().parents[1] / "scripts/build-crun.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BuildInputs(unittest.TestCase):
    def test_changed_download_and_cache_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"pinned source")
            record = {"url": source.as_uri(), "sha256": BUILDER.sha256(source)}
            cached = BUILDER.download(record, root / "cache")
            self.assertEqual(cached.read_bytes(), source.read_bytes())
            cached.write_bytes(b"changed cache")
            with self.assertRaisesRegex(RuntimeError, "invalid digest"):
                BUILDER.download(record, root / "cache")
            cached.unlink()
            source.write_bytes(b"changed server content")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                BUILDER.download(record, root / "cache")
            self.assertEqual(list((root / "cache").iterdir()), [])

    def test_archive_cannot_write_outside_private_tree(self):
        for name, kind, link in [
            ("../escaped", tarfile.REGTYPE, ""),
            ("/escaped", tarfile.REGTYPE, ""),
            ("link", tarfile.SYMTYPE, "../escaped"),
            ("link", tarfile.LNKTYPE, "../escaped"),
            ("device", tarfile.CHRTYPE, ""),
        ]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "input.tar"
                with tarfile.open(archive, "w") as output:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.linkname = link
                    output.addfile(entry)
                with self.assertRaises(RuntimeError):
                    BUILDER.extract(archive, root / "private")
                self.assertFalse((root / "escaped").exists())

    def test_apk_concatenated_streams_and_relative_library_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "input.tar"
            with archive.open("wb") as stream:
                for name in [".PKGINFO", "lib/ld-musl-test.so.1"]:
                    with tarfile.open(fileobj=stream, mode="w") as output:
                        entry = tarfile.TarInfo(name)
                        entry.size = 7
                        output.addfile(entry, io.BytesIO(b"library"))
                with tarfile.open(fileobj=stream, mode="w") as output:
                    entry = tarfile.TarInfo("usr/lib/libc.so")
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "../../lib/ld-musl-test.so.1"
                    output.addfile(entry)
            BUILDER.extract(archive, root / "private", ("lib/", "usr/lib/"))
            self.assertEqual((root / "private/usr/lib/libc.so").read_bytes(), b"library")
            self.assertFalse((root / "private/.PKGINFO").exists())


if __name__ == "__main__":
    unittest.main()
