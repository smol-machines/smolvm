"""Check the release gate against real thin and universal Mach-O libraries."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "darwin", "requires the Apple compiler and lipo")
class DeploymentTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="smol-macos-target-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        source = cls.root / "fixture.c"
        source.write_text("int fixture(void) { return 0; }\n")
        cls.supported = cls.root / "supported.dylib"
        cls.newer = cls.root / "newer.dylib"
        for arch, version, output in [
            ("arm64", "11.0", cls.supported), ("x86_64", "12.0", cls.newer),
        ]:
            subprocess.run([
                "/usr/bin/clang", "-dynamiclib", "-arch", arch,
                "-mmacosx-version-min=" + version, str(source), "-o", str(output),
            ], check=True)
        cls.universal = cls.root / "universal.dylib"
        subprocess.run([
            "/usr/bin/lipo", "-create", str(cls.supported), str(cls.newer),
            "-output", str(cls.universal),
        ], check=True)
        cls.gate = Path(__file__).resolve().parents[1] / "scripts/check-macos-deployment-target.py"

    def check(self, path):
        return subprocess.run([sys.executable, str(self.gate), str(path)],
                              capture_output=True, text=True)

    def test_supported_library_passes(self):
        print("V2_MARKER_macos_selfhosted")
        result = self.check(self.supported)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newer_library_is_rejected(self):
        result = self.check(self.newer)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires macOS 12.0.0", result.stderr)

    def test_one_unsupported_slice_rejects_the_universal_library(self):
        result = self.check(self.universal)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires macOS 12.0.0", result.stderr)

    def test_truncated_and_lfs_placeholder_files_are_rejected(self):
        invalid = self.root / "invalid.dylib"
        for data in [self.supported.read_bytes()[:32], b"version https://git-lfs.github.com/spec/v1\n"]:
            invalid.write_bytes(data)
            self.assertNotEqual(self.check(invalid).returncode, 0)


if __name__ == "__main__":
    unittest.main()
