"""Run the vendored stack's upstream unit tests with the engine's features."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
features = (
    "std,log,medium-ethernet,proto-ipv4,proto-ipv6,socket-tcp,socket-udp,"
    "socket-raw,iface-max-addr-count-3,proto-ipv4-fragmentation,"
    "fragmentation-buffer-size-65536,reassembly-buffer-count-16,"
    "assembler-max-segment-count-32"
)
with tempfile.TemporaryDirectory(prefix="smol-smoltcp-tests-") as temporary:
    checkout = Path(temporary) / "smoltcp"
    shutil.copytree(root / "vendor/smoltcp", checkout)
    # Give the upstream tests their own lockfile, separate from product builds.
    original = (checkout / "Cargo.toml.orig").read_text()
    (checkout / "Cargo.toml").write_text(
        original.replace('readme = "README.md"', "readme = false")
    )
    result = subprocess.run(
        ["cargo", "test", "--lib", "--no-default-features", "--features", features],
        cwd=checkout,
        env=os.environ.copy(),
        check=False,
    )
    raise SystemExit(result.returncode)
