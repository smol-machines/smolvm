"""Keep signed macOS runtime resources immutable after first use."""
import os
from pathlib import Path
import stat


def seal_runtime(root: Path):
    """Force runtime disk-template expansion to use its existing user-cache fallback.

    Never follow guest filesystem symlinks: their absolute targets belong to
    the guest, not to the host running the packager.
    """
    if root.is_symlink() or not root.is_dir():
        raise ValueError('A runtime bundle must be a real directory.')
    for directory, subdirectories, files in os.walk(root, topdown=False, followlinks=False):
        for name in files + subdirectories:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o222)
    root.chmod(stat.S_IMODE(root.stat().st_mode) & ~0o222)
