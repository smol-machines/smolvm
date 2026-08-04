"""Transformers integration for prepared smolvm forkpoints."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Sequence


_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _read_fork_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    values = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line:
            continue
        key, separator, value = line.partition("=")
        if not separator or _ENV_KEY.fullmatch(key) is None:
            raise ValueError(f"invalid fork environment at {path}:{line_number}")
        values[key] = value
    return values


def transformers_forkpoint_callback(
    *,
    command: str | Sequence[str] = "smolvm-fork-ready",
    env_path: str | Path = "/etc/smolvm/fork-env",
    reseed: bool = True,
    preload_cuda_modules: bool = True,
):
    """Fork after trainer preparation and preload clone CUDA modules by default."""
    try:
        from transformers import TrainerCallback, set_seed
    except ImportError as error:
        raise RuntimeError(
            "transformers_forkpoint_callback requires the transformers package"
        ) from error

    argv = (command,) if isinstance(command, str) else tuple(command)
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise ValueError("forkpoint command must contain non-empty strings")
    if preload_cuda_modules and "--cuda-preload-modules" not in argv:
        argv += ("--cuda-preload-modules",)
    fork_env_path = Path(env_path)

    class SmolvmTrainerForkpointCallback(TrainerCallback):
        def __init__(self):
            self.released = False
            self.fork_env: dict[str, str] = {}
            self.seed: int | None = None

        def on_train_begin(self, args, _state, control, **_kwargs):
            if self.released:
                return control

            subprocess.run(argv, check=True)
            self.released = True
            self.fork_env = _read_fork_env(fork_env_path)
            os.environ.update(self.fork_env)

            if reseed:
                seed_text = self.fork_env.get("SMOLVM_FORK_SEED")
                if seed_text is None:
                    index = self.fork_env.get("SMOLVM_FORK_INDEX")
                    if index is not None:
                        seed_text = str(int(getattr(args, "seed", 0) or 0) + int(index))
                if seed_text is not None:
                    self.seed = int(seed_text) % (2**32)
                    set_seed(self.seed)
                    if hasattr(args, "seed"):
                        args.seed = self.seed
                    if hasattr(args, "data_seed"):
                        args.data_seed = self.seed

            return control

    return SmolvmTrainerForkpointCallback()


def add_transformers_forkpoint(trainer, **options):
    """Attach the prepared forkpoint callback to a Transformers trainer."""
    callback = transformers_forkpoint_callback(**options)
    trainer.add_callback(callback)
    return callback
