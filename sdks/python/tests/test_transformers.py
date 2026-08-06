import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from smolvm_rollout.integrations import (
    add_transformers_forkpoint,
    transformers_forkpoint_callback,
)


class FakeTrainerCallback:
    pass


class FakeTrainer:
    def __init__(self):
        self.callbacks = []

    def add_callback(self, callback):
        self.callbacks.append(callback)


class TransformersForkpointTests(unittest.TestCase):
    def transformers_module(self, seeds):
        module = types.ModuleType("transformers")
        module.TrainerCallback = FakeTrainerCallback
        module.set_seed = seeds.append
        return module

    def test_callback_releases_once_imports_identity_and_reseeds(self):
        seeds = []
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / "fork-env"
            env_path.write_text(
                "SMOLVM_FORK_INDEX=3\nSMOLVM_FORK_NAME=worker-3\nVALUE=a=b c\n"
            )
            args = SimpleNamespace(seed=42, data_seed=7)
            control = object()
            with (
                mock.patch.dict(
                    sys.modules,
                    {"transformers": self.transformers_module(seeds)},
                ),
                mock.patch(
                    "smolvm_rollout.integrations.transformers.subprocess.run"
                ) as run,
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                callback = transformers_forkpoint_callback(
                    command=("fork-ready", "--test"), env_path=env_path
                )
                self.assertIs(callback.on_train_begin(args, None, control), control)
                self.assertIs(callback.on_train_begin(args, None, control), control)
                self.assertEqual(os.environ["SMOLVM_FORK_NAME"], "worker-3")
                self.assertEqual(os.environ["VALUE"], "a=b c")

            run.assert_called_once_with(
                ("fork-ready", "--test", "--cuda-preload-modules"), check=True
            )
            self.assertTrue(callback.released)
            self.assertEqual(callback.fork_env["SMOLVM_FORK_INDEX"], "3")
            self.assertEqual(callback.seed, 45)
            self.assertEqual(seeds, [45])
            self.assertEqual(args.seed, 45)
            self.assertEqual(args.data_seed, 45)

    def test_explicit_seed_takes_precedence_over_index(self):
        seeds = []
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / "fork-env"
            env_path.write_text("SMOLVM_FORK_INDEX=3\nSMOLVM_FORK_SEED=99\n")
            args = SimpleNamespace(seed=42, data_seed=None)
            with (
                mock.patch.dict(
                    sys.modules,
                    {"transformers": self.transformers_module(seeds)},
                ),
                mock.patch(
                    "smolvm_rollout.integrations.transformers.subprocess.run"
                ),
            ):
                callback = transformers_forkpoint_callback(env_path=env_path)
                callback.on_train_begin(args, None, object())

            self.assertEqual(seeds, [99])
            self.assertEqual(args.seed, 99)
            self.assertEqual(args.data_seed, 99)

    def test_invalid_environment_does_not_repeat_consumed_forkpoint(self):
        seeds = []
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / "fork-env"
            env_path.write_text("not valid\n")
            with (
                mock.patch.dict(
                    sys.modules,
                    {"transformers": self.transformers_module(seeds)},
                ),
                mock.patch(
                    "smolvm_rollout.integrations.transformers.subprocess.run"
                ) as run,
            ):
                callback = transformers_forkpoint_callback(env_path=env_path)
                with self.assertRaisesRegex(ValueError, "invalid fork environment"):
                    callback.on_train_begin(SimpleNamespace(seed=1), None, object())
                callback.on_train_begin(SimpleNamespace(seed=1), None, object())

            run.assert_called_once()
            self.assertTrue(callback.released)

    def test_add_helper_attaches_callback(self):
        seeds = []
        trainer = FakeTrainer()
        with mock.patch.dict(
            sys.modules,
            {"transformers": self.transformers_module(seeds)},
        ):
            callback = add_transformers_forkpoint(trainer, command="fork-ready")
        self.assertEqual(trainer.callbacks, [callback])

    def test_cuda_module_preload_can_be_disabled(self):
        seeds = []
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / "fork-env"
            env_path.write_text("")
            with (
                mock.patch.dict(
                    sys.modules,
                    {"transformers": self.transformers_module(seeds)},
                ),
                mock.patch(
                    "smolvm_rollout.integrations.transformers.subprocess.run"
                ) as run,
            ):
                callback = transformers_forkpoint_callback(
                    command="fork-ready",
                    env_path=env_path,
                    preload_cuda_modules=False,
                )
                callback.on_train_begin(SimpleNamespace(seed=1), None, object())

            run.assert_called_once_with(("fork-ready",), check=True)

    def test_factory_reports_missing_transformers(self):
        with mock.patch.dict(sys.modules, {"transformers": None}):
            with self.assertRaisesRegex(RuntimeError, "requires the transformers"):
                transformers_forkpoint_callback()


if __name__ == "__main__":
    unittest.main()
