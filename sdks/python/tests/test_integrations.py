import subprocess
import sys
import unittest


class IntegrationBoundaryTests(unittest.TestCase):
    def test_core_import_does_not_load_or_export_framework_adapters(self):
        script = """
import sys
import smolvm_rollout

assert "smolvm_rollout.integrations" not in sys.modules
for name in (
    "UnslothVllmExecutor",
    "add_transformers_forkpoint",
    "peft_lora_tensors",
    "publish_peft_adapter",
):
    assert not hasattr(smolvm_rollout, name), name
"""
        subprocess.run([sys.executable, "-c", script], check=True)


if __name__ == "__main__":
    unittest.main()
