import tempfile
import unittest
from unittest import mock
from pathlib import Path

from smolvm_rollout import RolloutClient, RolloutError, adapter_sha256


class AdapterDigestTests(unittest.TestCase):
    def test_digest_is_stable_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "adapter_config.json").write_bytes(b"{}")
            (root / "adapter_model.safetensors").write_bytes(b"weights")
            first = adapter_sha256(root)
            self.assertEqual(
                first,
                "26d1c7593b9650cb489a9a1fe2fad9def32c75ec2685cf8261c3c0fa3b73e315",
            )
            self.assertEqual(first, adapter_sha256(root))
            (root / "adapter_model.safetensors").write_bytes(b"changed")
            self.assertNotEqual(first, adapter_sha256(root))


class RecordingClient(RolloutClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:1/api/v1", "fused")
        self.recorded = None

    def _request(self, method, path, body=None):
        self.recorded = (method, path, body)
        return {"ok": True}


class LeaseDiscoveryTests(unittest.TestCase):
    def test_no_argument_client_reads_clone_assignment_and_authenticates(self):
        with tempfile.TemporaryDirectory() as directory:
            assignment = Path(directory) / "fork-env"
            assignment.write_text(
                "SMOLVM_ROLLOUT_URL=http://100.96.0.1:10081/api/v1/rollout-executors/fused\n"
                "SMOLVM_ROLLOUT_TOKEN=lease-id.secret\n"
                "SMOLVM_ROLLOUT_EXECUTOR=fused\n"
                "SMOLVM_ROLLOUT_POLICY=experiment-a\n",
                encoding="utf-8",
            )
            with mock.patch.dict("os.environ", {}, clear=True):
                client = RolloutClient(fork_env_path=assignment)
            self.assertEqual(client.api_url, "http://100.96.0.1:10081/api/v1")
            self.assertEqual(client.executor, "fused")
            self.assertEqual(client.bearer_token, "lease-id.secret")
            self.assertEqual(client.lease_policy, "experiment-a")

            with mock.patch("urllib.request.urlopen") as urlopen:
                response = urlopen.return_value.__enter__.return_value
                response.read.return_value = b"{}"
                client.generate(
                    idempotency_key="request",
                    policy="experiment-a",
                    prompts=["hello"],
                    max_tokens=1,
                )
                request = urlopen.call_args.args[0]
                self.assertEqual(
                    request.get_header("Authorization"), "Bearer lease-id.secret"
                )

    def test_environment_overrides_assignment_after_clone_release(self):
        with tempfile.TemporaryDirectory() as directory:
            assignment = Path(directory) / "fork-env"
            assignment.write_text(
                "SMOLVM_ROLLOUT_URL=http://100.96.0.1:10081/api/v1/rollout-executors/file\n"
                "SMOLVM_ROLLOUT_TOKEN=file-token\n"
                "SMOLVM_ROLLOUT_EXECUTOR=file\n"
                "SMOLVM_ROLLOUT_POLICY=file-policy\n",
                encoding="utf-8",
            )
            environment = {
                "SMOLVM_ROLLOUT_URL": "http://127.0.0.1:1/api/v1/rollout-executors/env",
                "SMOLVM_ROLLOUT_TOKEN": "env-token",
                "SMOLVM_ROLLOUT_EXECUTOR": "env",
                "SMOLVM_ROLLOUT_POLICY": "env-policy",
            }
            with mock.patch.dict("os.environ", environment, clear=True):
                client = RolloutClient(fork_env_path=assignment)
            self.assertEqual(client.executor, "env")
            self.assertEqual(client.bearer_token, "env-token")
            self.assertEqual(client.lease_policy, "env-policy")

    def test_incomplete_or_inconsistent_assignment_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            assignment = Path(directory) / "fork-env"
            assignment.write_text("SMOLVM_ROLLOUT_TOKEN=secret\n", encoding="utf-8")
            with mock.patch.dict("os.environ", {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "missing"):
                    RolloutClient(fork_env_path=assignment)

            assignment.write_text(
                "SMOLVM_ROLLOUT_URL=http://host/api/v1/rollout-executors/other\n"
                "SMOLVM_ROLLOUT_TOKEN=secret\n"
                "SMOLVM_ROLLOUT_EXECUTOR=fused\n"
                "SMOLVM_ROLLOUT_POLICY=policy\n",
                encoding="utf-8",
            )
            with mock.patch.dict("os.environ", {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    RolloutClient(fork_env_path=assignment)


class DevicePublicationTests(unittest.TestCase):
    def test_device_token_is_encoded_without_exposing_a_descriptor(self):
        client = RecordingClient()
        response = client.publish_device_policy(
            "policy", "step-1", bytes(range(32))
        )
        self.assertEqual(response, {"ok": True})
        method, path, body = client.recorded
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/rollout-executors/fused/device-policies")
        self.assertEqual(body["tensorBundleToken"], bytes(range(32)).hex())
        self.assertNotIn("adapterSha256", body)

    def test_device_publication_retries_one_ambiguous_transport_failure(self):
        class FlakyClient(RecordingClient):
            def __init__(self):
                super().__init__()
                self.attempts = []

            def _request(self, method, path, body=None):
                self.attempts.append((method, path, body))
                if len(self.attempts) == 1:
                    raise RolloutError(0, "UNAVAILABLE", "lost response")
                return {"ok": True}

        client = FlakyClient()
        self.assertEqual(
            client.publish_device_policy("policy", "step-1", bytes(range(32))),
            {"ok": True},
        )
        self.assertEqual(len(client.attempts), 2)
        self.assertEqual(client.attempts[0], client.attempts[1])


if __name__ == "__main__":
    unittest.main()
