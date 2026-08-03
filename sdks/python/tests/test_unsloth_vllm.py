import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from smolvm_rollout import UnslothVllmExecutor


@dataclass
class FakeRequest:
    lora_name: str
    lora_int_id: int
    lora_tensors: object | None = None
    lora_config: object | None = None


class FakeEngine:
    def __init__(self):
        self.adapters = {}
        self.added = []
        self.removed = []

    def add_lora(self, request):
        self.added.append(request)
        self.adapters[request.lora_int_id] = request
        return True

    def remove_lora(self, adapter_id):
        self.removed.append(adapter_id)
        return self.adapters.pop(adapter_id, None) is not None

    def list_loras(self):
        return set(self.adapters)


class FakeLogprob:
    def __init__(self, value, rank, token):
        self.logprob = value
        self.rank = rank
        self.decoded_token = token


class FakeCompletion:
    def __init__(self, request, prompt):
        self.text = f"{request.lora_name}:{prompt}"
        self.token_ids = [request.lora_int_id, 17]
        self.logprobs = [{request.lora_int_id: FakeLogprob(-0.25, 1, "x")}]
        self.finish_reason = "length"
        self.stop_reason = None


class FakeOutput:
    def __init__(self, request, prompt):
        self.prompt_token_ids = (
            prompt if isinstance(prompt, list) else [ord(value) for value in prompt]
        )
        self.outputs = [FakeCompletion(request, prompt)]


class FakeModel:
    def __init__(self):
        self.engine = FakeEngine()
        self.vllm_engine = SimpleNamespace(llm_engine=self.engine)
        self.loads = []
        self.generate_calls = []

    def load_lora(self, path, *, load_tensors, lora_request_id):
        self.loads.append((path, load_tensors, lora_request_id))
        return FakeRequest(Path(path).name, lora_request_id)

    def fast_generate(
        self, prompts, *, sampling_params, lora_request, use_tqdm
    ):
        self.generate_calls.append(
            (list(prompts), list(sampling_params), list(lora_request), use_tqdm)
        )
        return [
            FakeOutput(request, prompt)
            for request, prompt in zip(lora_request, prompts)
        ]


class FakeImported:
    def __init__(self):
        self.tensors = {"lora": object()}
        self.adapter_config = {"r": 16}
        self.closed = False

    def close(self):
        self.closed = True


def request_factory(name, adapter_id, tensors, config):
    return FakeRequest(name, adapter_id, tensors, config)


def executor(model, socket_path, **options):
    configuration = {
        "port": 0,
        "batch_window_ms": 50,
        "request_timeout_secs": 2,
        "_request_factory": request_factory,
        "_sampling_factory": lambda **values: values,
        "_synchronize": lambda: None,
    }
    configuration.update(options)
    return UnslothVllmExecutor(model, socket_path, **configuration)


def json_request(endpoint, path, body=None):
    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"{endpoint}{path}",
        data=payload,
        method="GET" if body is None else "POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        finally:
            error.close()


class UnslothVllmExecutorTests(unittest.TestCase):
    def test_rejects_non_loopback_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "loopback"):
                executor(
                    FakeModel(),
                    Path(directory) / "device.sock",
                    host="0.0.0.0",
                )

    def test_shared_model_lock_must_be_reentrant(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "reentrant"):
                executor(
                    FakeModel(),
                    Path(directory) / "device.sock",
                    model_lock=threading.Lock(),
                )
            service = executor(
                FakeModel(),
                Path(directory) / "device.sock",
                model_lock=threading.RLock(),
            )
            self.assertIsNotNone(service)

    def test_partial_start_failure_does_not_deadlock(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "device.sock"
            socket_path.write_text("not a socket")
            service = executor(FakeModel(), socket_path)
            errors = []

            thread = threading.Thread(
                target=lambda: self._capture_start_error(service, errors), daemon=True
            )
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIn("non-socket", str(errors[0]))

    @staticmethod
    def _capture_start_error(service, errors):
        try:
            service.start()
        except Exception as error:
            errors.append(error)

    def test_filesystem_load_is_unique_and_drained_on_shutdown(self):
        model = FakeModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(model, Path(directory) / "device.sock")
            service.start()
            try:
                body = {"lora_name": "policy-a", "lora_path": "/adapters/a"}
                self.assertEqual(
                    json_request(service.endpoint, "/v1/load_lora_adapter", body)[0],
                    200,
                )
                status, response = json_request(
                    service.endpoint, "/v1/load_lora_adapter", body
                )
                self.assertEqual(status, 409)
                self.assertIn("already loaded", response["error"])
                self.assertEqual(len(model.loads), 1)
                status, response = json_request(service.endpoint, "/v1/models")
                self.assertEqual(status, 200)
                self.assertEqual(response["data"], [{"id": "policy-a"}])
            finally:
                service.shutdown()
            self.assertEqual(model.engine.adapters, {})
            self.assertEqual(
                model.engine.removed, [model.engine.added[0].lora_int_id]
            )

    def test_device_load_inserts_without_dummy_generation(self):
        model = FakeModel()
        imported = FakeImported()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(
                model,
                Path(directory) / "device.sock",
                _import_adapter=lambda _bundle: imported,
            )
            owner = service._load_device("policy-device", object())
            self.assertEqual(service.models(), ("policy-device",))
            self.assertEqual(len(model.engine.added), 1)
            self.assertEqual(model.generate_calls, [])
            service._unload_device("policy-device", owner)
            owner.close()
            self.assertTrue(imported.closed)
            self.assertEqual(
                model.engine.removed, [model.engine.added[0].lora_int_id]
            )

    def test_adapter_ids_skip_existing_engine_allocations(self):
        model = FakeModel()
        model.engine.adapters[1_000_000_000] = FakeRequest("external", 1_000_000_000)
        imported = FakeImported()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(
                model,
                Path(directory) / "device.sock",
                _import_adapter=lambda _bundle: imported,
            )
            owner = service._load_device("policy-device", object())
            self.assertEqual(owner.request.lora_int_id, 1_000_000_001)
            service._unload_device("policy-device", owner)
            owner.close()

    def test_failed_install_rollback_retains_device_mapping_for_unload(self):
        model = FakeModel()
        imported = FakeImported()
        synchronizations = 0
        fail_remove = True

        def synchronize():
            nonlocal synchronizations
            synchronizations += 1
            if synchronizations == 1:
                raise RuntimeError("injected synchronize failure")

        original_remove = model.engine.remove_lora

        def remove(adapter_id):
            if fail_remove:
                raise RuntimeError("injected rollback failure")
            return original_remove(adapter_id)

        model.engine.remove_lora = remove
        with tempfile.TemporaryDirectory() as directory:
            service = UnslothVllmExecutor(
                model,
                Path(directory) / "device.sock",
                port=0,
                _import_adapter=lambda _bundle: imported,
                _request_factory=request_factory,
                _sampling_factory=lambda **values: values,
                _synchronize=synchronize,
            )
            owner = service._load_device("uncertain", object())
            self.assertTrue(service._stopping.is_set())
            self.assertFalse(imported.closed)
            self.assertEqual(service.models(), ("uncertain",))
            fail_remove = False
            service._unload_device("uncertain", owner)
            owner.close()
            self.assertTrue(imported.closed)
            self.assertEqual(service.models(), ())

    def test_concurrent_policies_are_coalesced_and_json_safe(self):
        model = FakeModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(
                model,
                Path(directory) / "device.sock",
                batch_window_ms=200,
            )
            service._insert("policy-a", FakeRequest("policy-a", 11), "filesystem")
            service._insert("policy-b", FakeRequest("policy-b", 12), "filesystem")
            with service:
                barrier = threading.Barrier(3)
                results = []
                errors = []

                def generate(policy, prompt):
                    try:
                        barrier.wait(timeout=2)
                        results.append(
                            json_request(
                                service.endpoint,
                                "/v1/completions",
                                {
                                    "model": policy,
                                    "prompt": [prompt],
                                    "n": 1,
                                    "max_tokens": 2,
                                    "logprobs": 1,
                                },
                            )
                        )
                    except Exception as error:
                        errors.append(error)

                threads = [
                    threading.Thread(target=generate, args=("policy-a", "one")),
                    threading.Thread(target=generate, args=("policy-b", "two")),
                ]
                for thread in threads:
                    thread.start()
                barrier.wait(timeout=2)
                for thread in threads:
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())

                self.assertEqual(errors, [])
                self.assertEqual([status for status, _ in results], [200, 200])
                self.assertEqual(len(model.generate_calls), 1)
                prompts, sampling, requests, use_tqdm = model.generate_calls[0]
                self.assertEqual(set(prompts), {"one", "two"})
                self.assertEqual(
                    {request.lora_name for request in requests},
                    {"policy-a", "policy-b"},
                )
                self.assertEqual(len(sampling), 2)
                self.assertFalse(use_tqdm)
                for _, response in results:
                    logprob = response["choices"][0]["logprobs"][0]
                    value = next(iter(logprob.values()))
                    self.assertEqual(value["logprob"], -0.25)
                    self.assertEqual(value["rank"], 1)

    def test_request_larger_than_batch_limit_fails_without_queuing(self):
        model = FakeModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(
                model,
                Path(directory) / "device.sock",
                max_batch_prompts=1,
            )
            service._insert("policy-a", FakeRequest("policy-a", 1), "filesystem")
            with service:
                status, response = json_request(
                    service.endpoint,
                    "/v1/completions",
                    {
                        "model": "policy-a",
                        "prompt": ["one", "two"],
                        "n": 1,
                        "max_tokens": 2,
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn("batch prompt limit", response["error"])
                self.assertEqual(model.generate_calls, [])

    def test_sampling_and_streaming_are_validated_before_queueing(self):
        model = FakeModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(model, Path(directory) / "device.sock")
            service._insert("policy-a", FakeRequest("policy-a", 1), "filesystem")
            with service:
                base = {
                    "model": "policy-a",
                    "prompt": [[1, 2]],
                    "n": 1,
                    "max_tokens": 2,
                }
                for field, value in (
                    ("stream", True),
                    ("temperature", float("nan")),
                    ("top_p", 2),
                    ("top_k", 0),
                    ("seed", -1),
                ):
                    status, _ = json_request(
                        service.endpoint,
                        "/v1/completions",
                        {**base, field: value},
                    )
                    self.assertEqual(status, 400, field)
                self.assertEqual(model.generate_calls, [])

    def test_shutdown_drains_an_inflight_generation_before_unload(self):
        class BlockingModel(FakeModel):
            def __init__(self):
                super().__init__()
                self.entered = threading.Event()
                self.release = threading.Event()

            def fast_generate(self, *args, **kwargs):
                self.entered.set()
                if not self.release.wait(2):
                    raise RuntimeError("test generation was not released")
                return super().fast_generate(*args, **kwargs)

        model = BlockingModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(model, Path(directory) / "device.sock")
            service._insert("policy-a", FakeRequest("policy-a", 1), "filesystem")
            service.start()
            responses = []
            request_thread = threading.Thread(
                target=lambda: responses.append(
                    json_request(
                        service.endpoint,
                        "/v1/completions",
                        {
                            "model": "policy-a",
                            "prompt": ["one"],
                            "n": 1,
                            "max_tokens": 2,
                        },
                    )
                )
            )
            request_thread.start()
            self.assertTrue(model.entered.wait(2))
            shutdown_errors = []
            shutdown_thread = threading.Thread(
                target=lambda: self._capture_shutdown_error(
                    service, shutdown_errors
                )
            )
            shutdown_thread.start()
            time.sleep(0.05)
            self.assertTrue(shutdown_thread.is_alive())
            self.assertEqual(model.engine.removed, [])
            model.release.set()
            request_thread.join(timeout=2)
            shutdown_thread.join(timeout=2)
            self.assertFalse(request_thread.is_alive())
            self.assertFalse(shutdown_thread.is_alive())
            self.assertEqual(shutdown_errors, [])
            self.assertEqual(responses[0][0], 200)
            self.assertEqual(model.engine.removed, [1])

    def test_timed_out_shutdown_retains_state_for_cleanup_retry(self):
        class StalledModel(FakeModel):
            def __init__(self):
                super().__init__()
                self.entered = threading.Event()
                self.release = threading.Event()

            def fast_generate(self, *args, **kwargs):
                self.entered.set()
                self.release.wait(2)
                return super().fast_generate(*args, **kwargs)

        model = StalledModel()
        with tempfile.TemporaryDirectory() as directory:
            service = executor(
                model,
                Path(directory) / "device.sock",
                request_timeout_secs=0.1,
            )
            service._insert("policy-a", FakeRequest("policy-a", 1), "filesystem")
            service.start()
            response = []
            request_thread = threading.Thread(
                target=lambda: response.append(
                    json_request(
                        service.endpoint,
                        "/v1/completions",
                        {
                            "model": "policy-a",
                            "prompt": ["one"],
                            "n": 1,
                            "max_tokens": 2,
                        },
                    )
                )
            )
            request_thread.start()
            self.assertTrue(model.entered.wait(2))
            request_thread.join(timeout=2)
            self.assertEqual(response[0][0], 504)
            with self.assertRaisesRegex(RuntimeError, "did not stop"):
                service.shutdown()
            self.assertEqual(service.models(), ("policy-a",))
            self.assertEqual(model.engine.removed, [])
            with self.assertRaisesRegex(RuntimeError, "cleanup is incomplete"):
                service.start()
            model.release.set()
            deadline = time.monotonic() + 2
            while service._batch_thread is not None and service._batch_thread.is_alive():
                if time.monotonic() >= deadline:
                    self.fail("batch thread did not finish after release")
                time.sleep(0.01)
            service.shutdown()
            self.assertEqual(service.models(), ())
            self.assertEqual(model.engine.removed, [1])

    @staticmethod
    def _capture_shutdown_error(service, errors):
        try:
            service.shutdown()
        except Exception as error:
            errors.append(error)


if __name__ == "__main__":
    unittest.main()
