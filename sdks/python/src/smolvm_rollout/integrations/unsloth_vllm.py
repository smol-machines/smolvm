"""Managed, continuously batched rollout endpoint for an embedded Unsloth vLLM."""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from ..device_handoff import DeviceAdapterBundle, DeviceAdapterServer
from ..torch_handoff import import_torch_device_adapter


_MAX_BODY_BYTES = 64 * 1024 * 1024
_MAX_PROMPTS_PER_REQUEST = 4096
_MAX_PROMPT_TEXT_BYTES = 16 * 1024 * 1024
_MAX_PROMPT_TOKENS = 1_048_576
_MAX_COMPLETION_TOKENS = 65_536
_ADAPTER_ID_BASE = 1_000_000_000


class _HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class _InstallRollbackFailure(RuntimeError):
    pass


@dataclass
class _AdapterRecord:
    request: Any
    source: str


@dataclass
class _DeviceOwner:
    imported: Any
    request: Any

    def close(self) -> None:
        self.imported.close()


class _PendingCall:
    def __init__(self, body: dict[str, Any], prompt_kind: str) -> None:
        self.body = body
        self.prompt_kind = prompt_kind
        self.done = threading.Event()
        self.response: dict[str, Any] | None = None
        self.error: Exception | None = None
        self.cancelled = False


class _RolloutHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], executor: "UnslothVllmExecutor") -> None:
        self.executor = executor
        self.request_queue_size = min(max(16, executor.max_queue_depth), 4096)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _RolloutHandler)


class _RolloutHandler(BaseHTTPRequestHandler):
    server: _RolloutHttpServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(min(self.server.executor.request_timeout, 30.0))

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError as error:
            raise _HttpError(400, "invalid content-length") from error
        if length <= 0 or length > _MAX_BODY_BYTES:
            raise _HttpError(400, "request body is empty or exceeds its size limit")
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _HttpError(400, "request body must be JSON") from error
        if not isinstance(body, dict):
            raise _HttpError(400, "request body must be an object")
        return body

    def do_GET(self) -> None:
        if self.path == "/health":
            try:
                self.server.executor._health()
                self._json(200, {"status": "ok"})
            except _HttpError as error:
                self._json(error.status, {"error": str(error)})
            return
        if not self.server.executor._begin_request():
            self._json(503, {"error": "rollout executor is not accepting work"})
            return
        try:
            if self.path == "/v1/models":
                self._json(
                    200,
                    {"data": [{"id": name} for name in self.server.executor.models()]},
                )
            else:
                self._json(404, {"error": "not found"})
        finally:
            self.server.executor._end_request()

    def do_POST(self) -> None:
        if not self.server.executor._begin_request():
            self._json(503, {"error": "rollout executor is not accepting work"})
            return
        try:
            body = self._body()
            if self.path == "/v1/completions":
                self._json(200, self.server.executor._generate(body))
            elif self.path == "/v1/load_lora_adapter":
                self.server.executor._load_filesystem(body)
                self._json(200, {"status": "ok"})
            elif self.path == "/v1/unload_lora_adapter":
                self.server.executor._unload_filesystem(body)
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "not found"})
        except _HttpError as error:
            self._json(error.status, {"error": str(error)})
        except Exception as error:
            self._json(500, {"error": str(error)})
        finally:
            self.server.executor._end_request()


class UnslothVllmExecutor:
    """Serve one embedded Unsloth vLLM as a versioned multi-policy backend.

    The HTTP endpoint is loopback-only and implements the subset of the vLLM
    OpenAI/runtime-LoRA API consumed by smolvm. Concurrent completion requests
    are coalesced into one ``fast_generate`` call with per-prompt LoRA and
    sampling parameters. Device-resident adapters are inserted directly into
    the embedded engine and retained until smolvm acknowledges unload.
    """

    def __init__(
        self,
        model: Any,
        device_socket: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        model_lock: Any | None = None,
        batch_window_ms: float = 5.0,
        max_batch_requests: int = 64,
        max_batch_prompts: int = 4096,
        max_queue_depth: int = 256,
        request_timeout_secs: float = 300.0,
        _import_adapter: Callable[[DeviceAdapterBundle], Any] | None = None,
        _request_factory: Callable[[str, int, dict[str, Any], dict[str, Any]], Any]
        | None = None,
        _sampling_factory: Callable[..., Any] | None = None,
        _synchronize: Callable[[], None] | None = None,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise ValueError("rollout host must be a numeric loopback address") from error
        if not address.is_loopback:
            raise ValueError("rollout host must be loopback")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 0 <= port <= 65535
        ):
            raise ValueError("rollout port must be between 0 and 65535")
        if (
            not isinstance(batch_window_ms, (int, float))
            or isinstance(batch_window_ms, bool)
            or not math.isfinite(batch_window_ms)
            or not 0 <= batch_window_ms <= 1000
        ):
            raise ValueError("batch_window_ms must be between 0 and 1000")
        for name, value in (
            ("max_batch_requests", max_batch_requests),
            ("max_batch_prompts", max_batch_prompts),
            ("max_queue_depth", max_queue_depth),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be positive")
        if (
            not isinstance(request_timeout_secs, (int, float))
            or isinstance(request_timeout_secs, bool)
            or not math.isfinite(request_timeout_secs)
            or request_timeout_secs <= 0
        ):
            raise ValueError("request_timeout_secs must be positive")
        engine = getattr(getattr(model, "vllm_engine", None), "llm_engine", None)
        if engine is None or not callable(getattr(engine, "add_lora", None)):
            raise ValueError("model must expose an embedded Unsloth vLLM engine")
        if not callable(getattr(engine, "remove_lora", None)):
            raise ValueError("embedded Unsloth vLLM engine cannot remove LoRAs")
        if not callable(getattr(model, "fast_generate", None)):
            raise ValueError("model must expose Unsloth fast_generate")
        if model_lock is not None:
            acquire = getattr(model_lock, "acquire", None)
            release = getattr(model_lock, "release", None)
            if not callable(acquire) or not callable(release):
                raise ValueError("model_lock must be a reentrant lock")
            with model_lock:
                if not acquire(blocking=False):
                    raise ValueError("model_lock must be reentrant")
                release()

        self.model = model
        self.device_socket = Path(device_socket)
        if not self.device_socket.is_absolute():
            raise ValueError("device_socket must be an absolute path")
        self.host = host
        self._endpoint_host = f"[{host}]" if address.version == 6 else host
        self.port = port
        self.batch_window = batch_window_ms / 1000.0
        self.max_batch_requests = max_batch_requests
        self.max_batch_prompts = max_batch_prompts
        self.max_queue_depth = max_queue_depth
        self.request_timeout = request_timeout_secs
        self._engine = engine
        self._import_adapter = _import_adapter or import_torch_device_adapter
        self._request_factory = _request_factory or self._default_request
        self._sampling_factory = _sampling_factory or self._default_sampling
        self._synchronize = _synchronize or self._default_synchronize
        self._model_lock = model_lock if model_lock is not None else threading.RLock()
        self._adapters_lock = threading.Lock()
        self._adapters: dict[str, _AdapterRecord] = {}
        self._next_adapter_id = _ADAPTER_ID_BASE
        self._queue: deque[_PendingCall] = deque()
        self._condition = threading.Condition()
        self._request_condition = threading.Condition()
        self._active_requests = 0
        self._stopping = threading.Event()
        self._state_lock = threading.Lock()
        self._started = False
        self._http: _RolloutHttpServer | None = None
        self._http_thread: threading.Thread | None = None
        self._batch_thread: threading.Thread | None = None
        self._device: DeviceAdapterServer | None = None
        self._device_thread: threading.Thread | None = None
        self._thread_error: Exception | None = None
        self._device_cleanup_error: Exception | None = None

    @property
    def endpoint(self) -> str:
        http = self._http
        port = http.server_address[1] if http is not None else self.port
        return f"http://{self._endpoint_host}:{port}"

    def __enter__(self) -> "UnslothVllmExecutor":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.shutdown()

    def start(self) -> "UnslothVllmExecutor":
        """Bind both private endpoints and start background serving threads."""

        with self._state_lock:
            if self._started:
                return self
            if any(
                value is not None
                for value in (
                    self._http,
                    self._http_thread,
                    self._batch_thread,
                    self._device,
                    self._device_thread,
                )
            ):
                raise RuntimeError(
                    "rollout executor cleanup is incomplete; call shutdown again"
                )
            self._stopping.clear()
            self._thread_error = None
            self._device_cleanup_error = None
            try:
                self._http = _RolloutHttpServer((self.host, self.port), self)
                self._device = DeviceAdapterServer(
                    self.device_socket,
                    load_adapter=self._load_device,
                    unload_adapter=self._unload_device,
                    io_timeout_secs=self.request_timeout,
                )
                self._device_thread = threading.Thread(
                    target=self._run_device,
                    name="smolvm-device-adapters",
                    daemon=True,
                )
                self._batch_thread = threading.Thread(
                    target=self._run_batch,
                    name="smolvm-rollout-batcher",
                    daemon=True,
                )
                self._http_thread = threading.Thread(
                    target=self._run_http,
                    name="smolvm-rollout-http",
                    daemon=True,
                )
                self._device_thread.start()
                deadline = time.monotonic() + min(self.request_timeout, 30.0)
                while not self._device.ready:
                    if self._thread_error is not None:
                        raise self._thread_error
                    if time.monotonic() >= deadline:
                        raise TimeoutError("device adapter server did not become ready")
                    time.sleep(0.01)
                if self._thread_error is not None:
                    raise self._thread_error
                self._batch_thread.start()
                self._http_thread.start()
                self._started = True
            except Exception:
                self._shutdown_locked()
                raise
        return self

    def serve_forever(self) -> None:
        """Start the executor and block until ``shutdown`` is called."""

        self.start()
        thread = self._http_thread
        if thread is not None:
            thread.join()
        if self._thread_error is not None:
            raise self._thread_error

    def shutdown(self) -> None:
        """Reject queued work, stop listeners, and unload retained adapters."""

        with self._state_lock:
            self._shutdown_locked()

    def _shutdown_locked(self) -> None:
        self._stopping.set()
        with self._condition:
            while self._queue:
                call = self._queue.popleft()
                call.error = RuntimeError("rollout executor is shutting down")
                call.done.set()
            self._condition.notify_all()
        http = self._http
        http_thread = self._http_thread
        if http is not None and http_thread is not None and http_thread.is_alive():
            http.shutdown()
        deadline = time.monotonic() + min(self.request_timeout, 30.0)
        with self._request_condition:
            while self._active_requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._request_condition.wait(remaining)
            active_requests = self._active_requests
        cleanup_error = self._thread_error
        can_unload = active_requests == 0
        if not can_unload:
            cleanup_error = cleanup_error or RuntimeError(
                f"{active_requests} rollout requests did not drain"
            )
        device = self._device
        if device is not None and can_unload:
            device.shutdown()
        current = threading.current_thread()
        for thread in (self._http_thread, self._batch_thread, self._device_thread):
            if thread is self._device_thread and not can_unload:
                continue
            if (
                thread is not None
                and thread is not current
                and thread.ident is not None
            ):
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        live_threads = []
        for thread in (self._http_thread, self._batch_thread, self._device_thread):
            if thread is self._device_thread and not can_unload:
                continue
            if thread is not None and thread is not current and thread.is_alive():
                live_threads.append(thread)
                cleanup_error = cleanup_error or RuntimeError(
                    f"rollout thread {thread.name!r} did not stop"
                )
        can_cleanup = can_unload and not live_threads
        cleanup_failed = False
        if can_cleanup and device is not None:
            try:
                device.drain()
                self._device_cleanup_error = None
            except Exception as error:
                cleanup_failed = True
                self._device_cleanup_error = error
                cleanup_error = cleanup_error or error
        if can_cleanup:
            for name in self._filesystem_models():
                try:
                    self._remove(name, "filesystem")
                except Exception as error:
                    cleanup_failed = True
                    cleanup_error = cleanup_error or error
        can_cleanup = can_cleanup and not cleanup_failed
        if http is not None:
            http.server_close()
        self._started = False
        if can_cleanup:
            self._http = None
            self._http_thread = None
            self._batch_thread = None
            self._device = None
            self._device_thread = None
            self._thread_error = None
            self._device_cleanup_error = None
        if cleanup_error is not None:
            raise cleanup_error

    def _begin_request(self) -> bool:
        with self._request_condition:
            if self._stopping.is_set() or not self._started:
                return False
            self._active_requests += 1
            return True

    def _end_request(self) -> None:
        with self._request_condition:
            self._active_requests -= 1
            if self._active_requests == 0:
                self._request_condition.notify_all()

    def _health(self) -> None:
        error = self._thread_error
        if error is not None:
            raise _HttpError(503, f"rollout executor failed: {error}")
        if self._stopping.is_set() or not self._started:
            raise _HttpError(503, "rollout executor is not accepting work")

    def models(self) -> tuple[str, ...]:
        with self._adapters_lock:
            return tuple(sorted(self._adapters))

    def _run_device(self) -> None:
        try:
            assert self._device is not None
            self._device.serve_forever()
        except Exception as error:
            if not self._stopping.is_set():
                self._record_failure(error)
            else:
                self._device_cleanup_error = error

    def _run_batch(self) -> None:
        try:
            self._batch_loop()
        except Exception as error:
            if not self._stopping.is_set():
                self._record_failure(error)

    def _run_http(self) -> None:
        try:
            assert self._http is not None
            self._http.serve_forever()
        except Exception as error:
            if not self._stopping.is_set():
                self._record_failure(error)

    def _record_failure(self, error: Exception) -> None:
        if self._thread_error is None:
            self._thread_error = error
        self._stopping.set()
        with self._condition:
            while self._queue:
                call = self._queue.popleft()
                call.error = error
                call.done.set()
            self._condition.notify_all()
        http = self._http
        http_thread = self._http_thread
        if (
            http is not None
            and http_thread is not None
            and http_thread is not threading.current_thread()
            and http_thread.is_alive()
        ):
            http.shutdown()

    def _allocate_id(self) -> int:
        with self._model_lock:
            list_loras = getattr(self._engine, "list_loras", None)
            used = set(list_loras()) if callable(list_loras) else set()
            with self._adapters_lock:
                value = self._next_adapter_id
                while value in used:
                    value += 1
                self._next_adapter_id = value + 1
                return value

    @staticmethod
    def _default_request(
        name: str,
        adapter_id: int,
        tensors: dict[str, Any],
        config: dict[str, Any],
    ) -> Any:
        try:
            from vllm.lora.request import LoRARequest

            request = LoRARequest(
                name,
                adapter_id,
                lora_tensors=tensors,
                lora_config=config,
            )
        except (ImportError, TypeError) as error:
            raise RuntimeError(
                "Unsloth's tensor-aware vLLM LoRA integration is unavailable"
            ) from error
        if getattr(request, "lora_tensors", None) is None:
            raise RuntimeError("vLLM LoRARequest discarded device tensors")
        return request

    @staticmethod
    def _default_sampling(**values: Any) -> Any:
        from vllm import SamplingParams

        return SamplingParams(**values)

    @staticmethod
    def _default_synchronize() -> None:
        import torch

        torch.cuda.synchronize()

    def _insert(self, name: str, request: Any, source: str) -> None:
        with self._model_lock:
            with self._adapters_lock:
                if name in self._adapters:
                    raise _HttpError(409, f"adapter {name!r} is already loaded")
            added = False
            try:
                if not self._engine.add_lora(request):
                    raise RuntimeError("embedded vLLM rejected the LoRA adapter")
                added = True
                self._synchronize()
                with self._adapters_lock:
                    self._adapters[name] = _AdapterRecord(
                        request=request, source=source
                    )
            except Exception as install_error:
                if added:
                    try:
                        self._engine.remove_lora(request.lora_int_id)
                        self._synchronize()
                    except Exception as rollback_error:
                        with self._adapters_lock:
                            self._adapters[name] = _AdapterRecord(
                                request=request, source=source
                            )
                        raise _InstallRollbackFailure(
                            "embedded vLLM adapter installation failed and could not "
                            f"be rolled back: {install_error}"
                        ) from rollback_error
                raise

    def _load_device(self, name: str, bundle: DeviceAdapterBundle) -> _DeviceOwner:
        if self._stopping.is_set():
            raise RuntimeError("rollout executor is shutting down")
        self._validate_adapter_name(name)
        imported = self._import_adapter(bundle)
        try:
            request = self._request_factory(
                name,
                self._allocate_id(),
                imported.tensors,
                imported.adapter_config,
            )
            self._insert(name, request, "device")
            return _DeviceOwner(imported=imported, request=request)
        except _InstallRollbackFailure as error:
            # The engine may still reference the imported allocation. Return an
            # owner so DeviceAdapterServer retains it and can honor the cleanup
            # unload that smolvm sends after the failed publication boundary.
            owner = _DeviceOwner(imported=imported, request=request)
            self._record_failure(error)
            return owner
        except Exception:
            imported.close()
            raise

    def _remove(self, name: str, source: str) -> None:
        with self._model_lock:
            with self._adapters_lock:
                record = self._adapters.get(name)
            if record is None:
                return
            if record.source != source:
                raise _HttpError(
                    409, f"adapter {name!r} was loaded from {record.source}"
                )
            self._engine.remove_lora(record.request.lora_int_id)
            self._synchronize()
            with self._adapters_lock:
                current = self._adapters.get(name)
                if current is record:
                    del self._adapters[name]

    def _filesystem_models(self) -> tuple[str, ...]:
        with self._adapters_lock:
            return tuple(
                name
                for name, record in self._adapters.items()
                if record.source == "filesystem"
            )

    def _unload_device(self, name: str, _owner: _DeviceOwner) -> None:
        self._remove(name, "device")

    def _load_filesystem(self, body: dict[str, Any]) -> None:
        name = body.get("lora_name")
        path = body.get("lora_path")
        self._validate_adapter_name(name)
        if not isinstance(path, str) or not path:
            raise _HttpError(400, "lora_path must be non-empty")
        loader = getattr(self.model, "load_lora", None)
        if not callable(loader):
            raise _HttpError(501, "embedded Unsloth model cannot load filesystem LoRAs")
        with self._model_lock:
            with self._adapters_lock:
                if name in self._adapters:
                    raise _HttpError(409, f"adapter {name!r} is already loaded")
            request = loader(
                path, load_tensors=False, lora_request_id=self._allocate_id()
            )
            self._insert(name, request, "filesystem")

    def _unload_filesystem(self, body: dict[str, Any]) -> None:
        name = body.get("lora_name")
        self._validate_adapter_name(name)
        self._remove(name, "filesystem")

    @staticmethod
    def _validate_adapter_name(name: Any) -> None:
        if (
            not isinstance(name, str)
            or not name
            or len(name.encode()) > 512
            or "\0" in name
        ):
            raise _HttpError(400, "lora_name must be non-empty and at most 512 bytes")

    def _validate_generate(self, body: dict[str, Any]) -> str:
        model = body.get("model")
        if (
            not isinstance(model, str)
            or not model
            or len(model.encode()) > 512
            or "\0" in model
        ):
            raise _HttpError(400, "model must be non-empty")
        with self._adapters_lock:
            if model not in self._adapters:
                raise _HttpError(404, f"model {model!r} is not loaded")
        prompts = body.get("prompt")
        if not isinstance(prompts, list) or not prompts:
            raise _HttpError(400, "prompt must be a non-empty list")
        if len(prompts) > _MAX_PROMPTS_PER_REQUEST:
            raise _HttpError(400, "request contains too many prompts")
        if len(prompts) > self.max_batch_prompts:
            raise _HttpError(400, "request exceeds the configured batch prompt limit")
        if all(isinstance(value, str) for value in prompts):
            if any(not value for value in prompts):
                raise _HttpError(400, "text prompts must be non-empty")
            if sum(len(value.encode()) for value in prompts) > _MAX_PROMPT_TEXT_BYTES:
                raise _HttpError(400, "prompt text exceeds its size limit")
            prompt_kind = "text"
        elif all(
            isinstance(value, list)
            and value
            and all(
                isinstance(token, int)
                and not isinstance(token, bool)
                and 0 <= token <= 0xFFFFFFFF
                for token in value
            )
            for value in prompts
        ):
            if sum(len(value) for value in prompts) > _MAX_PROMPT_TOKENS:
                raise _HttpError(400, "prompt tokens exceed their size limit")
            prompt_kind = "tokens"
        else:
            raise _HttpError(400, "prompts must be uniformly text or token IDs")
        n = body.get("n", 1)
        max_tokens = body.get("max_tokens")
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 256:
            raise _HttpError(400, "n must be between 1 and 256")
        if (
            not isinstance(max_tokens, int)
            or isinstance(max_tokens, bool)
            or not 1 <= max_tokens <= _MAX_COMPLETION_TOKENS
        ):
            raise _HttpError(400, "max_tokens is invalid")
        if body.get("stream", False) is not False:
            raise _HttpError(400, "streaming completions are not supported")
        self._validate_sampling(body)
        return prompt_kind

    @staticmethod
    def _validate_sampling(body: dict[str, Any]) -> None:
        def number(name: str, default: float) -> float:
            value = body.get(name, default)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise _HttpError(400, f"{name} must be finite")
            return float(value)

        temperature = number("temperature", 1.0)
        top_p = number("top_p", 1.0)
        min_p = number("min_p", 0.0)
        repetition_penalty = number("repetition_penalty", 1.0)
        if temperature < 0:
            raise _HttpError(400, "temperature cannot be negative")
        if not 0 <= top_p <= 1:
            raise _HttpError(400, "top_p must be between 0 and 1")
        if not 0 <= min_p <= 1:
            raise _HttpError(400, "min_p must be between 0 and 1")
        if repetition_penalty <= 0:
            raise _HttpError(400, "repetition_penalty must be positive")
        top_k = body.get("top_k", -1)
        if (
            not isinstance(top_k, int)
            or isinstance(top_k, bool)
            or top_k == 0
            or top_k < -1
        ):
            raise _HttpError(400, "top_k must be -1 or a positive integer")
        for name in ("seed", "logprobs", "prompt_logprobs"):
            value = body.get(name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise _HttpError(400, f"{name} must be a non-negative integer")

    def _generate(self, body: dict[str, Any]) -> dict[str, Any]:
        prompt_kind = self._validate_generate(body)
        call = _PendingCall(body, prompt_kind)
        with self._condition:
            if self._stopping.is_set():
                raise _HttpError(503, "rollout executor is shutting down")
            if len(self._queue) >= self.max_queue_depth:
                raise _HttpError(503, "rollout executor queue is full")
            self._queue.append(call)
            self._condition.notify()
        if not call.done.wait(self.request_timeout):
            with self._condition:
                call.cancelled = True
                try:
                    self._queue.remove(call)
                except ValueError:
                    pass
            raise _HttpError(504, "rollout generation timed out")
        if call.error is not None:
            if isinstance(call.error, _HttpError):
                raise call.error
            raise RuntimeError(str(call.error)) from call.error
        assert call.response is not None
        return call.response

    def _batch_loop(self) -> None:
        while not self._stopping.is_set():
            with self._condition:
                while not self._queue and not self._stopping.is_set():
                    self._condition.wait(0.5)
                if self._stopping.is_set():
                    return
                deadline = time.monotonic() + self.batch_window
                while time.monotonic() < deadline and not self._stopping.is_set():
                    self._condition.wait(max(0.0, deadline - time.monotonic()))
                if self._stopping.is_set():
                    return
                first = next((call for call in self._queue if not call.cancelled), None)
                if first is None:
                    self._queue.clear()
                    continue
                selected: list[_PendingCall] = []
                prompts = 0
                remaining: deque[_PendingCall] = deque()
                while self._queue:
                    call = self._queue.popleft()
                    count = len(call.body["prompt"])
                    if (
                        call.cancelled
                        or call.prompt_kind != first.prompt_kind
                        or len(selected) >= self.max_batch_requests
                        or prompts + count > self.max_batch_prompts
                    ):
                        if not call.cancelled:
                            remaining.append(call)
                        continue
                    selected.append(call)
                    prompts += count
                self._queue.extendleft(reversed(remaining))
                if self._queue:
                    self._condition.notify()
            if selected:
                self._execute_batch(selected)

    def _execute_batch(self, calls: list[_PendingCall]) -> None:
        calls = [call for call in calls if not call.cancelled]
        if not calls:
            return
        prompts: list[Any] = []
        requests: list[Any] = []
        sampling: list[Any] = []
        slices: list[tuple[_PendingCall, int, int]] = []
        try:
            with self._model_lock:
                with self._adapters_lock:
                    records = {
                        call.body["model"]: self._adapters.get(call.body["model"])
                        for call in calls
                    }
                for call in calls:
                    body = call.body
                    record = records[body["model"]]
                    if record is None:
                        raise _HttpError(
                            404, f"model {body['model']!r} is not loaded"
                        )
                    begin = len(prompts)
                    prompts.extend(body["prompt"])
                    requests.extend([record.request] * len(body["prompt"]))
                    seed = body.get("seed")
                    for prompt_index in range(len(body["prompt"])):
                        sampling.append(
                            self._sampling_factory(
                                n=body.get("n", 1),
                                max_tokens=body["max_tokens"],
                                temperature=body.get("temperature", 1.0),
                                top_p=body.get("top_p", 1.0),
                                top_k=body.get("top_k", -1),
                                min_p=body.get("min_p", 0.0),
                                repetition_penalty=body.get(
                                    "repetition_penalty", 1.0
                                ),
                                seed=(
                                    None if seed is None else seed + prompt_index
                                ),
                                logprobs=body.get("logprobs"),
                                prompt_logprobs=body.get("prompt_logprobs"),
                            )
                        )
                    slices.append((call, begin, len(prompts)))
                outputs = self.model.fast_generate(
                    prompts,
                    sampling_params=sampling,
                    lora_request=requests,
                    use_tqdm=False,
                )
                self._synchronize()
            if len(outputs) != len(prompts):
                raise RuntimeError("embedded vLLM returned the wrong number of outputs")
            for call, begin, end in slices:
                call.response = self._completion_response(outputs[begin:end])
        except Exception as error:
            for call in calls:
                call.error = error
        finally:
            for call in calls:
                call.done.set()

    @staticmethod
    def _completion_response(outputs: list[Any]) -> dict[str, Any]:
        choices = []
        completion_tokens = 0
        prompt_tokens = 0
        index = 0
        for output in outputs:
            prompt_ids = [int(token) for token in output.prompt_token_ids]
            prompt_tokens += len(prompt_ids)
            for completion in output.outputs:
                token_ids = [int(token) for token in completion.token_ids]
                completion_tokens += len(token_ids)
                finish_reason = getattr(completion, "finish_reason", None)
                choices.append(
                    {
                        "index": index,
                        "text": str(completion.text),
                        "token_ids": token_ids,
                        "prompt_token_ids": prompt_ids,
                        "logprobs": _json_value(
                            getattr(completion, "logprobs", None)
                        ),
                        "finish_reason": (
                            None if finish_reason is None else str(finish_reason)
                        ),
                        "stop_reason": _json_value(
                            getattr(completion, "stop_reason", None)
                        ),
                    }
                )
                index += 1
        return {
            "id": f"smolvm-{time.time_ns()}",
            "choices": choices,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }


def _json_value(value: Any, depth: int = 0) -> Any:
    """Convert vLLM result objects into strict, bounded JSON-compatible values."""

    if depth > 16:
        raise ValueError("vLLM response nesting exceeds its safety limit")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {
            str(key): _json_value(item, depth + 1) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_json_value(item, depth + 1) for item in value]
    fields = {}
    for name in ("logprob", "rank", "decoded_token"):
        if hasattr(value, name):
            fields[name] = _json_value(getattr(value, name), depth + 1)
    if fields:
        return fields
    item = getattr(value, "item", None)
    if callable(item):
        converted = item()
        if converted is not value:
            return _json_value(converted, depth + 1)
    return str(value)
