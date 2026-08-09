"""Small dependency-free client usable from TRL, Unsloth, or custom RL loops."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Sequence


_FORK_ENV_PATH = Path("/etc/smolvm/fork-env")
_ROLLOUT_URL_ENV = "SMOLVM_ROLLOUT_URL"
_ROLLOUT_TOKEN_ENV = "SMOLVM_ROLLOUT_TOKEN"
_ROLLOUT_EXECUTOR_ENV = "SMOLVM_ROLLOUT_EXECUTOR"
_ROLLOUT_POLICY_ENV = "SMOLVM_ROLLOUT_POLICY"
_ROLLOUT_LEASE_KEYS = (
    _ROLLOUT_URL_ENV,
    _ROLLOUT_TOKEN_ENV,
    _ROLLOUT_EXECUTOR_ENV,
    _ROLLOUT_POLICY_ENV,
)


class RolloutError(RuntimeError):
    """A structured error returned by smolvm's rollout API."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.status = status
        self.code = code
        self.message = message


def _read_fork_env(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise RuntimeError(f"cannot read smolvm fork assignment {path}: {error}") from error

    values: dict[str, str] = {}
    for number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError(f"invalid smolvm fork assignment at {path}:{number}")
        if key in values:
            raise RuntimeError(f"duplicate {key} in smolvm fork assignment {path}")
        values[key] = value
    return values


def _lease_configuration(path: Path) -> tuple[str, str, str, str]:
    values = _read_fork_env(path)
    for key in _ROLLOUT_LEASE_KEYS:
        if key in os.environ:
            values[key] = os.environ[key]
    missing = [key for key in _ROLLOUT_LEASE_KEYS if not values.get(key)]
    if missing:
        raise RuntimeError(
            "smolvm rollout lease configuration is unavailable: missing "
            + ", ".join(missing)
        )

    url = values[_ROLLOUT_URL_ENV].rstrip("/")
    executor = values[_ROLLOUT_EXECUTOR_ENV]
    suffix = f"/rollout-executors/{executor}"
    if not url.endswith(suffix):
        raise RuntimeError(
            f"{_ROLLOUT_URL_ENV} does not match {_ROLLOUT_EXECUTOR_ENV}"
        )
    api_url = url[: -len(suffix)]
    if not api_url.startswith(("http://", "https://")):
        raise RuntimeError(f"{_ROLLOUT_URL_ENV} must be an HTTP URL")
    return (
        api_url,
        executor,
        values[_ROLLOUT_TOKEN_ENV],
        values[_ROLLOUT_POLICY_ENV],
    )


def adapter_sha256(directory: str | os.PathLike[str]) -> str:
    """Return the deterministic directory digest required by policy publication."""

    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("adapter path must be a directory")
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                raise ValueError("adapter directories cannot contain symlinks")
        for name in names:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("adapter directories may contain only regular files")
            files.append(path)
    if not files:
        raise ValueError("adapter directory contains no files")

    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        name = path.relative_to(root).as_posix().encode("utf-8")
        size = path.stat().st_size
        digest.update(struct.pack("<Q", len(name)))
        digest.update(name)
        digest.update(struct.pack("<Q", size))
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


class RolloutClient:
    """Synchronous rollout client designed for framework generation boundaries."""

    def __init__(
        self,
        api_url: str | None = None,
        executor: str | None = None,
        *,
        bearer_token: str | None = None,
        fork_env_path: str | os.PathLike[str] = _FORK_ENV_PATH,
        timeout: float = 300.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        lease_policy = None
        if api_url is None and executor is None:
            api_url, executor, discovered_token, lease_policy = _lease_configuration(
                Path(fork_env_path)
            )
            if bearer_token is not None and bearer_token != discovered_token:
                raise ValueError("bearer_token conflicts with the smolvm lease credential")
            bearer_token = discovered_token
        elif api_url is None or executor is None:
            raise TypeError("api_url and executor must be provided together")
        self.api_url = api_url.rstrip("/")
        self.executor = executor
        self.bearer_token = bearer_token
        self.lease_policy = lease_policy
        self.timeout = timeout
        self.ssl_context = ssl_context

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"content-type": "application/json"}
        if self.bearer_token is not None:
            headers["authorization"] = f"Bearer {self.bearer_token}"
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.ssl_context
            ) as response:
                payload = response.read()
                return None if not payload else json.loads(payload)
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"code": "HTTP_ERROR", "error": raw.decode(errors="replace")}
            raise RolloutError(
                error.code,
                str(payload.get("code", "HTTP_ERROR")),
                str(payload.get("error", error.reason)),
            ) from error
        except urllib.error.URLError as error:
            raise RolloutError(0, "UNAVAILABLE", str(error.reason)) from error

    def ensure_vllm_executor(
        self,
        *,
        endpoint: str,
        adapter_root: str | os.PathLike[str],
        device_adapter_socket: str | os.PathLike[str] | None = None,
        fallback_pool: str | None = None,
        max_concurrent_requests: int = 32,
        max_queue_depth: int = 256,
        request_timeout_secs: int = 300,
    ) -> dict[str, Any]:
        """Declaratively create the executor or verify an identical registration."""

        desired: dict[str, Any] = {
            "name": self.executor,
            "backend": "vllm",
            "endpoint": endpoint,
            "adapterRoot": str(Path(adapter_root).resolve()),
            "maxConcurrentRequests": max_concurrent_requests,
            "maxQueueDepth": max_queue_depth,
            "requestTimeoutSecs": request_timeout_secs,
        }
        if fallback_pool is not None:
            desired["fallbackPool"] = fallback_pool
        if device_adapter_socket is not None:
            desired["deviceAdapterSocket"] = str(Path(device_adapter_socket).resolve())
        try:
            return self._request("POST", "/rollout-executors", desired)
        except RolloutError as error:
            if error.status != 409:
                raise
        current = self.info()
        comparable = {
            "backend": current["backend"],
            "endpoint": current["endpoint"],
            "adapterRoot": current["adapterRoot"],
            "deviceAdapterSocket": current.get("deviceAdapterSocket"),
            "fallbackPool": current.get("fallbackPool"),
            "maxConcurrentRequests": current["maxConcurrentRequests"],
            "maxQueueDepth": current["maxQueueDepth"],
        }
        expected = {
            "backend": "vllm",
            "endpoint": endpoint,
            "adapterRoot": desired["adapterRoot"],
            "deviceAdapterSocket": desired.get("deviceAdapterSocket"),
            "fallbackPool": fallback_pool,
            "maxConcurrentRequests": max_concurrent_requests,
            "maxQueueDepth": max_queue_depth,
        }
        if comparable != expected:
            raise RolloutError(
                409,
                "CONFLICT",
                f"executor {self.executor!r} exists with different configuration",
            )
        return current

    def info(self) -> dict[str, Any]:
        """Return capabilities, queue state, fallback, and published policies."""

        return self._request("GET", f"/rollout-executors/{self.executor}")

    def publish_policy(
        self,
        policy: str,
        version: str,
        adapter_directory: str | os.PathLike[str],
        *,
        retain_previous: bool = False,
    ) -> dict[str, Any]:
        """Content-verify and atomically publish one immutable LoRA version."""

        info = self.info()
        root = Path(info["adapterRoot"]).resolve(strict=True)
        adapter = Path(adapter_directory).resolve(strict=True)
        try:
            relative = adapter.relative_to(root)
        except ValueError as error:
            raise ValueError("adapter must be beneath the executor adapter root") from error
        return self._request(
            "POST",
            f"/rollout-executors/{self.executor}/policies",
            {
                "policy": policy,
                "version": version,
                "adapterPath": relative.as_posix(),
                "adapterSha256": adapter_sha256(adapter),
                "retainPrevious": retain_previous,
            },
        )

    def publish_device_policy(
        self,
        policy: str,
        version: str,
        tensor_bundle_token: bytes | str,
        *,
        retain_previous: bool = False,
    ) -> dict[str, Any]:
        """Atomically publish a one-use device-resident LoRA allocation."""

        token = (
            tensor_bundle_token.hex()
            if isinstance(tensor_bundle_token, bytes)
            else tensor_bundle_token
        )
        if len(token) != 64:
            raise ValueError("tensor bundle token must contain exactly 32 bytes")
        try:
            bytes.fromhex(token)
        except ValueError as error:
            raise ValueError("tensor bundle token must be hexadecimal") from error
        path = f"/rollout-executors/{self.executor}/device-policies"
        body = {
            "policy": policy,
            "version": version,
            "tensorBundleToken": token,
            "retainPrevious": retain_previous,
        }
        try:
            return self._request("POST", path, body)
        except RolloutError as error:
            if error.status != 0:
                raise
            # The token is one-use, but the controller remembers its digest.
            # Reusing the same token is therefore safe when a lost response
            # leaves it ambiguous whether the first request was accepted.
            return self._request("POST", path, body)

    def retire_policy(self, policy: str, version: str) -> None:
        """Stop routing and unload a policy version after its requests drain."""

        self._request(
            "DELETE",
            f"/rollout-executors/{self.executor}/policies/{policy}/{version}",
        )

    @staticmethod
    def _prompts(prompts: Sequence[str] | Sequence[Sequence[int]]) -> list[dict[str, Any]]:
        if not prompts:
            raise ValueError("at least one prompt is required")
        if isinstance(prompts[0], str):
            if not all(isinstance(prompt, str) for prompt in prompts):
                raise ValueError("one request cannot mix text and token prompts")
            return [{"text": prompt} for prompt in prompts]
        if not all(not isinstance(prompt, str) for prompt in prompts):
            raise ValueError("one request cannot mix text and token prompts")
        return [{"tokenIds": list(prompt)} for prompt in prompts]

    def job(
        self,
        *,
        idempotency_key: str,
        policy: str,
        prompts: Sequence[str] | Sequence[Sequence[int]],
        max_tokens: int,
        version: str | None = None,
        n: int = 1,
        deadline_ms: int | None = None,
        **sampling: Any,
    ) -> dict[str, Any]:
        """Build a generation job for `generate` or a cross-policy cohort."""

        parameters = {"n": n, "maxTokens": max_tokens}
        wire_names = {
            "temperature": "temperature",
            "top_p": "topP",
            "top_k": "topK",
            "min_p": "minP",
            "repetition_penalty": "repetitionPenalty",
            "seed": "seed",
            "logprobs": "logprobs",
            "prompt_logprobs": "promptLogprobs",
        }
        unknown = set(sampling) - set(wire_names)
        if unknown:
            raise TypeError(f"unknown sampling parameters: {sorted(unknown)}")
        parameters.update(
            {wire_names[name]: value for name, value in sampling.items() if value is not None}
        )
        job: dict[str, Any] = {
            "idempotencyKey": idempotency_key,
            "policy": policy,
            "prompts": self._prompts(prompts),
            "sampling": parameters,
        }
        if version is not None:
            job["version"] = version
        if deadline_ms is not None:
            job["deadlineMs"] = deadline_ms
        return job

    def generate(self, **job: Any) -> dict[str, Any]:
        """Generate through one policy, returning exact token IDs and logprobs."""

        return self._request(
            "POST",
            f"/rollout-executors/{self.executor}/generate",
            self.job(**job),
        )

    def generate_batch(self, jobs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Submit independent policy jobs together so vLLM can fuse the cohort."""

        response = self._request(
            "POST",
            f"/rollout-executors/{self.executor}/batches",
            {"jobs": list(jobs)},
        )
        return response["jobs"]

    def close(self) -> None:
        """Drain and delete the executor registration."""

        self._request("DELETE", f"/rollout-executors/{self.executor}")
