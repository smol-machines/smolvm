# smolvm rollout client

`smolvm-rollout` is the framework-neutral generation boundary for fused policy
rollouts. A trainer publishes each immutable LoRA version and submits text or
token-ID prompts; smolvm verifies and routes the version while one local vLLM
engine continuously batches compatible policies. Unsupported workflows can use
the executor's advertised `fallbackPool` with the ordinary fork-lease API.
Training-framework adapters remain optional layers above this core contract.

The vLLM server must bind to loopback, enable LoRA and runtime adapter updates,
and reserve at least one spare CPU LoRA slot so a new policy version can load
before the previous version retires. smolvm never exposes vLLM's unrestricted
adapter-path endpoint to remote callers.

```python
from smolvm_rollout import RolloutClient

client = RolloutClient("http://127.0.0.1:8080/api/v1", "qwen")
client.ensure_vllm_executor(
    endpoint="http://127.0.0.1:8000",
    adapter_root="/var/lib/smolvm/adapters",
    fallback_pool="isolated-rollouts",
)
client.publish_policy("experiment-a", "step-40", "/var/lib/smolvm/adapters/a-40")
result = client.generate(
    idempotency_key="experiment-a-step-40-batch-7",
    policy="experiment-a",
    prompts=[[1, 2, 3]],
    max_tokens=64,
    temperature=0.9,
    seed=7,
    logprobs=1,
)
```

Inside a worker acquired with `rolloutAccess`, no endpoint or credential wiring
is needed. `RolloutClient()` reads the clone-local assignment installed at
`/etc/smolvm/fork-env` and authenticates every request with its lease scope:

```python
client = RolloutClient()
result = client.generate(
    idempotency_key="experiment-a-step-40-batch-7",
    policy=client.lease_policy,
    prompts=[[1, 2, 3]],
    max_tokens=64,
)
```

When the fork assignment includes a batch ID and size, the client automatically
coordinates matching `generate` calls for up to 250 ms so the rollout engine can
batch policies before admitting stragglers. Use
`RolloutClient(auto_fork_cohort=False)` for intentionally divergent workers, or
set `auto_fork_cohort_max_wait_ms` to tune the bounded wait.

For colocated CUDA trainers, `publish_device_adapter` replaces the checkpoint
write with an immutable device allocation. Framework adapters provide a mapping
of named tensors and a serializable adapter configuration to the core contract:

```python
from smolvm_rollout import publish_device_adapter

token = publish_device_adapter(adapter_tensors, adapter_config)
client.publish_device_policy("experiment-a", "step-41", token)
```

PyTorch synchronization is automatic. Other CUDA frameworks pass their own
stream barrier with `synchronize=` before smolvm packs the immutable allocation.
Publish at an optimizer-step boundary while the framework has stopped mutating
the selected adapter tensors.

The rollout process runs `DeviceAdapterServer` with framework load/unload
callbacks. `import_torch_device_adapter` provides named PyTorch views over the
received CUDA allocation; the server retains them until smolvm drains active
requests and the unload callback succeeds. Filesystem publication remains the
fallback when a framework has no device-adapter callback.
