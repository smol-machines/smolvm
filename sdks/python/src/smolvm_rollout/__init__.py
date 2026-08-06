"""Framework-neutral client for smolvm fused rollout executors."""

from .client import RolloutClient, RolloutError, adapter_sha256
from .device_handoff import (
    DeviceAdapterBundle,
    DeviceAdapterServer,
    DeviceTensor,
    publish_device_adapter,
)
from .torch_handoff import TorchDeviceAdapter, import_torch_device_adapter

__all__ = [
    "DeviceAdapterBundle",
    "DeviceAdapterServer",
    "DeviceTensor",
    "RolloutClient",
    "RolloutError",
    "TorchDeviceAdapter",
    "adapter_sha256",
    "publish_device_adapter",
    "import_torch_device_adapter",
]
