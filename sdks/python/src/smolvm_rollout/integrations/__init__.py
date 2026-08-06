"""Optional training-framework adapters for the smolvm rollout contract."""

from .peft import peft_lora_tensors, publish_peft_adapter
from .transformers import add_transformers_forkpoint, transformers_forkpoint_callback
from .unsloth_vllm import UnslothVllmExecutor

__all__ = [
    "UnslothVllmExecutor",
    "add_transformers_forkpoint",
    "peft_lora_tensors",
    "publish_peft_adapter",
    "transformers_forkpoint_callback",
]
