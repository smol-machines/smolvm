"""PEFT integration for device-resident LoRA publication."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from ..device_handoff import publish_device_adapter


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()


def _adapter_name(model: Any, requested: str | None) -> str:
    name = requested if requested is not None else getattr(model, "active_adapter", None)
    if not isinstance(name, str) or not name:
        raise ValueError("a single active PEFT adapter is required")
    return name


def _configuration(model: Any, adapter_name: str) -> Mapping[str, Any]:
    configurations = getattr(model, "peft_config", None)
    if not isinstance(configurations, Mapping) or adapter_name not in configurations:
        raise ValueError(f"PEFT adapter {adapter_name!r} is not configured")
    configuration = configurations[adapter_name]
    if _enum_value(getattr(configuration, "peft_type", "")) != "LORA":
        raise ValueError("device adapter publication supports LoRA and QLoRA only")
    if str(getattr(configuration, "bias", "none")).lower() != "none":
        raise ValueError("device adapter publication does not support trained biases")
    if bool(getattr(configuration, "use_dora", False)):
        raise ValueError("device adapter publication does not support DoRA")
    if getattr(configuration, "modules_to_save", None):
        raise ValueError("device adapter publication does not support modules_to_save")
    if getattr(configuration, "trainable_token_indices", None):
        raise ValueError("device adapter publication does not support trainable tokens")
    if getattr(model, "_tp_plan", None) is not None:
        modules = getattr(model, "modules", None)
        if not callable(modules):
            raise ValueError("cannot verify whether the PEFT model is sharded")
        if any(
            getattr(getattr(module, "_tp_info", None), "tp_plan", None)
            for module in modules()
        ):
            raise ValueError("device adapter publication requires an unsharded PEFT model")

    if isinstance(configuration, Mapping):
        values = configuration
    else:
        to_dict = getattr(configuration, "to_dict", None)
        if not callable(to_dict):
            raise TypeError("PEFT adapter configuration must expose to_dict()")
        values = to_dict()
    if not isinstance(values, Mapping):
        raise TypeError("PEFT adapter configuration must serialize to a mapping")
    return values


def _remove_adapter_name(name: str, adapter_name: str) -> str | None:
    marker = f".{adapter_name}"
    if name.endswith(marker):
        return name[: -len(marker)]
    prefix, separator, suffix = name.rpartition(".")
    if not separator or not prefix.endswith(marker):
        return None
    return f"{prefix[: -len(marker)]}.{suffix}"


def _lora_tensors(model: Any, adapter_name: str) -> dict[str, Any]:
    named_parameters = getattr(model, "named_parameters", None)
    if not callable(named_parameters):
        raise TypeError("PEFT model must expose named_parameters()")

    tensors = {}
    for parameter_name, parameter in named_parameters():
        if "lora_" not in parameter_name:
            continue
        published_name = _remove_adapter_name(parameter_name, adapter_name)
        if published_name is not None:
            if published_name in tensors:
                raise ValueError(f"duplicate PEFT adapter tensor {published_name!r}")
            tensors[published_name] = parameter.detach()
    if not tensors:
        raise ValueError(f"PEFT adapter {adapter_name!r} has no LoRA tensors")
    return dict(sorted(tensors.items()))


def peft_lora_tensors(model: Any, *, adapter_name: str | None = None) -> dict[str, Any]:
    """Return one unsharded LoRA adapter without traversing base-model state."""
    name = _adapter_name(model, adapter_name)
    _configuration(model, name)
    return _lora_tensors(model, name)


def publish_peft_adapter(
    model: Any,
    *,
    adapter_name: str | None = None,
    shim_path: str | os.PathLike[str] | None = None,
    synchronize: Callable[[], None] | None = None,
) -> bytes:
    """Publish a compatible PEFT LoRA directly from its trainable parameters."""
    name = _adapter_name(model, adapter_name)
    configuration = _configuration(model, name)
    return publish_device_adapter(
        _lora_tensors(model, name),
        configuration,
        shim_path=shim_path,
        synchronize=synchronize,
    )
