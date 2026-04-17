"""Embedded Python SDK for smolvm."""

from .errors import (
    ConflictError,
    HypervisorUnavailableError,
    InvalidStateError,
    NotFoundError,
    SmolvmError,
)
from .machine import Machine, quick_exec, quick_run, with_machine
from .types import (
    ExecOptions,
    ExecResult,
    ExecStreamEvent,
    FileWriteOptions,
    ImageInfo,
    MachineConfig,
    MountSpec,
    PortSpec,
    ResourceSpec,
)

__all__ = [
    "Machine",
    "MachineConfig",
    "MountSpec",
    "PortSpec",
    "ResourceSpec",
    "ExecOptions",
    "ExecResult",
    "ExecStreamEvent",
    "FileWriteOptions",
    "ImageInfo",
    "SmolvmError",
    "NotFoundError",
    "InvalidStateError",
    "HypervisorUnavailableError",
    "ConflictError",
    "with_machine",
    "quick_exec",
    "quick_run",
]
