"""Python-visible exception types for smolvm-embedded."""

from ._native import (
    ConflictError,
    HypervisorUnavailableError,
    InvalidStateError,
    NotFoundError,
    SmolvmError,
)

__all__ = [
    "SmolvmError",
    "NotFoundError",
    "InvalidStateError",
    "HypervisorUnavailableError",
    "ConflictError",
]
