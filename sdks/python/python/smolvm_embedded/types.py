"""Typed configuration and result objects for smolvm-embedded."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(slots=True)
class MountSpec:
    source: str
    target: str
    read_only: bool = True


@dataclass(slots=True)
class PortSpec:
    host: int
    guest: int


@dataclass(slots=True)
class ResourceSpec:
    cpus: int | None = None
    memory_mib: int | None = None
    network: bool | None = None
    storage_gib: int | None = None
    overlay_gib: int | None = None


@dataclass(slots=True)
class MachineConfig:
    name: str
    mounts: list[MountSpec] = field(default_factory=list)
    ports: list[PortSpec] = field(default_factory=list)
    resources: ResourceSpec | None = None
    persistent: bool = False


@dataclass(slots=True)
class ExecOptions:
    env: Mapping[str, str] | None = None
    workdir: str | None = None
    timeout: int | None = None


@dataclass(slots=True)
class FileWriteOptions:
    mode: int | None = None


@dataclass(frozen=True, slots=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True, slots=True)
class ImageInfo:
    reference: str
    digest: str
    size: int
    architecture: str
    os: str


@dataclass(frozen=True, slots=True)
class ExecStreamEvent:
    kind: str
    data: str | None = None
    exit_code: int | None = None
    message: str | None = None
