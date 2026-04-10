"""High-level Python wrapper for the smolvm embedded runtime."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from time import time_ns
from typing import Iterator

_PACKAGE_DIR = Path(__file__).resolve().parent
_BUNDLED_LIB_DIR = _PACKAGE_DIR / "lib"
_BUNDLED_BOOT_BIN = _PACKAGE_DIR / "smolvm"

from ._native import Machine as _NativeMachine, configure_embedded_paths
from .types import (
    ExecOptions,
    ExecResult,
    ExecStreamEvent,
    FileWriteOptions,
    ImageInfo,
    MachineConfig,
)

configure_embedded_paths(
    lib_dir=str(_BUNDLED_LIB_DIR) if _BUNDLED_LIB_DIR.is_dir() else None,
    boot_bin=str(_BUNDLED_BOOT_BIN) if _BUNDLED_BOOT_BIN.is_file() else None,
)


def _mounts_arg(config: MachineConfig) -> list[tuple[str, str, bool]] | None:
    if not config.mounts:
        return None
    return [(mount.source, mount.target, mount.read_only) for mount in config.mounts]


def _ports_arg(config: MachineConfig) -> list[tuple[int, int]] | None:
    if not config.ports:
        return None
    return [(port.host, port.guest) for port in config.ports]


def _resource_kwargs(config: MachineConfig) -> dict[str, object]:
    if config.resources is None:
        return {}
    return {
        "cpus": config.resources.cpus,
        "memory_mib": config.resources.memory_mib,
        "network": config.resources.network,
        "storage_gib": config.resources.storage_gib,
        "overlay_gib": config.resources.overlay_gib,
    }


def _exec_kwargs(options: ExecOptions | None) -> dict[str, object]:
    if options is None:
        return {}
    return {
        "env": list(options.env.items()) if options.env is not None else None,
        "workdir": options.workdir,
        "timeout_secs": options.timeout,
    }


def _image_info(value: dict[str, object]) -> ImageInfo:
    return ImageInfo(
        reference=str(value["reference"]),
        digest=str(value["digest"]),
        size=int(value["size"]),
        architecture=str(value["architecture"]),
        os=str(value["os"]),
    )


def _exec_stream_event(value: dict[str, object]) -> ExecStreamEvent:
    return ExecStreamEvent(
        kind=str(value["kind"]),
        data=value.get("data"),
        exit_code=value.get("exit_code"),
        message=value.get("message"),
    )


class Machine:
    """A Python wrapper around the native embedded machine binding."""

    def __init__(self, config: MachineConfig):
        self.name = config.name
        self._native = _NativeMachine(
            config.name,
            mounts=_mounts_arg(config),
            ports=_ports_arg(config),
            persistent=config.persistent,
            **_resource_kwargs(config),
        )
        self._started = False

    @classmethod
    def _from_native(cls, name: str, native: _NativeMachine) -> "Machine":
        machine = cls.__new__(cls)
        machine.name = name
        machine._native = native
        machine._started = True
        return machine

    @classmethod
    def create(cls, config: MachineConfig) -> "Machine":
        machine = cls(config)
        if not config.persistent:
            machine.start()
        return machine

    @classmethod
    def connect(cls, name: str) -> "Machine":
        return cls._from_native(name, _NativeMachine.connect(name))

    @property
    def state(self) -> str:
        return self._native.state

    @property
    def is_running(self) -> bool:
        return self._native.is_running

    @property
    def pid(self) -> int | None:
        return self._native.pid

    @property
    def is_started(self) -> bool:
        return self._started

    def start(self) -> None:
        self._native.start()
        self._started = True

    def exec(self, command: list[str], options: ExecOptions | None = None) -> ExecResult:
        exit_code, stdout, stderr = self._native.exec(command, **_exec_kwargs(options))
        return ExecResult(exit_code=exit_code, stdout=stdout, stderr=stderr)

    def run(
        self,
        image: str,
        command: list[str],
        options: ExecOptions | None = None,
    ) -> ExecResult:
        exit_code, stdout, stderr = self._native.run(image, command, **_exec_kwargs(options))
        return ExecResult(exit_code=exit_code, stdout=stdout, stderr=stderr)

    def pull_image(self, image: str) -> ImageInfo:
        return _image_info(self._native.pull_image(image))

    def list_images(self) -> list[ImageInfo]:
        return [_image_info(value) for value in self._native.list_images()]

    def write_file(
        self,
        path: str,
        data: str | bytes | bytearray,
        options: FileWriteOptions | None = None,
    ) -> None:
        payload = data.encode() if isinstance(data, str) else bytes(data)
        mode = options.mode if options is not None else None
        self._native.write_file(path, payload, mode)

    def read_file(self, path: str) -> bytes:
        return bytes(self._native.read_file(path))

    def exec_streaming(
        self,
        command: list[str],
        options: ExecOptions | None = None,
    ) -> list[ExecStreamEvent]:
        return [_exec_stream_event(value) for value in self._native.exec_streaming(command, **_exec_kwargs(options))]

    def stop(self) -> None:
        self._native.stop()
        self._started = False

    def delete(self) -> None:
        self._native.delete()
        self._started = False


@contextmanager
def with_machine(config: MachineConfig) -> Iterator[Machine]:
    machine = Machine.create(config)
    try:
        yield machine
    finally:
        try:
            machine.delete()
        except Exception:
            pass


def quick_exec(
    command: list[str],
    *,
    config: MachineConfig | None = None,
    options: ExecOptions | None = None,
) -> ExecResult:
    machine_config = config or MachineConfig(name=f"quick-{time_ns():x}")
    with with_machine(machine_config) as machine:
        return machine.exec(command, options)


def quick_run(
    image: str,
    command: list[str],
    *,
    config: MachineConfig | None = None,
    options: ExecOptions | None = None,
) -> ExecResult:
    machine_config = config or MachineConfig(name=f"quick-{time_ns():x}")
    with with_machine(machine_config) as machine:
        return machine.run(image, command, options)
