"""Framework-neutral receiver for smolvm device-resident policy adapters."""

from __future__ import annotations

import array
import ctypes
import functools
import json
import os
import socket
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterable, Mapping
from typing import Any, Callable


_REQUEST_MAGIC = b"SMVDLH01"
_RESPONSE_MAGIC = b"SMVDHR01"
_HEADER = struct.Struct("<8sB3xIIQ4x")
_RESPONSE = struct.Struct("<8siI")
_OP_HEALTH = 0
_OP_LOAD = 1
_OP_UNLOAD = 2
_MAX_MODEL_BYTES = 512
_MAX_METADATA_BYTES = (2 << 20) + 64
_MAX_RESPONSE_BYTES = 1 << 20
_DEFAULT_IO_TIMEOUT_SECS = 30.0
_DEFAULT_SHIM = "/opt/smolvm-cuda/libcudart-shim.so"
_DTYPES = {
    "bool",
    "int8",
    "uint8",
    "int16",
    "int32",
    "int64",
    "float8_e4m3fn",
    "float8_e5m2",
    "float16",
    "bfloat16",
    "float32",
    "float64",
}
_DTYPE_SIZES = {
    "bool": 1,
    "int8": 1,
    "uint8": 1,
    "float8_e4m3fn": 1,
    "float8_e5m2": 1,
    "int16": 2,
    "float16": 2,
    "bfloat16": 2,
    "int32": 4,
    "float32": 4,
    "int64": 8,
    "float64": 8,
}


@dataclass(frozen=True)
class DeviceTensor:
    """One named contiguous tensor range inside an imported allocation."""

    name: str
    shape: tuple[int, ...]
    dtype: str
    offset: int
    size: int


class DeviceAdapterBundle:
    """Descriptor and validated manifest delivered to a framework loader."""

    def __init__(
        self,
        descriptor: int,
        allocation_size: int,
        manifest: dict[str, Any],
        tensors: tuple[DeviceTensor, ...],
    ) -> None:
        self.descriptor = descriptor
        self.allocation_size = allocation_size
        self.manifest = manifest
        self.tensors = tensors

    def _close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _LoadedAdapter:
    bundle: DeviceAdapterBundle
    owner: Any
    framework_unloaded: bool = False


LoadAdapter = Callable[[str, DeviceAdapterBundle], Any]
UnloadAdapter = Callable[[str, Any], None]


@functools.lru_cache(maxsize=4)
def _publisher(path: str):
    # Keep the GIL while the host copies the selected ranges so another Python
    # training thread cannot enqueue an optimizer update halfway through the
    # snapshot boundary.
    library = ctypes.PyDLL(path)
    publish = library.smolvm_cuda_publish_tensor_bundle
    publish.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    publish.restype = ctypes.c_int
    return publish


def publish_device_adapter(
    tensors: Mapping[str, Any] | Iterable[tuple[str, Any]],
    adapter_config: Mapping[str, Any],
    *,
    shim_path: str | os.PathLike[str] | None = None,
    synchronize: Callable[[], None] | None = None,
) -> bytes:
    """Stage named CUDA tensors and return a one-use 256-bit publication token.

    Tensor objects use the small PyTorch-compatible surface ``detach()``,
    ``is_cuda``, ``is_contiguous()``, ``data_ptr()``, ``shape``, ``dtype``,
    ``numel()``, and ``element_size()``. PyTorch tensors synchronize through
    PyTorch's existing CUDA connection. Other frameworks must provide a
    ``synchronize`` callback so their queued work cannot be overtaken by the
    publication connection.
    """

    entries = list(tensors.items() if isinstance(tensors, Mapping) else tensors)
    if not entries:
        raise ValueError("at least one device adapter tensor is required")
    if len(entries) > 65_536:
        raise ValueError("device adapter contains too many tensors")
    if not isinstance(adapter_config, Mapping):
        raise TypeError("adapter_config must be a mapping")
    configuration = json.loads(
        json.dumps(
            dict(adapter_config),
            default=lambda value: (
                sorted(value)
                if isinstance(value, (set, frozenset))
                else getattr(value, "value", str(value))
            ),
        )
    )
    names: set[str] = set()
    retained = []
    manifest_tensors = []
    pointers = []
    sizes = []
    device = None
    for name, tensor in entries:
        if not isinstance(name, str) or not name or len(name.encode()) > 1024 or "\0" in name:
            raise ValueError("device adapter tensor names must be unique, non-empty, and bounded")
        if name in names:
            raise ValueError(f"duplicate device adapter tensor name {name!r}")
        names.add(name)
        value = tensor.detach()
        if not bool(value.is_cuda):
            raise ValueError(f"device adapter tensor {name!r} is not on CUDA")
        if not value.is_contiguous():
            value = value.contiguous()
        tensor_device = getattr(value.device, "index", None)
        if not isinstance(tensor_device, int) or tensor_device < 0:
            raise ValueError(f"device adapter tensor {name!r} has no CUDA device index")
        if device is None:
            device = tensor_device
        elif tensor_device != device:
            raise ValueError("one device adapter publication cannot span CUDA devices")
        pointer = int(value.data_ptr())
        size = int(value.numel()) * int(value.element_size())
        if pointer <= 0 or size <= 0:
            raise ValueError(f"device adapter tensor {name!r} is empty")
        dtype = str(value.dtype).removeprefix("torch.")
        if dtype not in _DTYPES:
            raise ValueError(f"device adapter tensor {name!r} has unsupported dtype {dtype!r}")
        shape = [int(dimension) for dimension in value.shape]
        if len(shape) > 16 or any(dimension <= 0 for dimension in shape):
            raise ValueError(f"device adapter tensor {name!r} has an invalid shape")
        retained.append(value)
        pointers.append(pointer)
        sizes.append(size)
        manifest_tensors.append({"name": name, "shape": shape, "dtype": dtype})
    manifest = json.dumps(
        {
            "schema": "smolvm.device-lora.v1",
            "adapterConfig": configuration,
            "tensors": manifest_tensors,
        },
        separators=(",", ":"),
    ).encode()
    if len(manifest) > 1 << 20:
        raise ValueError("device adapter manifest exceeds 1 MiB")
    if synchronize is not None:
        synchronize()
    else:
        try:
            import torch
        except ImportError as error:
            raise ValueError(
                "non-PyTorch device publication requires a synchronize callback"
            ) from error
        if not all(isinstance(value, torch.Tensor) for value in retained):
            raise ValueError(
                "non-PyTorch device publication requires a synchronize callback"
            )
        torch.cuda.synchronize(device)
    path = str(shim_path or os.environ.get("SMOLVM_CUDART_SHIM", _DEFAULT_SHIM))
    publish = _publisher(path)
    pointer_array = (ctypes.c_uint64 * len(pointers))(*pointers)
    size_array = (ctypes.c_uint64 * len(sizes))(*sizes)
    token = ctypes.create_string_buffer(64)
    token_len = ctypes.c_size_t()
    status = publish(
        manifest,
        len(manifest),
        pointer_array,
        size_array,
        len(pointers),
        token,
        len(token),
        ctypes.byref(token_len),
    )
    if status:
        raise RuntimeError(f"device adapter publication failed with CUDA status {status}")
    if token_len.value != 32:
        raise RuntimeError("smolvm returned an invalid device adapter token")
    return token.raw[: token_len.value]


class DeviceAdapterServer:
    """Own device mappings from load acknowledgement through unload acknowledgement.

    ``load_adapter`` imports the descriptor, installs the policy in its framework,
    and returns an owner object that keeps the mapping alive. ``unload_adapter``
    removes the policy. If the owner exposes ``close()``, it is called only after
    framework unload succeeds.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        load_adapter: LoadAdapter,
        unload_adapter: UnloadAdapter,
        io_timeout_secs: float = _DEFAULT_IO_TIMEOUT_SECS,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("device adapter socket path must be absolute")
        if io_timeout_secs <= 0:
            raise ValueError("io_timeout_secs must be positive")
        self._io_timeout_secs = io_timeout_secs
        self._load_adapter = load_adapter
        self._unload_adapter = unload_adapter
        self._loaded: dict[str, _LoadedAdapter] = {}
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._stopping = threading.Event()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None

    @property
    def ready(self) -> bool:
        """Return whether the private socket has completed bind and listen."""

        return self._listener is not None

    def serve_forever(self) -> None:
        """Bind the private socket and process requests until ``shutdown``."""

        listener: socket.socket | None = None
        cleanup_error: Exception | None = None
        socket_identity: tuple[int, int] | None = None
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _remove_stale_socket(self.path)
            listener.bind(str(self.path))
            metadata = self.path.lstat()
            socket_identity = (metadata.st_dev, metadata.st_ino)
            os.chmod(self.path, 0o600)
            listener.listen(16)
            listener.settimeout(0.5)
            self._listener = listener
            self._ready.set()
            while not self._stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                with connection:
                    connection.settimeout(self._io_timeout_secs)
                    self._serve_one(connection)
        except BaseException as error:
            if not self._ready.is_set():
                self._startup_error = error
                self._ready.set()
            raise
        finally:
            self._listener = None
            if listener is not None:
                listener.close()
            _remove_owned_socket(self.path, socket_identity)
            try:
                self.drain()
            except Exception as error:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error

    def wait_until_ready(self, timeout: float | None = None) -> None:
        """Wait until the socket accepts connections or startup fails."""

        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        if not self._ready.wait(timeout):
            raise TimeoutError(f"device adapter server did not become ready at {self.path}")
        if self._startup_error is not None:
            raise RuntimeError(
                f"device adapter server failed to start at {self.path}"
            ) from self._startup_error

    def shutdown(self) -> None:
        """Stop accepting requests and unload every retained adapter mapping."""

        self._stopping.set()
        listener = self._listener
        if listener is not None:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.settimeout(0.1)
            try:
                wake.connect(str(self.path))
            except OSError:
                pass
            finally:
                wake.close()
            try:
                listener.close()
            except OSError:
                pass

    def drain(self) -> None:
        """Unload every retained mapping, preserving failures for a safe retry."""

        first_error: Exception | None = None
        for model in tuple(self._loaded):
            try:
                self._unload(model)
            except Exception as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def _serve_one(self, connection: socket.socket) -> None:
        descriptor = -1
        try:
            _validate_peer(connection)
            receive_flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
            header, ancillary, flags, _ = connection.recvmsg(
                _HEADER.size,
                socket.CMSG_SPACE(array.array("i").itemsize),
                receive_flags,
            )
            if not header:
                return
            if len(header) < _HEADER.size:
                header += _receive_exact(connection, _HEADER.size - len(header))
            magic, operation, model_len, metadata_len, allocation_size = _HEADER.unpack(
                header
            )
            if magic != _REQUEST_MAGIC:
                raise ValueError("invalid device handoff request")
            if model_len > _MAX_MODEL_BYTES or metadata_len > _MAX_METADATA_BYTES:
                raise ValueError("device handoff request exceeds its size limit")
            descriptors = array.array("i")
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    usable = len(data) - len(data) % descriptors.itemsize
                    descriptors.frombytes(data[:usable])
            if flags & socket.MSG_CTRUNC or len(descriptors) > 1:
                for received in descriptors:
                    os.close(received)
                raise ValueError("device handoff supplied multiple descriptors")
            if descriptors:
                descriptor = descriptors[0]
                os.set_inheritable(descriptor, False)
            model = _receive_exact(connection, model_len).decode("utf-8")
            metadata = _receive_exact(connection, metadata_len)
            if operation == _OP_HEALTH:
                if model or metadata or descriptor >= 0 or allocation_size:
                    raise ValueError("invalid device handoff health request")
            elif operation == _OP_LOAD:
                if not model or descriptor < 0 or not metadata or allocation_size <= 0:
                    raise ValueError("incomplete device adapter load request")
                bundle = _decode_bundle(descriptor, allocation_size, metadata)
                descriptor = -1
                self._load(model, bundle)
            elif operation == _OP_UNLOAD:
                if not model or metadata or descriptor >= 0 or allocation_size:
                    raise ValueError("invalid device adapter unload request")
                self._unload(model)
            else:
                raise ValueError("unsupported device handoff operation")
            _send_response(connection, 0, b"")
        except Exception as error:  # The error is returned to the local controller.
            if descriptor >= 0:
                os.close(descriptor)
            message = str(error).encode("utf-8", errors="replace")[:_MAX_RESPONSE_BYTES]
            _send_response(connection, 1, message)

    def _load(self, model: str, bundle: DeviceAdapterBundle) -> None:
        with self._lock:
            if model in self._loaded:
                bundle._close()
                raise ValueError(f"device adapter {model!r} is already loaded")
            try:
                owner = self._load_adapter(model, bundle)
            except Exception:
                bundle._close()
                raise
            self._loaded[model] = _LoadedAdapter(bundle=bundle, owner=owner)

    def _unload(self, model: str) -> None:
        with self._lock:
            loaded = self._loaded.get(model)
            if loaded is None:
                return
            if not loaded.framework_unloaded:
                self._unload_adapter(model, loaded.owner)
                loaded.framework_unloaded = True
            close = getattr(loaded.owner, "close", None)
            if callable(close):
                close()
            loaded.bundle._close()
            del self._loaded[model]


def _remove_stale_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(metadata.st_mode):
        raise RuntimeError(f"refusing to replace non-socket path {path}")
    if metadata.st_uid != os.geteuid():
        raise RuntimeError(f"refusing to replace socket {path} owned by another user")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    except OSError as error:
        raise RuntimeError(f"cannot verify existing device adapter socket {path}: {error}") from error
    else:
        raise RuntimeError(f"device adapter socket {path} is already active")
    finally:
        probe.close()


def _remove_owned_socket(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) == identity and stat.S_ISSOCK(metadata.st_mode):
        path.unlink()


def _validate_peer(connection: socket.socket) -> None:
    peer_option = getattr(socket, "SO_PEERCRED", None)
    if peer_option is None:
        return
    credentials = connection.getsockopt(socket.SOL_SOCKET, peer_option, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    if uid != os.geteuid():
        raise PermissionError("device handoff peer has a different user identity")


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError("device handoff request ended early")
        chunks.extend(chunk)
    return bytes(chunks)


def _send_response(connection: socket.socket, status: int, message: bytes) -> None:
    try:
        connection.sendall(_RESPONSE.pack(_RESPONSE_MAGIC, status, len(message)) + message)
    except OSError:
        pass


def _decode_bundle(
    descriptor: int, allocation_size: int, metadata: bytes
) -> DeviceAdapterBundle:
    if len(metadata) < 8:
        raise ValueError("device adapter metadata is truncated")
    manifest_len, count = struct.unpack_from("<II", metadata)
    expected = 8 + manifest_len + count * 16
    if count == 0 or expected != len(metadata):
        raise ValueError("device adapter metadata is inconsistent")
    manifest = json.loads(metadata[8 : 8 + manifest_len])
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "adapterConfig",
        "tensors",
    }:
        raise ValueError("invalid device adapter manifest")
    if manifest["schema"] != "smolvm.device-lora.v1":
        raise ValueError("unsupported device adapter manifest schema")
    if not isinstance(manifest["adapterConfig"], dict):
        raise ValueError("device adapter config must be an object")
    manifest_tensors = manifest["tensors"]
    if not isinstance(manifest_tensors, list) or len(manifest_tensors) != count:
        raise ValueError("device adapter manifest tensor count mismatch")
    tensors = []
    names = set()
    prior_end = 0
    ranges = memoryview(metadata)[8 + manifest_len :]
    for index, tensor in enumerate(manifest_tensors):
        if not isinstance(tensor, dict) or set(tensor) != {"name", "shape", "dtype"}:
            raise ValueError("invalid device adapter tensor manifest")
        name = tensor["name"]
        shape = tensor["shape"]
        dtype = tensor["dtype"]
        if (
            not isinstance(name, str)
            or not name
            or len(name.encode()) > 1024
            or "\0" in name
            or name in names
        ):
            raise ValueError("device adapter tensor names must be unique and bounded")
        if (
            not isinstance(shape, list)
            or len(shape) > 16
            or any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in shape)
        ):
            raise ValueError("invalid device adapter tensor shape")
        if dtype not in _DTYPE_SIZES:
            raise ValueError("unsupported device adapter tensor dtype")
        expected_size = _DTYPE_SIZES[dtype]
        for dimension in shape:
            expected_size *= dimension
            if expected_size > allocation_size:
                raise ValueError("device adapter tensor size exceeds its allocation")
        offset, size = struct.unpack_from("<QQ", ranges, index * 16)
        if (
            offset != prior_end
            or size != expected_size
            or offset + size > allocation_size
        ):
            raise ValueError("device adapter tensor range is invalid")
        names.add(name)
        tensors.append(
            DeviceTensor(
                name=name,
                shape=tuple(shape),
                dtype=dtype,
                offset=offset,
                size=size,
            )
        )
        prior_end = offset + size
    return DeviceAdapterBundle(descriptor, allocation_size, manifest, tuple(tensors))
