import array
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

from smolvm_rollout import DeviceAdapterServer, publish_device_adapter
from smolvm_rollout import device_handoff


REQUEST = struct.Struct("<8sB3xIIQ4x")
RESPONSE = struct.Struct("<8siI")


def request(path, operation, model="", metadata=b"", descriptor=None, size=0):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(path))
    header = REQUEST.pack(
        b"SMVDLH01", operation, len(model.encode()), len(metadata), size
    )
    if descriptor is None:
        connection.sendall(header)
    else:
        connection.sendmsg(
            [header],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
        )
    connection.sendall(model.encode() + metadata)
    response = connection.recv(RESPONSE.size)
    magic, status, message_len = RESPONSE.unpack(response)
    message = b""
    while len(message) < message_len:
        message += connection.recv(message_len - len(message))
    connection.close()
    return magic, status, message


class Owner:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False

    def close(self):
        os.fstat(self.descriptor)
        self.closed = True


def start_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.wait_until_ready(2)
    return thread


class DeviceHandoffTests(unittest.TestCase):
    def test_active_socket_is_never_unlinked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(1)
            try:
                with self.assertRaisesRegex(RuntimeError, "already active"):
                    device_handoff._remove_stale_socket(path)
                self.assertTrue(path.exists())
            finally:
                listener.close()

    def test_failed_server_start_does_not_unlink_an_active_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(4)
            errors = []
            server = DeviceAdapterServer(
                path,
                load_adapter=lambda _model, _bundle: None,
                unload_adapter=lambda _model, _owner: None,
            )

            def run_server():
                try:
                    server.serve_forever()
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            with self.assertRaisesRegex(RuntimeError, "failed to start"):
                server.wait_until_ready(2)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertTrue(errors)
            self.assertTrue(path.exists())

            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(str(path))
            finally:
                probe.close()
                listener.close()

    def test_manifest_range_must_match_shape_and_dtype(self):
        manifest = json.dumps(
            {
                "schema": "smolvm.device-lora.v1",
                "adapterConfig": {},
                "tensors": [
                    {
                        "name": "q_proj.lora_A.weight",
                        "shape": [2, 4],
                        "dtype": "float16",
                    }
                ],
            },
            separators=(",", ":"),
        ).encode()
        metadata = (
            struct.pack("<II", len(manifest), 1)
            + manifest
            + struct.pack("<QQ", 0, 8)
        )
        with tempfile.TemporaryFile() as allocation:
            with self.assertRaisesRegex(ValueError, "range is invalid"):
                device_handoff._decode_bundle(allocation.fileno(), 64, metadata)

    def test_partial_client_is_timed_out_without_blocking_health(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            server = DeviceAdapterServer(
                path,
                load_adapter=lambda _model, _bundle: None,
                unload_adapter=lambda _model, _owner: None,
                io_timeout_secs=0.05,
            )
            thread = start_server(server)
            stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stalled.connect(str(path))
            stalled.sendall(b"S")
            time.sleep(0.1)
            stalled.close()
            self.assertEqual(request(path, 0), (b"SMVDHR01", 0, b""))
            server.shutdown()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_framework_tensors_form_a_versioned_publication_manifest(self):
        class Device:
            index = 0

        class Tensor:
            is_cuda = True
            is_contiguous_value = True
            device = Device()
            dtype = "torch.bfloat16"
            shape = (2, 4)

            def detach(self):
                return self

            def is_contiguous(self):
                return self.is_contiguous_value

            def data_ptr(self):
                return 0x12340000

            def numel(self):
                return 8

            def element_size(self):
                return 2

        captured = {}
        events = []

        def publish(manifest, manifest_len, pointers, sizes, count, token, capacity, token_len):
            events.append("publish")
            captured["manifest"] = json.loads(manifest[:manifest_len])
            captured["pointers"] = [pointers[index] for index in range(count)]
            captured["sizes"] = [sizes[index] for index in range(count)]
            value = bytes(range(32))
            import ctypes

            ctypes.memmove(token, value, len(value))
            ctypes.cast(token_len, ctypes.POINTER(ctypes.c_size_t))[0] = len(value)
            return 0

        with mock.patch.object(device_handoff, "_publisher", return_value=publish):
            token = publish_device_adapter(
                {"q_proj.lora_A.weight": Tensor()},
                {"r": 16, "lora_alpha": 16},
                synchronize=lambda: events.append("synchronize"),
            )
        self.assertEqual(token, bytes(range(32)))
        self.assertEqual(captured["manifest"]["schema"], "smolvm.device-lora.v1")
        self.assertEqual(captured["manifest"]["tensors"][0]["dtype"], "bfloat16")
        self.assertEqual(captured["pointers"], [0x12340000])
        self.assertEqual(captured["sizes"], [16])
        self.assertEqual(events, ["synchronize", "publish"])

    def test_descriptor_is_retained_until_successful_unload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            loaded = {}

            def load(model, bundle):
                os.fstat(bundle.descriptor)
                owner = Owner(bundle.descriptor)
                loaded[model] = owner
                return owner

            def unload(model, owner):
                self.assertIs(loaded[model], owner)
                os.fstat(owner.descriptor)

            server = DeviceAdapterServer(path, load_adapter=load, unload_adapter=unload)
            thread = start_server(server)

            self.assertEqual(request(path, 0), (b"SMVDHR01", 0, b""))
            manifest = json.dumps(
                {
                    "schema": "smolvm.device-lora.v1",
                    "adapterConfig": {},
                    "tensors": [
                        {"name": "q_proj.lora_A.weight", "shape": [2, 4], "dtype": "float16"}
                    ],
                },
                separators=(",", ":"),
            ).encode()
            metadata = (
                struct.pack("<II", len(manifest), 1)
                + manifest
                + struct.pack("<QQ", 0, 16)
            )
            with tempfile.TemporaryFile() as allocation:
                self.assertEqual(
                    request(
                        path,
                        1,
                        "fused-policy-step",
                        metadata,
                        allocation.fileno(),
                        64,
                    ),
                    (b"SMVDHR01", 0, b""),
                )
            owner = loaded["fused-policy-step"]
            os.fstat(owner.descriptor)
            self.assertFalse(owner.closed)
            self.assertEqual(
                request(path, 2, "fused-policy-step"),
                (b"SMVDHR01", 0, b""),
            )
            self.assertTrue(owner.closed)
            with self.assertRaises(OSError):
                os.fstat(owner.descriptor)

            server.shutdown()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_failed_unload_keeps_the_mapping_for_a_safe_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            attempts = 0

            def load(_model, bundle):
                return Owner(bundle.descriptor)

            def unload(_model, owner):
                nonlocal attempts
                attempts += 1
                os.fstat(owner.descriptor)
                if attempts == 1:
                    raise RuntimeError("injected unload failure")

            server = DeviceAdapterServer(path, load_adapter=load, unload_adapter=unload)
            thread = start_server(server)
            manifest = json.dumps(
                {
                    "schema": "smolvm.device-lora.v1",
                    "adapterConfig": {},
                    "tensors": [
                        {"name": "q_proj.lora_A.weight", "shape": [2, 4], "dtype": "float16"}
                    ],
                },
                separators=(",", ":"),
            ).encode()
            metadata = struct.pack("<II", len(manifest), 1) + manifest + struct.pack(
                "<QQ", 0, 16
            )
            with tempfile.TemporaryFile() as allocation:
                self.assertEqual(
                    request(path, 1, "retry", metadata, allocation.fileno(), 64)[1],
                    0,
                )
            owner = server._loaded["retry"].owner
            self.assertNotEqual(request(path, 2, "retry")[1], 0)
            os.fstat(owner.descriptor)
            self.assertFalse(owner.closed)
            self.assertEqual(request(path, 2, "retry")[1], 0)
            self.assertTrue(owner.closed)
            self.assertNotIn("retry", server._loaded)
            server.shutdown()
            thread.join(timeout=2)

    def test_owner_close_retry_does_not_unload_framework_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.sock"
            unloads = 0

            class FlakyOwner(Owner):
                def __init__(self, descriptor):
                    super().__init__(descriptor)
                    self.close_attempts = 0

                def close(self):
                    self.close_attempts += 1
                    if self.close_attempts == 1:
                        raise RuntimeError("injected mapping release failure")
                    super().close()

            def load(_model, bundle):
                return FlakyOwner(bundle.descriptor)

            def unload(_model, _owner):
                nonlocal unloads
                unloads += 1

            server = DeviceAdapterServer(path, load_adapter=load, unload_adapter=unload)
            thread = start_server(server)
            manifest = json.dumps(
                {
                    "schema": "smolvm.device-lora.v1",
                    "adapterConfig": {},
                    "tensors": [
                        {
                            "name": "q_proj.lora_A.weight",
                            "shape": [2, 4],
                            "dtype": "float16",
                        }
                    ],
                },
                separators=(",", ":"),
            ).encode()
            metadata = (
                struct.pack("<II", len(manifest), 1)
                + manifest
                + struct.pack("<QQ", 0, 16)
            )
            with tempfile.TemporaryFile() as allocation:
                self.assertEqual(
                    request(path, 1, "close-retry", metadata, allocation.fileno(), 64)[1],
                    0,
                )
            self.assertNotEqual(request(path, 2, "close-retry")[1], 0)
            self.assertEqual(request(path, 2, "close-retry")[1], 0)
            self.assertEqual(unloads, 1)
            server.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
