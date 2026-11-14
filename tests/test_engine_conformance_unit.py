#!/usr/bin/env python3
"""Offline regression checks for the Docker response-shape validator."""
import socket
import threading
import unittest
from unittest.mock import patch
from test_engine_conformance import Conn, Replay, shape_errors


class ShapeErrorsTest(unittest.TestCase):
    def test_null_cannot_replace_required_object(self):
        self.assertTrue(shape_errors({"Id": "abc"}, None))

    def test_null_cannot_replace_required_nested_value(self):
        self.assertEqual(
            shape_errors({"State": {"Running": True}}, {"State": None}),
            ["$.State: recorded dict, got None"],
        )

    def test_non_null_values_keep_their_type(self):
        for value in ("abc", 1, True, [], {}):
            with self.subTest(value=value):
                self.assertTrue(shape_errors(value, None))

    def test_variable_values_and_unknown_nullable_types_are_allowed(self):
        self.assertEqual(shape_errors({"Id": "abc"}, {"Id": "def"}), [])
        self.assertEqual(shape_errors(None, None), [])
        self.assertEqual(shape_errors(None, {"Id": "def"}), [])


class StreamingTest(unittest.TestCase):
    def test_closing_a_connection_wakes_a_blocked_stream_reader(self):
        client, peer = socket.socketpair()
        conn = Conn.__new__(Conn)
        conn.sock, conn.buf = client, b""
        reader = threading.Thread(target=conn.drain, daemon=True)
        try:
            reader.start()
            conn.close()
            reader.join(timeout=2)
            self.assertFalse(reader.is_alive())
        finally:
            conn.close()
            peer.close()

    def test_a_stream_without_a_response_is_a_failure(self):
        replay = Replay("unused", "/tmp")
        request = {"method": "GET", "path": "/events", "query": "", "status": 200}
        with patch("test_engine_conformance.Conn", side_effect=OSError("refused")):
            replay.stream(0, request)
        self.assertEqual(len(replay.failures), 1)
        self.assertIn("no stream answer", replay.failures[0])


if __name__ == "__main__":
    unittest.main()
