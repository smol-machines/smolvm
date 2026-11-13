#!/usr/bin/env python3
"""Offline regression checks for the Docker response-shape validator."""
import unittest
from test_engine_conformance import shape_errors


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


if __name__ == "__main__":
    unittest.main()
