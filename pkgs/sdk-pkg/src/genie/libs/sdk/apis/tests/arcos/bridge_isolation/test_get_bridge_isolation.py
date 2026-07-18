#!/usr/bin/env python3
"""Unit tests for arcOS Bridge Isolation get APIs (full coverage).

get.py's ``get_bridge_isolation`` instantiates
``genie.libs.parser.arcos.show_bridge_isolation.ShowBridgeIsolation``
directly (NOT device.parse()), so tests patch ``ShowBridgeIsolation`` in the
get module's namespace and drive the public get_* helper off canned parser
output that matches the ShowBridgeIsolation schema.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.bridge_isolation import get as bi_get
from genie.libs.sdk.apis.arcos.bridge_isolation.get import get_bridge_isolation

MOD = "genie.libs.sdk.apis.arcos.bridge_isolation.get"

_PARSED = {
    "isolation-enabled": True,
    "isolation-drop-packets": 42,
    "isolation-drop-octets": 5376,
}

_PARSED_DISABLED = {
    "isolation-enabled": False,
}


class _DummyDevice:
    """Placeholder device -- ShowBridgeIsolation is patched, so this is
    unused beyond being a valid argument."""
    name = "rtr1"


class TestGetBridgeIsolation(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowBridgeIsolation")
    def test_get_bridge_isolation(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_bridge_isolation(self.device, "swp1")
        self.assertTrue(result["isolation-enabled"])
        self.assertEqual(result["isolation-drop-packets"], 42)
        self.assertEqual(result["isolation-drop-octets"], 5376)

    @patch(f"{MOD}.ShowBridgeIsolation")
    def test_get_bridge_isolation_interface_passed_to_parser(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        get_bridge_isolation(self.device, "swp1")
        mock_parser.return_value.parse.assert_called_with(interface="swp1")

    @patch(f"{MOD}.ShowBridgeIsolation")
    def test_get_bridge_isolation_disabled(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED_DISABLED
        result = get_bridge_isolation(self.device, "swp2")
        self.assertFalse(result["isolation-enabled"])
        self.assertNotIn("isolation-drop-packets", result)

    @patch(f"{MOD}.ShowBridgeIsolation")
    def test_get_bridge_isolation_empty_on_schema_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bridge_isolation(self.device, "swp1"), {})

    @patch(f"{MOD}.ShowBridgeIsolation")
    def test_get_bridge_isolation_empty_on_unexpected_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(get_bridge_isolation(self.device, "swp1"), {})


class TestBridgeIsolationGetFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    bridge_isolation/get.py must be referenced by name somewhere in this
    test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(bi_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == bi_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Bridge Isolation get/is functions: {missing}")

        print(
            f"\nBridge Isolation get/is coverage: {len(names)} functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
