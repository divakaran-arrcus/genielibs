#!/usr/bin/env python3
"""Unit tests for arcOS gNMI get APIs (full coverage).

genie.libs.sdk.apis.arcos.gnmi.get.get_gnmi_server instantiates
``genie.libs.parser.arcos.show_gnmi.ShowGnmiServer`` directly (bypassing
``device.parse``) and calls ``.parse()`` on it. Tests therefore patch the
``ShowGnmiServer`` name as imported into the ``get`` module and return
canned parser output shaped like the real ``ShowGnmiServer`` schema.
``is_gnmi_server_enabled`` is layered on top of ``get_gnmi_server`` and is
exercised through the same patched parser.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.gnmi import get as gnmi_get
from genie.libs.sdk.apis.arcos.gnmi.get import (
    get_gnmi_server,
    is_gnmi_server_enabled,
)

MOD = "genie.libs.sdk.apis.arcos.gnmi.get"

CANNED_OUTPUT = {
    "enabled": True,
    "transport-security": True,
    "port": 57400,
    "listen-addresses": ["10.0.0.1", "10.0.0.2"],
    "clients-connected": 2,
}

CANNED_OUTPUT_DISABLED = {
    "enabled": False,
    "port": 57400,
}


class TestGetGnmiServer(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowGnmiServer")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_gnmi_server(self):
        result = get_gnmi_server(self.device)
        self.assertTrue(result["enabled"])
        self.assertTrue(result["transport-security"])
        self.assertEqual(result["port"], 57400)
        self.assertEqual(result["listen-addresses"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(result["clients-connected"], 2)

    def test_is_gnmi_server_enabled_true(self):
        self.assertTrue(is_gnmi_server_enabled(self.device))


class TestGetGnmiServerDisabled(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowGnmiServer")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT_DISABLED

    def test_is_gnmi_server_enabled_false(self):
        self.assertFalse(is_gnmi_server_enabled(self.device))


class TestGetGnmiServerEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- get_gnmi_server should
    degrade to {}, and is_gnmi_server_enabled to False."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowGnmiServer")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )

    def test_get_gnmi_server_empty(self):
        self.assertEqual(get_gnmi_server(self.device), {})

    def test_is_gnmi_server_enabled_empty(self):
        self.assertFalse(is_gnmi_server_enabled(self.device))


class TestGetGnmiServerGenericException(unittest.TestCase):
    """Any unexpected exception from the parser should also degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowGnmiServer")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = RuntimeError("boom")

    def test_get_gnmi_server_generic_exception(self):
        self.assertEqual(get_gnmi_server(self.device), {})


class TestGnmiGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    gnmi/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(gnmi_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == gnmi_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered gNMI get functions: {missing}")

        print(
            f"\ngNMI get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
