#!/usr/bin/env python3
"""Unit tests for arcOS STP get APIs (full coverage).

Both get helpers instantiate genie.libs.parser.arcos.show_stp.ShowStpGlobal
directly and call .parse() -- they do not go through device.parse(). Tests
patch ShowStpGlobal where it is imported into the get module and drive
canned parser output (built from the ShowStpGlobal schema in show_stp.py).
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.stp.get import (
    get_stp_global,
    get_stp_enabled_protocol,
)

MOD = "genie.libs.sdk.apis.arcos.stp.get"

GLOBAL_PARSED = {
    "bridge-assurance": True,
    "bpdu-guard": True,
    "enabled-protocol": "RAPID_PVST",
}


class _DummyDevice:
    """Minimal device stand-in; ShowStpGlobal is patched so no execute()
    is actually invoked."""
    name = "rtr1"


class TestGetStp(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowStpGlobal")
    def test_get_stp_global(self, mock_parser):
        mock_parser.return_value.parse.return_value = GLOBAL_PARSED
        result = get_stp_global(self.device)
        self.assertEqual(result, GLOBAL_PARSED)

    @patch(f"{MOD}.ShowStpGlobal")
    def test_get_stp_enabled_protocol(self, mock_parser):
        mock_parser.return_value.parse.return_value = GLOBAL_PARSED
        self.assertEqual(
            get_stp_enabled_protocol(self.device), "RAPID_PVST")


class TestGetStpEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- get_* helpers degrade
    gracefully instead of propagating."""

    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowStpGlobal")
    def test_get_stp_global_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_stp_global(self.device), {})

    @patch(f"{MOD}.ShowStpGlobal")
    def test_get_stp_enabled_protocol_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertIsNone(get_stp_enabled_protocol(self.device))

    @patch(f"{MOD}.ShowStpGlobal")
    def test_get_stp_global_unexpected_exception(self, mock_parser):
        """Any other exception is logged and also degrades to {}."""
        mock_parser.return_value.parse.side_effect = RuntimeError("boom")
        self.assertEqual(get_stp_global(self.device), {})


class TestGetStpCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_* function in
    stp/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.stp import get as stp_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(stp_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == stp_get.__name__
            and name.startswith("get_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered STP get functions: {missing}")

        print(f"\nSTP get coverage: {len(names)} get_*, 0 missing")


if __name__ == "__main__":
    unittest.main()
