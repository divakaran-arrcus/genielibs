#!/usr/bin/env python3
"""Unit tests for arcOS SLA get APIs (full coverage).

get.py's ``get_sla_icmp`` instantiates
``genie.libs.parser.arcos.show_sla.ShowSlaIcmp`` directly (NOT
device.parse()), so tests patch ``ShowSlaIcmp`` in the get module's
namespace and drive the public get_* helper off canned parser output that
matches the ShowSlaIcmp schema.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.sla import get as sla_get
from genie.libs.sdk.apis.arcos.sla.get import get_sla_icmp

MOD = "genie.libs.sdk.apis.arcos.sla.get"

_PARSED = {
    "admin-state": True,
    "sessions": {
        "probe1": {
            "name": "probe1",
            "admin-state": True,
            "target-address": "10.0.0.1",
            "source-address": "10.0.0.2",
            "session-interval": 60,
            "probe-count": 5,
            "probe-interval": 1000,
            "payload-size": 256,
        },
        "probe2": {
            "name": "probe2",
            "admin-state": False,
        },
    },
}

_PARSED_NO_SESSIONS = {
    "admin-state": False,
}


class _DummyDevice:
    """Placeholder device -- ShowSlaIcmp is patched, so this is unused
    beyond being a valid argument."""
    name = "rtr1"


class TestGetSlaIcmp(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_sla_icmp(self.device)
        self.assertTrue(result["admin-state"])
        self.assertIn("probe1", result["sessions"])
        self.assertEqual(result["sessions"]["probe1"]["target-address"], "10.0.0.1")
        self.assertEqual(result["sessions"]["probe1"]["probe-count"], 5)

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp_default_ni_passed_to_parser(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        get_sla_icmp(self.device)
        mock_parser.return_value.parse.assert_called_with(ni="default")

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp_named_instance_passed_to_parser(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        get_sla_icmp(self.device, network_instance="vrf-red")
        mock_parser.return_value.parse.assert_called_with(ni="vrf-red")

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp_no_sessions(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED_NO_SESSIONS
        result = get_sla_icmp(self.device)
        self.assertFalse(result["admin-state"])
        self.assertNotIn("sessions", result)

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp_empty_on_schema_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_sla_icmp(self.device), {})

    @patch(f"{MOD}.ShowSlaIcmp")
    def test_get_sla_icmp_empty_on_unexpected_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(get_sla_icmp(self.device), {})


class TestSlaGetFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    sla/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sla_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sla_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered SLA get/is functions: {missing}")

        print(
            f"\nSLA get/is coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
