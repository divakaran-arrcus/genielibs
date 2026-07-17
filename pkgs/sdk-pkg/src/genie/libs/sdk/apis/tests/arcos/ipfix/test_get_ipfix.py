#!/usr/bin/env python3
"""Unit tests for arcOS IPFIX get APIs (full coverage).

genie.libs.sdk.apis.arcos.ipfix.get.get_ipfix_state instantiates
``genie.libs.parser.arcos.show_ipfix.ShowIpfix`` directly (bypassing
``device.parse``) and calls ``.parse()`` on it. Tests therefore patch the
``ShowIpfix`` name as imported into the ``get`` module and return canned
parser output shaped like the real ``ShowIpfix`` schema.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.ipfix import get as ipfix_get
from genie.libs.sdk.apis.arcos.ipfix.get import get_ipfix_state

MOD = "genie.libs.sdk.apis.arcos.ipfix.get"

CANNED_OUTPUT = {
    "observation-points": {
        "OBS1": {"name": "OBS1", "observation-domain-id": 100},
    },
    "exporting-processes": {
        "EXP1": {
            "name": "EXP1",
            "destinations": {
                "DEST1": {
                    "name": "DEST1",
                    "destination-address": "10.0.0.2",
                    "destination-port": 4739,
                    "packets-sent": 1000,
                    "packets-dropped": 0,
                },
            },
        },
    },
}


class TestGetIpfix(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowIpfix")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_ipfix_state(self):
        result = get_ipfix_state(self.device)
        self.assertIn("OBS1", result["observation-points"])
        self.assertEqual(
            result["observation-points"]["OBS1"]["observation-domain-id"], 100
        )
        self.assertIn("EXP1", result["exporting-processes"])
        dest = result["exporting-processes"]["EXP1"]["destinations"]["DEST1"]
        self.assertEqual(dest["destination-address"], "10.0.0.2")
        self.assertEqual(dest["destination-port"], 4739)
        self.assertEqual(dest["packets-sent"], 1000)
        self.assertEqual(dest["packets-dropped"], 0)


class TestGetIpfixEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- get_ipfix_state should
    degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowIpfix")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )

    def test_get_ipfix_state_empty(self):
        self.assertEqual(get_ipfix_state(self.device), {})


class TestGetIpfixGenericException(unittest.TestCase):
    """Any unexpected exception from the parser should also degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowIpfix")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = RuntimeError("boom")

    def test_get_ipfix_state_generic_exception(self):
        self.assertEqual(get_ipfix_state(self.device), {})


class TestIpfixGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    ipfix/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ipfix_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ipfix_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered IPFIX get functions: {missing}")

        print(
            f"\nIPFIX get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
