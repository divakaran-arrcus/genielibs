#!/usr/bin/env python3
"""Unit tests for arcOS DHCP Relay get APIs (full coverage).

genie.libs.sdk.apis.arcos.dhcp_relay.get.get_dhcp_relay instantiates
``genie.libs.parser.arcos.show_dhcp_relay.ShowDhcpRelay`` directly and calls
``.parse()`` on it. Tests therefore patch the ``ShowDhcpRelay`` name as
imported into the ``get`` module and return canned parser output shaped
like the real ``ShowDhcpRelay`` schema.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.dhcp_relay import get as dhcp_relay_get
from genie.libs.sdk.apis.arcos.dhcp_relay.get import get_dhcp_relay

MOD = "genie.libs.sdk.apis.arcos.dhcp_relay.get"

CANNED_OUTPUT = {
    "helper-addresses": ["10.0.0.5"],
    "use-interface-vrf": True,
    "agent-information-option": True,
    "counters": {
        "received-requests": 10,
        "received-responses": 8,
        "relayed-requests": 10,
        "relayed-responses": 8,
        "total-drops": 0,
    },
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "helper-addresses": ["10.0.0.5"],
        }
    },
}


class TestGetDhcpRelay(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowDhcpRelay")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_dhcp_relay_found(self):
        result = get_dhcp_relay(self.device)
        self.assertEqual(result, CANNED_OUTPUT)

    def test_get_dhcp_relay_fields(self):
        result = get_dhcp_relay(self.device)
        self.assertEqual(result["helper-addresses"], ["10.0.0.5"])
        self.assertTrue(result["use-interface-vrf"])
        self.assertTrue(result["agent-information-option"])
        self.assertEqual(result["counters"]["received-requests"], 10)
        self.assertEqual(result["interfaces"]["swp1"]["name"], "swp1")


class TestGetDhcpRelayDegrade(unittest.TestCase):
    """Parser raises -- get_dhcp_relay should degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_get_dhcp_relay_empty(self):
        with patch(f"{MOD}.ShowDhcpRelay") as mock_parser:
            mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
                "empty"
            )
            self.assertEqual(get_dhcp_relay(self.device), {})

    def test_get_dhcp_relay_exception(self):
        with patch(f"{MOD}.ShowDhcpRelay") as mock_parser:
            mock_parser.return_value.parse.side_effect = RuntimeError("boom")
            self.assertEqual(get_dhcp_relay(self.device), {})


class TestDhcpRelayGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    dhcp_relay/get.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(dhcp_relay_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == dhcp_relay_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered DHCP Relay get functions: {missing}"
        )

        print(f"\nDHCP Relay get coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
