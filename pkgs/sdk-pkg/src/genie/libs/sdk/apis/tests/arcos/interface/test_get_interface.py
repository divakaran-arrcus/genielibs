#!/usr/bin/env python3
"""Unit tests for arcOS Interface get APIs (full coverage).

The get helpers use device.parse("show interface[ <intf>]") (dict keyed by
interface name), so a dummy device returning canned parser output exercises them.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.interface.get import (
    get_interface_status,
    get_interface_information,
    is_interface_up,
    get_interface_mtu,
    get_interfaces,
    get_interface_names,
    get_interface_description,
    get_interface_ipv4_addresses,
    get_interface_ipv4_address,
    get_interface_ipv6_addresses,
)

_PARSED = {
    "swp1": {
        "name": "swp1",
        "type": "ethernetCsmacd",
        "mtu": 9000,
        "enabled": True,
        "admin-status": "UP",
        "oper-status": "UP",
        "description": "link to rtr2",
        "ipv4-addresses": {"10.0.0.1": {"prefix-length": 24}},
        "ipv6-addresses": {"2001:db8::1": {"prefix-length": 64}},
    },
    "swp2": {  # oper down
        "name": "swp2", "mtu": 1500, "enabled": True,
        "admin-status": "UP", "oper-status": "DOWN", "description": "",
    },
    "swp3": {  # admin down
        "name": "swp3", "mtu": 1500, "enabled": False,
        "admin-status": "DOWN", "oper-status": "DOWN", "description": "",
    },
}


class _DummyDevice:
    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestGetInterface(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_interfaces(self):
        self.assertEqual(set(get_interfaces(self.device)), {"swp1", "swp2", "swp3"})

    def test_get_interface_names(self):
        self.assertEqual(set(get_interface_names(self.device)), {"swp1", "swp2", "swp3"})

    def test_get_interface_status_up(self):
        self.assertEqual(get_interface_status(self.device, "swp1"), "up")

    def test_get_interface_status_down(self):
        self.assertEqual(get_interface_status(self.device, "swp2"), "down")

    def test_get_interface_status_admin_down(self):
        self.assertEqual(get_interface_status(self.device, "swp3"), "admin-down")

    def test_is_interface_up(self):
        self.assertTrue(is_interface_up(self.device, "swp1"))
        self.assertFalse(is_interface_up(self.device, "swp2"))

    def test_get_interface_information(self):
        self.assertEqual(get_interface_information(self.device, "swp1")["mtu"], 9000)

    def test_get_interface_information_missing(self):
        self.assertIsNone(get_interface_information(self.device, "swp9"))

    def test_get_interface_mtu(self):
        self.assertEqual(get_interface_mtu(self.device, "swp1"), 9000)

    def test_get_interface_description(self):
        self.assertEqual(get_interface_description(self.device, "swp1"), "link to rtr2")

    def test_get_interface_ipv4_addresses(self):
        self.assertEqual(
            get_interface_ipv4_addresses(self.device, "swp1"),
            {"10.0.0.1": {"prefix-length": 24}},
        )

    def test_get_interface_ipv4_address(self):
        self.assertEqual(get_interface_ipv4_address(self.device, "swp1"), "10.0.0.1")

    def test_get_interface_ipv6_addresses(self):
        self.assertIn("2001:db8::1", get_interface_ipv6_addresses(self.device, "swp1"))


class TestGetInterfaceEmpty(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_get_interfaces_empty(self):
        self.assertEqual(get_interfaces(self.device), {})

    def test_get_interface_mtu_none(self):
        self.assertIsNone(get_interface_mtu(self.device, "swp1"))

    def test_is_interface_up_false(self):
        self.assertFalse(is_interface_up(self.device, "swp1"))

    def test_get_interface_ipv4_addresses_empty(self):
        self.assertEqual(get_interface_ipv4_addresses(self.device, "swp1"), {})

    def test_get_interface_status_none(self):
        self.assertIsNone(get_interface_status(self.device, "swp1"))


if __name__ == "__main__":
    unittest.main()
