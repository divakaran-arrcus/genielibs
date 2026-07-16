#!/usr/bin/env python3
"""Unit tests for arcOS Interface get APIs.

The get helpers use device.parse("show interface") (dict keyed by interface
name), so a dummy device returning canned parser output exercises them.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.interface.get import (
    get_interfaces,
    get_interface_names,
    get_interface_mtu,
    get_interface_information,
    is_interface_up,
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
    },
    "loopback0": {
        "name": "loopback0",
        "type": "softwareLoopback",
        "mtu": 65536,
        "enabled": True,
        "admin-status": "UP",
        "oper-status": "UP",
        "description": "",
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
        self.assertEqual(set(get_interfaces(self.device)), {"swp1", "loopback0"})

    def test_get_interface_names(self):
        self.assertEqual(set(get_interface_names(self.device)), {"swp1", "loopback0"})

    def test_get_interface_mtu(self):
        self.assertEqual(get_interface_mtu(self.device, "swp1"), 9000)

    def test_get_interface_information(self):
        info = get_interface_information(self.device, "swp1")
        self.assertEqual(info["description"], "link to rtr2")

    def test_get_interface_information_missing(self):
        self.assertIsNone(get_interface_information(self.device, "swp9"))

    def test_is_interface_up(self):
        self.assertTrue(is_interface_up(self.device, "swp1"))


class TestGetInterfaceEmpty(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_get_interfaces_empty(self):
        self.assertEqual(get_interfaces(self.device), {})

    def test_get_interface_mtu_none(self):
        self.assertIsNone(get_interface_mtu(self.device, "swp1"))

    def test_is_interface_up_false(self):
        self.assertFalse(is_interface_up(self.device, "swp1"))


if __name__ == "__main__":
    unittest.main()
