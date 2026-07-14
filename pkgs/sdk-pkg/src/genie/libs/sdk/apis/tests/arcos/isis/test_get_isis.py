#!/usr/bin/env python3
"""Unit tests for arcOS ISIS get APIs.

Uses a dummy device whose ``parse()`` returns pre-canned parser output (matching
the arcOS ISIS parser model), so the get helpers are exercised without a real
device. Mirrors the arcos/route_policy API test style.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_net,
    get_isis_system_id,
    get_isis_adjacency,
    get_isis_adjacency_count,
)


# Combined parsed structure: get_isis_net/system_id read ["global"];
# get_isis_adjacency reads ["interface"] under isis[<instance>].
_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "net": ["49.0000.0000.0000.0005.00"],
                        "system-id": "0000.0000.0005",
                    },
                    "interface": {
                        "swp1": {
                            "level": {
                                2: {
                                    "adjacency": {
                                        "rtr2": {
                                            "state": "UP",
                                            "adjacency-type": "LEVEL_2",
                                        }
                                    }
                                }
                            }
                        },
                        "swp2": {
                            "level": {
                                1: {
                                    "adjacency": {
                                        "rtr3": {"state": "UP"}
                                    }
                                }
                            }
                        },
                    },
                }
            }
        }
    }
}


class _DummyDevice:
    """Returns a fixed parsed dict, or raises, from parse()."""

    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestGetIsisData(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_isis_net(self):
        self.assertEqual(get_isis_net(self.device), "49.0000.0000.0000.0005.00")

    def test_get_isis_system_id(self):
        self.assertEqual(get_isis_system_id(self.device), "0000.0000.0005")

    def test_get_isis_adjacency_all(self):
        result = get_isis_adjacency(self.device)
        self.assertIn("interface", result)
        self.assertEqual(set(result["interface"]), {"swp1", "swp2"})

    def test_get_isis_adjacency_interface_filter(self):
        result = get_isis_adjacency(self.device, interface="swp1")
        self.assertEqual(set(result["interface"]), {"swp1"})

    def test_get_isis_adjacency_interface_filter_miss(self):
        # No match -> empty dict (helper returns {} when nothing matches).
        result = get_isis_adjacency(self.device, interface="swp9")
        self.assertEqual(result, {})

    def test_get_isis_adjacency_count(self):
        self.assertEqual(get_isis_adjacency_count(self.device), 2)

    def test_get_isis_adjacency_count_interface(self):
        self.assertEqual(
            get_isis_adjacency_count(self.device, interface="swp1"), 1
        )


class TestGetIsisEmpty(unittest.TestCase):
    """Empty / no-data behavior: helpers degrade to None / empty, not raise."""

    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_get_isis_net_none(self):
        self.assertIsNone(get_isis_net(self.device))

    def test_get_isis_system_id_none(self):
        self.assertIsNone(get_isis_system_id(self.device))

    def test_get_isis_adjacency_empty(self):
        self.assertEqual(get_isis_adjacency(self.device), {})

    def test_get_isis_adjacency_count_zero(self):
        self.assertEqual(get_isis_adjacency_count(self.device), 0)


if __name__ == "__main__":
    unittest.main()
