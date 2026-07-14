#!/usr/bin/env python3
"""Unit tests for arcOS ISIS verify APIs.

Verify helpers wrap the get helpers in a Timeout retry loop and return bool.
Positive cases return True on the first iteration (fast); negative cases use
max_time=0 so the loop exits immediately instead of polling.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.isis.verify import (
    verify_isis_system_id,
    verify_isis_adjacency_present,
    verify_isis_adjacency_not_present,
)


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
                                2: {"adjacency": {"rtr2": {"state": "UP"}}}
                            }
                        },
                    },
                }
            }
        }
    }
}


class _DummyDevice:
    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestVerifyIsis(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)
        self.empty = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_system_id_present(self):
        self.assertTrue(verify_isis_system_id(self.device))

    def test_system_id_absent_fast_fail(self):
        self.assertFalse(verify_isis_system_id(self.empty, max_time=0))

    def test_adjacency_present(self):
        self.assertTrue(verify_isis_adjacency_present(self.device, adjacency="rtr2"))

    def test_adjacency_present_false_fast_fail(self):
        self.assertFalse(
            verify_isis_adjacency_present(self.device, adjacency="rtrX", max_time=0)
        )

    def test_adjacency_not_present_true(self):
        self.assertTrue(
            verify_isis_adjacency_not_present(self.device, adjacency="rtrX")
        )

    def test_adjacency_not_present_false_fast_fail(self):
        # rtr2 IS present, so "not present" is False (fast-fail via max_time=0).
        self.assertFalse(
            verify_isis_adjacency_not_present(self.device, adjacency="rtr2", max_time=0)
        )


if __name__ == "__main__":
    unittest.main()
