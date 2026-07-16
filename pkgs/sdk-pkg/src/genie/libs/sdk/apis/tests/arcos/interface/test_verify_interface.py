#!/usr/bin/env python3
"""Unit tests for arcOS Interface verify APIs.

Verify helpers wrap the get helpers in a Timeout loop; positive cases return on
the first iteration, negatives use max_time=0 to fast-fail.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.interface.verify import (
    verify_interface_state_up,
    verify_interface_mtu,
)

_PARSED = {
    "swp1": {
        "name": "swp1",
        "mtu": 9000,
        "enabled": True,
        "admin-status": "UP",
        "oper-status": "UP",
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


class TestVerifyInterface(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)
        self.empty = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_state_up(self):
        self.assertTrue(verify_interface_state_up(self.device, "swp1"))

    def test_state_up_false_fast_fail(self):
        self.assertFalse(verify_interface_state_up(self.empty, "swp1", max_time=0))

    def test_mtu_match(self):
        self.assertTrue(verify_interface_mtu(self.device, "swp1", 9000))

    def test_mtu_mismatch_fast_fail(self):
        self.assertFalse(verify_interface_mtu(self.device, "swp1", 1500, max_time=0))


if __name__ == "__main__":
    unittest.main()
