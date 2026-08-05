#!/usr/bin/env python3
"""Unit tests for arcOS Interface verify APIs (full coverage).

Verify helpers wrap the get helpers in a Timeout loop; positive cases return on
the first iteration, negatives use max_time=0 to fast-fail.
"""

import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.interface.verify import (
    verify_interface_state,
    verify_interface_state_up,
    verify_interface_state_down,
    verify_interface_state_admin_down,
    verify_interface_mtu,
    verify_interface_ipv4_address,
    verify_interface_description,
)

_PARSED = {
    "swp1": {
        "name": "swp1", "mtu": 9000, "enabled": True,
        "admin-status": "UP", "oper-status": "UP", "description": "link to rtr2",
        "ipv4-addresses": {"10.0.0.1": {"prefix-length": 24}},
    },
    "swp2": {
        "name": "swp2", "mtu": 1500, "enabled": True,
        "admin-status": "UP", "oper-status": "DOWN", "description": "",
    },
    "swp3": {
        "name": "swp3", "mtu": 1500, "enabled": False,
        "admin-status": "DOWN", "oper-status": "DOWN", "description": "",
    },
}


import inspect
import genie.libs.sdk.apis.arcos.interface.verify as verify_module
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

    def test_state_expected(self):
        self.assertTrue(verify_interface_state(self.device, "swp1", expected_status="up"))
        self.assertTrue(verify_interface_state(self.device, "swp2", expected_status="down"))

    def test_state_up(self):
        self.assertTrue(verify_interface_state_up(self.device, "swp1"))

    def test_state_up_false_fast_fail(self):
        self.assertFalse(verify_interface_state_up(self.empty, "swp1", max_time=0))

    def test_state_down(self):
        self.assertTrue(verify_interface_state_down(self.device, "swp2"))

    def test_state_down_false_fast_fail(self):
        self.assertFalse(verify_interface_state_down(self.device, "swp1", max_time=0))

    def test_state_admin_down(self):
        self.assertTrue(verify_interface_state_admin_down(self.device, "swp3"))

    def test_state_admin_down_false_fast_fail(self):
        self.assertFalse(verify_interface_state_admin_down(self.device, "swp1", max_time=0))

    def test_mtu_match(self):
        self.assertTrue(verify_interface_mtu(self.device, "swp1", 9000))

    def test_mtu_mismatch_fast_fail(self):
        self.assertFalse(verify_interface_mtu(self.device, "swp1", 1500, max_time=0))

    def test_ipv4_address_match(self):
        self.assertTrue(verify_interface_ipv4_address(self.device, "swp1", "10.0.0.1"))

    def test_ipv4_address_mismatch_fast_fail(self):
        self.assertFalse(
            verify_interface_ipv4_address(self.device, "swp1", "9.9.9.9", max_time=0)
        )

    def test_description_match(self):
        self.assertTrue(
            verify_interface_description(self.device, "swp1", "link to rtr2")
        )

    def test_description_mismatch_fast_fail(self):
        self.assertFalse(
            verify_interface_description(self.device, "swp1", "nope", max_time=0)
        )




class TestInterfaceVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify function in
    interface/verify.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(verify_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == verify_module.__name__
            and (name.startswith("verify_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered interface verify functions: {missing}")
if __name__ == "__main__":
    unittest.main()
