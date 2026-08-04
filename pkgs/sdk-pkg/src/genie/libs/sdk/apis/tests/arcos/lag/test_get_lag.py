#!/usr/bin/env python3
"""Unit tests for arcOS LAG (LACP/Bond) get APIs (full coverage).

The get helpers instantiate ``ShowLacpInterface`` directly (device.parse is
not used) and normalize its ``SchemaEmptyParserError`` into an empty dict.
A dummy device with a canned ``.parse()`` on the parser class stand-in
exercises the happy path; a device whose parser raises
``SchemaEmptyParserError`` exercises the empty-output path.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.lag.get import (
    get_lag_interfaces,
    get_lag_bond,
    get_lag_members,
    get_lag_member_sync_state,
    get_lag_bond_count,
)

MOD = "genie.libs.sdk.apis.arcos.lag.get"

_PARSED = {
    "interfaces": {
        "bond10": {
            "name": "bond10",
            "interval": "FAST",
            "members": {
                "swp10": {
                    "interface": "swp10",
                    "timeout": "SHORT",
                    "synchronization": "IN_SYNC",
                    "aggregatable": True,
                    "collecting": True,
                    "distributing": True,
                },
                "swp20": {
                    "interface": "swp20",
                    "timeout": "SHORT",
                    "synchronization": "OUT_SYNC",
                    "aggregatable": True,
                    "collecting": False,
                    "distributing": False,
                },
            },
        },
        "bond20": {
            "name": "bond20",
            "interval": "SLOW",
        },
    }
}


import inspect
import genie.libs.sdk.apis.arcos.lag.get as get_module
class _DummyDevice:
    """Stand-in device; ShowLacpInterface is patched so device is unused."""
    name = "rtr1"


class TestGetLag(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()
        patcher = patch(f"{MOD}.ShowLacpInterface")
        self.mock_parser_cls = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser_cls.return_value.parse.return_value = _PARSED

    def test_get_lag_interfaces(self):
        result = get_lag_interfaces(self.device)
        self.assertEqual(set(result), {"bond10", "bond20"})

    def test_get_lag_bond_found(self):
        result = get_lag_bond(self.device, "bond10")
        self.assertEqual(result["name"], "bond10")
        self.assertIn("members", result)

    def test_get_lag_bond_not_found_multi_interface(self):
        # bond9 not present, and >1 interfaces exist -> None
        result = get_lag_bond(self.device, "bond9")
        self.assertIsNone(result)

    def test_get_lag_bond_fallback_single_entry(self):
        single = {"interfaces": {"bond30": {"name": "bond30"}}}
        self.mock_parser_cls.return_value.parse.return_value = single
        result = get_lag_bond(self.device, "bondXYZ")
        self.assertEqual(result["name"], "bond30")

    def test_get_lag_members(self):
        result = get_lag_members(self.device, "bond10")
        self.assertEqual(set(result), {"swp10", "swp20"})

    def test_get_lag_members_no_bond(self):
        result = get_lag_members(self.device, "bond9")
        self.assertEqual(result, {})

    def test_get_lag_member_sync_state_in_sync(self):
        self.assertEqual(
            get_lag_member_sync_state(self.device, "bond10", "swp10"),
            "IN_SYNC",
        )

    def test_get_lag_member_sync_state_out_sync(self):
        self.assertEqual(
            get_lag_member_sync_state(self.device, "bond10", "swp20"),
            "OUT_SYNC",
        )

    def test_get_lag_member_sync_state_missing_member(self):
        self.assertIsNone(
            get_lag_member_sync_state(self.device, "bond10", "swp99")
        )

    def test_get_lag_bond_count(self):
        self.assertEqual(get_lag_bond_count(self.device), 2)


class TestGetLagEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- all getters degrade
    gracefully to empty/None."""

    def setUp(self):
        self.device = _DummyDevice()
        patcher = patch(f"{MOD}.ShowLacpInterface")
        self.mock_parser_cls = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser_cls.return_value.parse.side_effect = (
            SchemaEmptyParserError("empty")
        )

    def test_get_lag_interfaces_empty(self):
        self.assertEqual(get_lag_interfaces(self.device), {})

    def test_get_lag_bond_empty(self):
        self.assertIsNone(get_lag_bond(self.device, "bond10"))

    def test_get_lag_members_empty(self):
        self.assertEqual(get_lag_members(self.device, "bond10"), {})

    def test_get_lag_member_sync_state_empty(self):
        self.assertIsNone(
            get_lag_member_sync_state(self.device, "bond10", "swp10")
        )

    def test_get_lag_bond_count_empty(self):
        self.assertEqual(get_lag_bond_count(self.device), 0)


class TestGetLagUnexpectedException(unittest.TestCase):
    """Non-SchemaEmptyParserError exceptions are also swallowed (defensive
    branch in _parse_lacp)."""

    def setUp(self):
        self.device = _DummyDevice()
        patcher = patch(f"{MOD}.ShowLacpInterface")
        self.mock_parser_cls = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser_cls.return_value.parse.side_effect = RuntimeError(
            "boom"
        )

    def test_get_lag_interfaces_swallows_exception(self):
        self.assertEqual(get_lag_interfaces(self.device), {})




class TestLagGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get/is function in
    lag/get.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(get_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == get_module.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered lag get functions: {missing}")
if __name__ == "__main__":
    unittest.main()
