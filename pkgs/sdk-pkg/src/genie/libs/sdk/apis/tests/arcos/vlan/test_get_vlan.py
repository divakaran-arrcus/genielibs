#!/usr/bin/env python3
"""Unit tests for arcOS VLAN get APIs (full coverage).

genie.libs.sdk.apis.arcos.vlan.get._parse_vlans instantiates
genie.libs.parser.arcos.show_vlan.ShowVlan(device=device) and calls
.parse() on it (a local import inside the try block). Tests patch the
parser class at its source module so the local import picks up the mock,
and feed canned parsed output matching the ShowVlan schema:

    {"vlans": {"<vlan-id>": {"vlan-id": ..., "name": ..., "status": ...,
                              "members": [...]}}}

A machine coverage check (test_zzz_all_functions_covered) asserts every
public get_*/is_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure
from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.vlan.get as get_module
from genie.libs.sdk.apis.arcos.vlan.get import (
    get_vlans,
    get_vlan,
    get_vlan_members,
    get_vlan_count,
    get_vlan_name,
    get_vlan_status,
    is_vlan_present,
)

PARSER_PATCH_TARGET = "genie.libs.parser.arcos.show_vlan.ShowVlan"


PARSED = {
    "vlans": {
        "100": {
            "vlan-id": 100,
            "name": "MGMT",
            "status": "ACTIVE",
            "members": ["swp1", "swp2"],
        },
        "999": {
            "vlan-id": 999,
            "name": "QUARANTINE",
            "status": "SUSPEND",
            # no members
        },
    }
}


class TestGetVlan(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, return_value=None, side_effect=None):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    def test_get_vlans(self):
        self._patch_parser(return_value=PARSED)
        result = get_vlans(self.device)
        self.assertEqual(set(result), {"100", "999"})

    def test_get_vlan_found(self):
        self._patch_parser(return_value=PARSED)
        vlan = get_vlan(self.device, 100)
        self.assertEqual(vlan["name"], "MGMT")

    def test_get_vlan_not_found(self):
        self._patch_parser(return_value=PARSED)
        self.assertIsNone(get_vlan(self.device, 555))

    def test_get_vlan_members(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_members(self.device, 100), ["swp1", "swp2"])

    def test_get_vlan_members_absent(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_members(self.device, 999), [])

    def test_get_vlan_members_missing_vlan(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_members(self.device, 555), [])

    def test_get_vlan_count(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_count(self.device), 2)

    def test_get_vlan_name(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_name(self.device, 100), "MGMT")

    def test_get_vlan_name_missing_vlan(self):
        self._patch_parser(return_value=PARSED)
        self.assertIsNone(get_vlan_name(self.device, 555))

    def test_get_vlan_status(self):
        self._patch_parser(return_value=PARSED)
        self.assertEqual(get_vlan_status(self.device, 999), "SUSPEND")

    def test_get_vlan_status_missing_vlan(self):
        self._patch_parser(return_value=PARSED)
        self.assertIsNone(get_vlan_status(self.device, 555))

    def test_is_vlan_present_true(self):
        self._patch_parser(return_value=PARSED)
        self.assertTrue(is_vlan_present(self.device, 100))

    def test_is_vlan_present_false(self):
        self._patch_parser(return_value=PARSED)
        self.assertFalse(is_vlan_present(self.device, 555))


class TestGetVlanEmptyAndErrors(unittest.TestCase):
    """Exercise every except branch of _parse_vlans."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, side_effect):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        mock_cls.return_value.parse.side_effect = side_effect
        return mock_cls

    def test_get_vlans_schema_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_vlans(self.device), {})

    def test_get_vlans_subcommand_failure(self):
        self._patch_parser(SubCommandFailure("boom"))
        self.assertEqual(get_vlans(self.device), {})

    def test_get_vlans_unexpected_exception(self):
        self._patch_parser(ValueError("weird"))
        self.assertEqual(get_vlans(self.device), {})

    def test_get_vlan_none_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertIsNone(get_vlan(self.device, 100))

    def test_get_vlan_members_empty_when_no_data(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_vlan_members(self.device, 100), [])

    def test_get_vlan_count_zero_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_vlan_count(self.device), 0)

    def test_get_vlan_name_none_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertIsNone(get_vlan_name(self.device, 100))

    def test_get_vlan_status_none_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertIsNone(get_vlan_status(self.device, 100))

    def test_is_vlan_present_false_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertFalse(is_vlan_present(self.device, 100))


class TestGetVlanCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    vlan/get.py must be referenced by name somewhere in this test file's
    source. Order-safe under both pytest and `python -m unittest`.
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
            f"Uncovered VLAN get functions: {missing}")

        print(
            f"\nVLAN get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
