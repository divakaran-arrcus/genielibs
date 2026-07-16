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

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


get_vlans = _track("get_vlans", get_vlans)
get_vlan = _track("get_vlan", get_vlan)
get_vlan_members = _track("get_vlan_members", get_vlan_members)
get_vlan_count = _track("get_vlan_count", get_vlan_count)
get_vlan_name = _track("get_vlan_name", get_vlan_name)
get_vlan_status = _track("get_vlan_status", get_vlan_status)
is_vlan_present = _track("is_vlan_present", is_vlan_present)


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
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in get.py must
        have been called by at least one test above (excluding the
        internal _parse_vlans helper, which is exercised indirectly)."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(get_module, inspect.isfunction)
            if obj.__module__ == get_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in vlan/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
