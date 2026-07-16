#!/usr/bin/env python3
"""Unit tests for arcOS ACL get APIs (full coverage).

get.py's private ``_parse_acl`` instantiates
``genie.libs.parser.arcos.show_acl.ShowAclSet`` directly (NOT
device.parse()), so tests patch ``ShowAclSet`` in the get module's
namespace and drive the public get_*/is_* helpers off canned parser
output that matches the ShowAclSet schema.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.acl.get import (
    get_acl_sets,
    get_acl_set,
    get_acl_entries,
    is_acl_set_present,
    get_acl_set_count,
)

MOD = "genie.libs.sdk.apis.arcos.acl.get"

_PARSED = {
    "acl-sets": {
        "v4-acl ACL_IPV4": {
            "name": "v4-acl",
            "type": "ACL_IPV4",
            "description": "user ACL",
            "acl-entries": {
                "10": {
                    "sequence-id": "10",
                    "ipv4-source-address": "10.0.0.0/8",
                    "forwarding-action": "DROP",
                },
                "1000": {
                    "sequence-id": "1000",
                    "ipv4-source-address": "0.0.0.0/0",
                    "forwarding-action": "ACCEPT",
                },
            },
        },
        "v6-acl ACL_IPV6": {
            "name": "v6-acl",
            "type": "ACL_IPV6",
        },
    }
}

_SINGLE_PARSED = {
    "acl-sets": {
        "solo-acl ACL_L2": {
            "name": "solo-acl",
            "type": "ACL_L2",
        },
    }
}


class _DummyDevice:
    """Placeholder device -- ShowAclSet is patched, so this is unused
    beyond being a valid argument."""
    name = "rtr1"


class TestGetAclSets(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_sets(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_acl_sets(self.device)
        self.assertIn("v4-acl ACL_IPV4", result)
        self.assertIn("v6-acl ACL_IPV6", result)

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_sets_empty_on_schema_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_acl_sets(self.device), {})

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_sets_empty_on_unexpected_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(get_acl_sets(self.device), {})


class TestGetAclSet(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_set_exact_key_match(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_acl_set(self.device, "v4-acl", "ACL_IPV4")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "v4-acl")
        self.assertEqual(result["type"], "ACL_IPV4")

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_set_single_fallback(self, mock_parser):
        """When the exact 'name type' key isn't found but exactly one ACL
        set exists, fall back to it."""
        mock_parser.return_value.parse.return_value = _SINGLE_PARSED
        result = get_acl_set(self.device, "solo-acl", "ACL_IPV4")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "solo-acl")

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_set_not_found_multiple(self, mock_parser):
        """No exact match and more than one ACL set -> None."""
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_acl_set(self.device, "missing-acl", "ACL_IPV4")
        self.assertIsNone(result)

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_set_not_found_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertIsNone(get_acl_set(self.device, "v4-acl", "ACL_IPV4"))


class TestGetAclEntries(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_entries(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        entries = get_acl_entries(self.device, "v4-acl", "ACL_IPV4")
        self.assertIn("10", entries)
        self.assertIn("1000", entries)

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_entries_no_entries_key(self, mock_parser):
        mock_parser.return_value.parse.return_value = _SINGLE_PARSED
        entries = get_acl_entries(self.device, "solo-acl", "ACL_L2")
        self.assertEqual(entries, {})

    @patch(f"{MOD}.ShowAclSet")
    def test_get_acl_entries_acl_not_found(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_acl_entries(self.device, "v4-acl", "ACL_IPV4"), {})


class TestIsAclSetPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowAclSet")
    def test_present_true(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        self.assertTrue(is_acl_set_present(self.device, "v4-acl", "ACL_IPV4"))

    @patch(f"{MOD}.ShowAclSet")
    def test_present_false(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertFalse(is_acl_set_present(self.device, "v4-acl", "ACL_IPV4"))


class TestGetAclSetCount(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowAclSet")
    def test_count_two(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        self.assertEqual(get_acl_set_count(self.device), 2)

    @patch(f"{MOD}.ShowAclSet")
    def test_count_zero_when_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_acl_set_count(self.device), 0)


class TestAclGetFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    acl/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.acl import get as acl_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(acl_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == acl_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered ACL get/is functions: {missing}")

        print(
            f"\nACL get/is coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
