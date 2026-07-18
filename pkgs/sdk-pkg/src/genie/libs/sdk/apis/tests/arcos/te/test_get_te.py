#!/usr/bin/env python3
"""Unit tests for arcOS TE get APIs (full coverage).

genie.libs.sdk.apis.arcos.te.get._parse_te_admin_groups performs a *local*
import of ShowTeAdminGroup inside the function body (not a module-level
import), so patching must target the parser's home module
(genie.libs.parser.arcos.show_te.ShowTeAdminGroup) rather than an
attribute on the get module itself. The helper constructs the parser
directly (ShowTeAdminGroup(device=device).parse(...)) -- it does not go
through device.parse().
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.te import get as te_get
from genie.libs.sdk.apis.arcos.te.get import (
    get_te_admin_groups,
    get_te_admin_group,
    is_te_admin_group_present,
    get_te_admin_group_count,
)

_PATCH_TARGET = "genie.libs.parser.arcos.show_te.ShowTeAdminGroup"

_PARSED = {
    "network-instance": {
        "default": {
            "admin-groups": {
                "red": {"name": "red", "bit-position": 11},
                "green": {"name": "green", "bit-position": 2},
            }
        }
    }
}

_PARSED_EMPTY_NI = {
    "network-instance": {
        "default": {}
    }
}


def _make_parser_mock(return_value=None, side_effect=None):
    """Build a mock class whose instance's .parse() returns/raises as given."""
    instance = Mock()
    if side_effect is not None:
        instance.parse.side_effect = side_effect
    else:
        instance.parse.return_value = return_value
    parser_cls = Mock(return_value=instance)
    return parser_cls


class TestGetTeAdminGroups(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_get_te_admin_groups(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            result = get_te_admin_groups(self.device)
        self.assertEqual(
            result,
            {
                "red": {"name": "red", "bit-position": 11},
                "green": {"name": "green", "bit-position": 2},
            },
        )

    def test_get_te_admin_groups_named_instance(self):
        parsed = {
            "network-instance": {
                "vrf1": {"admin-groups": {"blue": {"name": "blue", "bit-position": 5}}}
            }
        }
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=parsed)):
            result = get_te_admin_groups(self.device, network_instance="vrf1")
        self.assertEqual(result, {"blue": {"name": "blue", "bit-position": 5}})

    def test_get_te_admin_group_found(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            result = get_te_admin_group(self.device, "red")
        self.assertEqual(result, {"name": "red", "bit-position": 11})

    def test_get_te_admin_group_missing(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            result = get_te_admin_group(self.device, "purple")
        self.assertIsNone(result)

    def test_is_te_admin_group_present_true(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            self.assertTrue(is_te_admin_group_present(self.device, "green"))

    def test_is_te_admin_group_present_false(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            self.assertFalse(is_te_admin_group_present(self.device, "purple"))

    def test_get_te_admin_group_count(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED)):
            self.assertEqual(get_te_admin_group_count(self.device), 2)


class TestGetTeAdminGroupsDegraded(unittest.TestCase):
    """Empty / degraded data and error paths."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_schema_empty_parser_error(self):
        with patch(
            _PATCH_TARGET,
            _make_parser_mock(side_effect=SchemaEmptyParserError("empty")),
        ):
            self.assertEqual(get_te_admin_groups(self.device), {})
            self.assertIsNone(get_te_admin_group(self.device, "red"))
            self.assertFalse(is_te_admin_group_present(self.device, "red"))
            self.assertEqual(get_te_admin_group_count(self.device), 0)

    def test_subcommand_failure(self):
        with patch(
            _PATCH_TARGET,
            _make_parser_mock(side_effect=SubCommandFailure("boom")),
        ):
            self.assertEqual(get_te_admin_groups(self.device), {})

    def test_unexpected_exception(self):
        with patch(
            _PATCH_TARGET,
            _make_parser_mock(side_effect=RuntimeError("weird")),
        ):
            self.assertEqual(get_te_admin_groups(self.device), {})

    def test_no_network_instance_key(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value={})):
            self.assertEqual(get_te_admin_groups(self.device), {})

    def test_network_instance_present_but_no_admin_groups(self):
        with patch(_PATCH_TARGET, _make_parser_mock(return_value=_PARSED_EMPTY_NI)):
            self.assertEqual(get_te_admin_groups(self.device), {})
            self.assertEqual(get_te_admin_group_count(self.device), 0)

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(te_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == te_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered TE get functions: {missing}")

        print(f"\nTE get coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
