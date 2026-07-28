#!/usr/bin/env python3
"""Unit tests for arcOS SNMP get APIs (full coverage).

genie.libs.sdk.apis.arcos.snmp.get.get_snmp_server instantiates
genie.libs.parser.arcos.show_snmp.ShowSnmpServer(device=device) and calls
.parse() on it. The import is a module-level `from ... import ShowSnmpServer`
in get.py, so the name is bound into get.py's own namespace at import time;
tests must patch it at that usage site (genie.libs.sdk.apis.arcos.snmp.get.
ShowSnmpServer), not at its original definition module, or the patch has no
effect. Canned parsed output matches the ShowSnmpServer schema:

    {"enabled": bool, "active": bool (optional)}

A machine coverage check (test_zzz_all_functions_covered) asserts every
public get_*/is_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure
from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.snmp.get as get_module
from genie.libs.sdk.apis.arcos.snmp.get import (
    get_snmp_server,
    is_snmp_server_enabled,
)

PARSER_PATCH_TARGET = "genie.libs.sdk.apis.arcos.snmp.get.ShowSnmpServer"


PARSED_ENABLED = {"enabled": True, "active": True}
PARSED_DISABLED = {"enabled": False}


class TestGetSnmpServer(unittest.TestCase):
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

    def test_get_snmp_server_enabled(self):
        self._patch_parser(return_value=PARSED_ENABLED)
        result = get_snmp_server(self.device)
        self.assertEqual(result, PARSED_ENABLED)

    def test_get_snmp_server_disabled(self):
        self._patch_parser(return_value=PARSED_DISABLED)
        result = get_snmp_server(self.device)
        self.assertEqual(result["enabled"], False)

    def test_is_snmp_server_enabled_true(self):
        self._patch_parser(return_value=PARSED_ENABLED)
        self.assertTrue(is_snmp_server_enabled(self.device))

    def test_is_snmp_server_enabled_false(self):
        self._patch_parser(return_value=PARSED_DISABLED)
        self.assertFalse(is_snmp_server_enabled(self.device))


class TestGetSnmpServerEmptyAndErrors(unittest.TestCase):
    """Exercise every except branch of get_snmp_server."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, side_effect):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        mock_cls.return_value.parse.side_effect = side_effect
        return mock_cls

    def test_get_snmp_server_schema_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_snmp_server(self.device), {})

    def test_get_snmp_server_subcommand_failure(self):
        self._patch_parser(SubCommandFailure("boom"))
        self.assertEqual(get_snmp_server(self.device), {})

    def test_get_snmp_server_unexpected_exception(self):
        self._patch_parser(ValueError("weird"))
        self.assertEqual(get_snmp_server(self.device), {})

    def test_is_snmp_server_enabled_false_when_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertFalse(is_snmp_server_enabled(self.device))


class TestGetSnmpCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    snmp/get.py must be referenced by name somewhere in this test file's
    source. Order-safe under both pytest and `python -m unittest` (unlike
    a runtime call-tracking gate, which depends on other test classes
    having already run).
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
            f"Uncovered SNMP get functions: {missing}")


if __name__ == "__main__":
    unittest.main()
