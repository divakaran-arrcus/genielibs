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

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


get_snmp_server = _track("get_snmp_server", get_snmp_server)
is_snmp_server_enabled = _track("is_snmp_server_enabled", is_snmp_server_enabled)


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
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in get.py must
        have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(get_module, inspect.isfunction)
            if obj.__module__ == get_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in snmp/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
