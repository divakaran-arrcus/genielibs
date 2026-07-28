#!/usr/bin/env python3
"""Unit tests for arcOS Port Security get APIs (full coverage).

genie.libs.sdk.apis.arcos.port_security.get imports
genie.libs.parser.arcos.show_port_security.ShowPortSecurity at module load
time (`from ... import ShowPortSecurity`), so the patch target is the name
bound in the API module itself:
genie.libs.sdk.apis.arcos.port_security.get.ShowPortSecurity

Canned data matches the ShowPortSecuritySchema:
    {"profiles": {<name>: {"name", "limit", "sticky", "violation-policy"}},
     "interfaces": {<name>: {"name", "enabled", "profile",
                              "violation-count", "learned-mac-count"}}}
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from unicon.core.errors import SubCommandFailure
from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.port_security.get as get_module
from genie.libs.sdk.apis.arcos.port_security.get import get_port_security

PARSER_PATCH_TARGET = "genie.libs.sdk.apis.arcos.port_security.get.ShowPortSecurity"

PARSED = {
    "profiles": {
        "PROF1": {
            "name": "PROF1",
            "limit": 5,
            "sticky": False,
            "violation-policy": "restrict",
        },
    },
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "profile": "PROF1",
            "violation-count": 0,
            "learned-mac-count": 3,
        },
    },
}


class TestGetPortSecurity(unittest.TestCase):
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

    def test_get_port_security(self):
        self._patch_parser(return_value=PARSED)
        result = get_port_security(self.device)
        self.assertEqual(result["profiles"]["PROF1"]["limit"], 5)
        self.assertEqual(result["interfaces"]["swp1"]["profile"], "PROF1")

    def test_get_port_security_schema_empty(self):
        self._patch_parser(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_port_security(self.device), {})

    def test_get_port_security_unexpected_exception(self):
        self._patch_parser(side_effect=ValueError("weird"))
        self.assertEqual(get_port_security(self.device), {})

    def test_get_port_security_subcommand_failure(self):
        self._patch_parser(side_effect=SubCommandFailure("boom"))
        self.assertEqual(get_port_security(self.device), {})


class TestPortSecurityGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    port_security/get.py must be referenced by name somewhere in this
    test file's source. Order-safe under both pytest (file order) and
    unittest (alphabetical class order via dir()).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name
            for name, obj in inspect.getmembers(get_module, inspect.isfunction)
            if obj.__module__ == get_module.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested public functions in port_security/get.py: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
