#!/usr/bin/env python3
"""Unit tests for arcOS Static VXLAN get APIs (full coverage).

genie.libs.sdk.apis.arcos.static_vxlan.get imports
genie.libs.parser.arcos.show_static_vxlan.ShowStaticVxlanTunnels at module
import time and instantiates it as ShowStaticVxlanTunnels(device=device).parse().
Tests patch the class at its import site in the get module
(genie.libs.sdk.apis.arcos.static_vxlan.get.ShowStaticVxlanTunnels) so the
already-bound reference is replaced, and feed canned parsed output matching
the ShowStaticVxlanTunnels schema:

    {"tunnels": {"<remote-vtep-ip>": {"remote-vtep": ..., "local-vtep": ...,
                                       "state": ..., "vnis": [...]}}}

A machine coverage check (test_zzz_all_functions_covered) asserts every
public get_*/is_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

import genie.libs.sdk.apis.arcos.static_vxlan.get as get_module
from genie.libs.sdk.apis.arcos.static_vxlan.get import get_static_vxlan_tunnels

PARSER_PATCH_TARGET = (
    "genie.libs.sdk.apis.arcos.static_vxlan.get.ShowStaticVxlanTunnels"
)

PARSED = {
    "tunnels": {
        "10.0.0.1": {
            "remote-vtep": "10.0.0.1",
            "local-vtep": "10.0.0.100",
            "state": "up",
            "vnis": [100, 200],
        },
        "10.0.0.2": {
            # degraded entry: no local-vtep/state/vnis, only the
            # mandatory remote-vtep key (matches Optional() schema fields)
            "remote-vtep": "10.0.0.2",
        },
    }
}


class TestGetStaticVxlanTunnels(unittest.TestCase):
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

    def test_get_static_vxlan_tunnels_success(self):
        self._patch_parser(return_value=PARSED)
        result = get_static_vxlan_tunnels(self.device)
        self.assertEqual(result, PARSED)
        self.assertEqual(set(result["tunnels"]), {"10.0.0.1", "10.0.0.2"})

    def test_get_static_vxlan_tunnels_degraded_entry(self):
        self._patch_parser(return_value=PARSED)
        result = get_static_vxlan_tunnels(self.device)
        degraded = result["tunnels"]["10.0.0.2"]
        self.assertEqual(degraded["remote-vtep"], "10.0.0.2")
        self.assertNotIn("local-vtep", degraded)
        self.assertNotIn("vnis", degraded)

    def test_get_static_vxlan_tunnels_instantiated_with_device_kwarg(self):
        mock_cls = self._patch_parser(return_value=PARSED)
        get_static_vxlan_tunnels(self.device)
        mock_cls.assert_called_once_with(device=self.device)


class TestGetStaticVxlanTunnelsEmptyAndErrors(unittest.TestCase):
    """Exercise every except branch of get_static_vxlan_tunnels."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def _patch_parser(self, side_effect):
        patcher = patch(PARSER_PATCH_TARGET)
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        mock_cls.return_value.parse.side_effect = side_effect
        return mock_cls

    def test_get_static_vxlan_tunnels_schema_empty(self):
        self._patch_parser(SchemaEmptyParserError("empty"))
        self.assertEqual(get_static_vxlan_tunnels(self.device), {})

    def test_get_static_vxlan_tunnels_unexpected_exception(self):
        self._patch_parser(ValueError("weird"))
        self.assertEqual(get_static_vxlan_tunnels(self.device), {})


class TestGetStaticVxlanCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    static_vxlan/get.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and `python -m unittest`.
    """

    def test_zzz_all_functions_covered(self):
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
            f"Untested public functions in static_vxlan/get.py: {missing}")


if __name__ == "__main__":
    unittest.main()
