#!/usr/bin/env python3
"""Unit tests for arcOS VLAN configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under a `vlan <name>` context and
calls device.configure(list). Tests mock device.configure and assert the
emitted CLI. A machine coverage check (TestConfigureVlanCoverage) asserts
that every public configure_*/unconfigure_* function in the module is
referenced by name somewhere in this test file's source.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.vlan.configure as configure_module
from genie.libs.sdk.apis.arcos.vlan.configure import (
    configure_vlan,
    unconfigure_vlan,
    configure_vlan_name,
    unconfigure_vlan_name,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureVlan(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_vlan(self):
        configure_vlan(self.d, "marketing", 100)
        c = self.d.cfg()
        self.assertIn("vlan marketing", c)
        self.assertIn("vlan-id 100", c)

    def test_unconfigure_vlan(self):
        unconfigure_vlan(self.d, "marketing")
        self.assertIn("no vlan marketing", self.d.cfg())

    def test_configure_vlan_name(self):
        configure_vlan_name(self.d, "marketing", "marketing-floor2")
        c = self.d.cfg()
        self.assertIn("vlan marketing", c)
        self.assertIn("name marketing-floor2", c)

    def test_unconfigure_vlan_name(self):
        unconfigure_vlan_name(self.d, "marketing")
        c = self.d.cfg()
        self.assertIn("vlan marketing", c)
        self.assertIn("no name", c)


class TestConfigureVlanFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_vlan_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_vlan(self.d, "marketing", 100)

    def test_unconfigure_vlan_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_vlan(self.d, "marketing")

    def test_configure_vlan_name_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_vlan_name(self.d, "marketing", "marketing-floor2")

    def test_unconfigure_vlan_name_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_vlan_name(self.d, "marketing")


class TestConfigureVlanCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in vlan/configure.py must be referenced by name somewhere in
    this test file's source. Order-safe under both pytest and
    `python -m unittest` (unlike a runtime call-tracking gate).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(configure_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == configure_module.__name__
            and (name.startswith("configure_") or name.startswith("unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered VLAN configure functions: {missing}")

        print(
            f"\nVLAN configure coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
