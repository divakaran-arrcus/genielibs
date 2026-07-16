#!/usr/bin/env python3
"""Unit tests for arcOS VLAN configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under a `vlan <name>` context and
calls device.configure(list). Tests mock device.configure and assert the
emitted CLI. A machine coverage check (test_zzz_all_functions_covered) asserts
that every public configure_*/unconfigure_* function in the module was
exercised by some test in this file.
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

# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


configure_vlan = _track("configure_vlan", configure_vlan)
unconfigure_vlan = _track("unconfigure_vlan", unconfigure_vlan)
configure_vlan_name = _track("configure_vlan_name", configure_vlan_name)
unconfigure_vlan_name = _track("unconfigure_vlan_name", unconfigure_vlan_name)


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
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in configure.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in vlan/configure.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
