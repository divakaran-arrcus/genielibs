#!/usr/bin/env python3
"""Unit tests for arcOS Static VXLAN configure/unconfigure APIs (full
coverage).

Each helper builds an arcOS CLI config list (either a bare `overlay
static-vxlan <bool>` toggle, or a `network-instance <ni>` context for the
L2VLAN_AWARE_BUNDLE static-vxlan NI) and calls device.configure(list). Tests
mock device.configure and assert the emitted CLI. A machine coverage check
(test_zzz_all_functions_covered) asserts that every public
configure_*/unconfigure_* function in the module was exercised by some test
in this file.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.static_vxlan.configure as configure_module
from genie.libs.sdk.apis.arcos.static_vxlan.configure import (
    configure_static_vxlan_global,
    unconfigure_static_vxlan_global,
    configure_static_vxlan_ni,
    unconfigure_static_vxlan_ni,
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


configure_static_vxlan_global = _track(
    "configure_static_vxlan_global", configure_static_vxlan_global)
unconfigure_static_vxlan_global = _track(
    "unconfigure_static_vxlan_global", unconfigure_static_vxlan_global)
configure_static_vxlan_ni = _track(
    "configure_static_vxlan_ni", configure_static_vxlan_ni)
unconfigure_static_vxlan_ni = _track(
    "unconfigure_static_vxlan_ni", unconfigure_static_vxlan_ni)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureStaticVxlanGlobal(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_global_default_enabled(self):
        configure_static_vxlan_global(self.d)
        self.assertIn("overlay static-vxlan true", self.d.cfg())

    def test_global_explicit_disabled(self):
        configure_static_vxlan_global(self.d, enabled=False)
        self.assertIn("overlay static-vxlan false", self.d.cfg())

    def test_unconfigure_global(self):
        unconfigure_static_vxlan_global(self.d)
        self.assertIn("overlay static-vxlan false", self.d.cfg())


class TestConfigureStaticVxlanNi(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_ni_basic_list_vteps(self):
        configure_static_vxlan_ni(
            self.d, "vxlan-ni1",
            remote_vteps=["10.0.0.1", "10.0.0.2"],
            vni_vlan_map={100: 10, 200: 20},
        )
        c = self.d.cfg()
        self.assertIn("network-instance vxlan-ni1", c)
        self.assertIn("type L2VLAN_AWARE_BUNDLE", c)
        self.assertIn("local-tunnel-endpoint-id 0", c)
        self.assertIn(
            "static-vxlan remote-vteps [ 10.0.0.1 10.0.0.2 ]", c)
        self.assertIn("vni 100 vlan-id 10", c)
        self.assertIn("vni 200 vlan-id 20", c)

    def test_ni_vni_map_sorted(self):
        configure_static_vxlan_ni(
            self.d, "vxlan-ni2",
            remote_vteps=["10.0.0.5"],
            vni_vlan_map={300: 30, 100: 10, 200: 20},
        )
        c = self.d.cfg()
        idx_100 = c.index("vni 100 vlan-id 10")
        idx_200 = c.index("vni 200 vlan-id 20")
        idx_300 = c.index("vni 300 vlan-id 30")
        self.assertLess(idx_100, idx_200)
        self.assertLess(idx_200, idx_300)

    def test_ni_string_vteps_and_custom_ltep(self):
        configure_static_vxlan_ni(
            self.d, "vxlan-ni3",
            remote_vteps="10.0.0.9",
            vni_vlan_map={500: 50},
            ltep_id=7,
        )
        c = self.d.cfg()
        self.assertIn("network-instance vxlan-ni3", c)
        self.assertIn("local-tunnel-endpoint-id 7", c)
        self.assertIn("static-vxlan remote-vteps [ 10.0.0.9 ]", c)
        self.assertIn("vni 500 vlan-id 50", c)

    def test_unconfigure_ni(self):
        unconfigure_static_vxlan_ni(self.d, "vxlan-ni1")
        self.assertIn("no network-instance vxlan-ni1", self.d.cfg())


class TestConfigureStaticVxlanFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_global_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_static_vxlan_global(self.d)

    def test_unconfigure_global_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_static_vxlan_global(self.d)

    def test_configure_ni_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_static_vxlan_ni(
                self.d, "vxlan-ni1",
                remote_vteps=["10.0.0.1"],
                vni_vlan_map={100: 10},
            )

    def test_unconfigure_ni_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_static_vxlan_ni(self.d, "vxlan-ni1")


class TestConfigureStaticVxlanCoverage(unittest.TestCase):
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
            f"Untested public functions in static_vxlan/configure.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
