#!/usr/bin/env python3
"""Unit tests for arcOS static routing configure/unconfigure APIs (full coverage).

Both helpers in genie.libs.sdk.apis.arcos.static_routing.configure build an
arcOS CLI config list (`network-instance <ni> / protocol STATIC default /
static-route <prefix> / ...`) and call `device.configure(config)`. Tests mock
`device.configure` and assert on distinctive substrings of the emitted CLI,
plus verify SubCommandFailure propagation on failure.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.static_routing.configure import (
    configure_static_route,
    unconfigure_static_route,
)


import inspect
import genie.libs.sdk.apis.arcos.static_routing.configure as configure_module
class _CfgDevice:
    def __init__(self, raise_exc=None):
        self.name = "rtr1"
        self._raise = raise_exc
        self.configure = Mock(side_effect=self._configure_side_effect)

    def _configure_side_effect(self, *args, **kwargs):
        if self._raise is not None:
            raise self._raise
        return True

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureStaticRoute(unittest.TestCase):
    """configure_static_route: default/null next-hop, explicit next-hop,
    metric, tag, custom network-instance, and failure propagation."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_default_null_next_hop(self):
        """next_hop defaults to 'null' -> emits 'next-hop DROP', no tag/metric."""
        configure_static_route(self.d, "100.100.100.0/24")
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("protocol STATIC default", c)
        self.assertIn("static-route 100.100.100.0/24", c)
        self.assertIn("next-hop-index nh1", c)
        self.assertIn("next-hop DROP", c)
        self.assertNotIn("set-tag", c)
        self.assertNotIn("metric", c)

    def test_explicit_next_hop_metric_tag(self):
        """Explicit IP next-hop + metric + tag + custom network-instance."""
        configure_static_route(
            self.d,
            "100.100.100.0/24",
            next_hop="10.1.1.1",
            metric=5,
            tag=1000,
            network_instance="vrf1",
        )
        c = self.d.cfg()
        self.assertIn("network-instance vrf1", c)
        self.assertIn("static-route 100.100.100.0/24", c)
        self.assertIn("set-tag 1000", c)
        self.assertIn("next-hop 10.1.1.1", c)
        self.assertIn("metric 5", c)

    def test_null_next_hop_case_insensitive(self):
        """next_hop='NULL' (any case) is treated as blackhole DROP."""
        configure_static_route(self.d, "10.0.0.0/8", next_hop="NULL")
        self.assertIn("next-hop DROP", self.d.cfg())

    def test_tag_none_omits_set_tag(self):
        configure_static_route(self.d, "10.0.0.0/8", tag=None)
        self.assertNotIn("set-tag", self.d.cfg())

    def test_metric_none_omits_metric(self):
        configure_static_route(self.d, "10.0.0.0/8", next_hop="10.1.1.1", metric=None)
        self.assertNotIn("metric", self.d.cfg())

    def test_exit_sequence(self):
        """Four exits close next-hop-index, static-route, protocol, network-instance."""
        configure_static_route(self.d, "10.0.0.0/8")
        c = self.d.cfg()
        self.assertEqual(c.count("exit"), 4)

    def test_configure_failure_raises(self):
        d = _CfgDevice(raise_exc=SubCommandFailure("boom"))
        with self.assertRaises(SubCommandFailure):
            configure_static_route(d, "10.0.0.0/8")


class TestUnconfigureStaticRoute(unittest.TestCase):
    """unconfigure_static_route: default/custom network-instance and
    failure propagation."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_unconfigure_default(self):
        unconfigure_static_route(self.d, "100.100.100.0/24")
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("protocol STATIC default", c)
        self.assertIn("no static-route 100.100.100.0/24", c)

    def test_unconfigure_custom_network_instance(self):
        unconfigure_static_route(self.d, "10.0.0.0/8", network_instance="vrf1")
        self.assertIn("network-instance vrf1", self.d.cfg())

    def test_unconfigure_failure_raises(self):
        d = _CfgDevice(raise_exc=SubCommandFailure("boom"))
        with self.assertRaises(SubCommandFailure):
            unconfigure_static_route(d, "10.0.0.0/8")




class TestStaticRoutingConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure/unconfigure function in
    static_routing/configure.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
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
            f"Uncovered static_routing configure functions: {missing}")
if __name__ == "__main__":
    unittest.main()
