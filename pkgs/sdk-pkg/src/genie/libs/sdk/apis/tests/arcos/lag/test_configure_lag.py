#!/usr/bin/env python3
"""Unit tests for arcOS LAG (LACP/Bond) configure/unconfigure APIs (full
coverage).

Each helper builds an arcOS CLI config list under `interface <bond>` (or
`lacp interface <bond>` for LACP interval) and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.lag import configure as lag_configure
from genie.libs.sdk.apis.arcos.lag.configure import (
    configure_lag_bond,
    unconfigure_lag_bond,
    configure_lag_member,
    unconfigure_lag_member,
    configure_lag_fallback,
    unconfigure_lag_fallback,
    configure_lag_l2_trunk,
    unconfigure_lag_l2_trunk,
    configure_lacp_interval,
    unconfigure_lacp_interval,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureLagBond(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_bond_basic(self):
        configure_lag_bond(self.d, "bond10")
        c = self.d.cfg()
        self.assertIn("interface bond10", c)
        self.assertIn("enabled true", c)
        self.assertIn("aggregation lag-type LACP", c)

    def test_bond_static_type(self):
        configure_lag_bond(self.d, "bond10", lag_type="STATIC")
        self.assertIn("aggregation lag-type STATIC", self.d.cfg())

    def test_bond_min_links(self):
        configure_lag_bond(self.d, "bond10", lag_type="LACP", min_links=2)
        self.assertIn("aggregation min-links 2", self.d.cfg())

    def test_unconfigure_bond(self):
        unconfigure_lag_bond(self.d, "bond10")
        self.assertIn("no interface bond10", self.d.cfg())


class TestConfigureLagMember(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_member(self):
        configure_lag_member(self.d, "swp10", "bond10")
        c = self.d.cfg()
        self.assertIn("interface swp10", c)
        self.assertIn("enabled true", c)
        self.assertIn("ethernet aggregate-id bond10", c)

    def test_unconfigure_member(self):
        unconfigure_lag_member(self.d, "swp10")
        c = self.d.cfg()
        self.assertIn("interface swp10", c)
        self.assertIn("no ethernet aggregate-id", c)


class TestConfigureLagFallback(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_fallback_default_mode(self):
        configure_lag_fallback(self.d, "bond1")
        c = self.d.cfg()
        self.assertIn("interface bond1", c)
        self.assertIn("aggregation lacp fallback mode INDIVIDUAL", c)

    def test_fallback_full(self):
        configure_lag_fallback(
            self.d, "bond1", mode="INDIVIDUAL", timeout=100, primary="swp3"
        )
        c = self.d.cfg()
        self.assertIn("aggregation lacp fallback mode INDIVIDUAL", c)
        self.assertIn("aggregation lacp fallback timeout 100", c)
        self.assertIn(
            "aggregation lacp fallback primary-interface swp3", c
        )

    def test_unconfigure_fallback(self):
        unconfigure_lag_fallback(self.d, "bond1")
        c = self.d.cfg()
        self.assertIn("interface bond1", c)
        self.assertIn("no aggregation lacp fallback mode", c)
        self.assertIn("no aggregation lacp fallback timeout", c)
        self.assertIn(
            "no aggregation lacp fallback primary-interface", c
        )


class TestConfigureLagL2Trunk(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_l2_trunk_list(self):
        configure_lag_l2_trunk(self.d, "bond11", [10, 20])
        c = self.d.cfg()
        self.assertIn("interface bond11", c)
        self.assertIn(
            "aggregation switched-vlan interface-mode TRUNK", c
        )
        self.assertIn(
            "aggregation switched-vlan trunk-vlans [ 10 20 ]", c
        )

    def test_l2_trunk_scalar(self):
        configure_lag_l2_trunk(self.d, "bond11", 30)
        self.assertIn(
            "aggregation switched-vlan trunk-vlans [ 30 ]", self.d.cfg()
        )

    def test_unconfigure_l2_trunk(self):
        unconfigure_lag_l2_trunk(self.d, "bond11")
        c = self.d.cfg()
        self.assertIn("interface bond11", c)
        self.assertIn(
            "no aggregation switched-vlan interface-mode", c
        )
        self.assertIn("no aggregation switched-vlan trunk-vlans", c)


class TestConfigureLacpInterval(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_interval_default(self):
        configure_lacp_interval(self.d, "bond111")
        c = self.d.cfg()
        self.assertIn("lacp interface bond111", c)
        self.assertIn("interval FAST", c)

    def test_interval_slow(self):
        configure_lacp_interval(self.d, "bond111", "SLOW")
        self.assertIn("interval SLOW", self.d.cfg())

    def test_unconfigure_interval(self):
        unconfigure_lacp_interval(self.d, "bond111")
        self.assertIn("no lacp interface bond111", self.d.cfg())


class TestLagConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in lag/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(lag_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == lag_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered LAG configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nLAG configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
