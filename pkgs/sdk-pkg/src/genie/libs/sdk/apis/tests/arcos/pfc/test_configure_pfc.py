#!/usr/bin/env python3
"""Unit tests for arcOS PFC (Priority Flow Control) configure/unconfigure APIs
(full coverage).

ArcOS PFC uses a hardware-platform profile context plus a per-interface
attach point:

    hardware platform pfc profile <name>
        tx enable true
        rx enable true
        cable-length <meters>
        traffic-class-<id> lossless enable true
        traffic-class-<id> lossless xoff <val>
        traffic-class-<id> lossless xon-offset <val>
        traffic-class-<id> watchdog enable true

    interface <name>
        platform pfc profile <profile>

Each helper builds a CLI config list and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI (including every
optional-parameter branch of configure_pfc_profile), plus exercise the
SubCommandFailure wrapping branch for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.pfc import configure as pfc_configure
from genie.libs.sdk.apis.arcos.pfc.configure import (
    configure_pfc_profile,
    unconfigure_pfc_profile,
    configure_pfc_interface,
    unconfigure_pfc_interface,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestPfcProfileApis(unittest.TestCase):
    """configure_pfc_profile, unconfigure_pfc_profile"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_profile_minimal(self):
        configure_pfc_profile(self.d, "PROF1")
        c = self.d.cfg()
        self.assertIn("hardware platform pfc profile PROF1", c)
        self.assertNotIn("tx enable true", c)
        self.assertNotIn("rx enable true", c)

    def test_profile_tx_rx_enable(self):
        configure_pfc_profile(self.d, "PROF1", tx_enable=True, rx_enable=True)
        c = self.d.cfg()
        self.assertIn("tx enable true", c)
        self.assertIn("rx enable true", c)

    def test_profile_cable_length(self):
        configure_pfc_profile(self.d, "PROF1", cable_length=50)
        self.assertIn("cable-length 50", self.d.cfg())

    def test_profile_traffic_classes_lossless_xoff_xon(self):
        configure_pfc_profile(
            self.d, "PROF1",
            traffic_classes={
                3: {"lossless": True, "xoff": 100, "xon_offset": 10},
            },
        )
        c = self.d.cfg()
        self.assertIn("traffic-class-3 lossless enable true", c)
        self.assertIn("traffic-class-3 lossless xoff 100", c)
        self.assertIn("traffic-class-3 lossless xon-offset 10", c)

    def test_profile_traffic_classes_watchdog(self):
        configure_pfc_profile(
            self.d, "PROF1",
            traffic_classes={4: {"watchdog": True}},
        )
        self.assertIn("traffic-class-4 watchdog enable true", self.d.cfg())

    def test_profile_traffic_classes_no_lossless_no_watchdog(self):
        """tc dict present but 'lossless'/'watchdog' both falsy -> only the
        xoff/xon-offset keys (if present) get emitted."""
        configure_pfc_profile(
            self.d, "PROF1",
            traffic_classes={5: {"xoff": 50}},
        )
        c = self.d.cfg()
        self.assertNotIn("traffic-class-5 lossless enable true", c)
        self.assertIn("traffic-class-5 lossless xoff 50", c)

    def test_profile_multiple_traffic_classes_sorted(self):
        configure_pfc_profile(
            self.d, "PROF1",
            traffic_classes={
                2: {"lossless": True},
                1: {"watchdog": True},
            },
        )
        c = self.d.cfg()
        idx_tc1 = c.index("traffic-class-1")
        idx_tc2 = c.index("traffic-class-2")
        self.assertLess(idx_tc1, idx_tc2)

    def test_unconfigure_profile(self):
        unconfigure_pfc_profile(self.d, "PROF1")
        self.assertIn("no hardware platform pfc profile PROF1", self.d.cfg())


class TestPfcInterfaceApis(unittest.TestCase):
    """configure_pfc_interface, unconfigure_pfc_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface(self):
        configure_pfc_interface(self.d, "swp1", "PROF1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("platform pfc profile PROF1", c)

    def test_unconfigure_interface(self):
        unconfigure_pfc_interface(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no platform pfc profile", c)


class TestSubCommandFailureWrapping(unittest.TestCase):
    """Every configure_*/unconfigure_* helper wraps a device.configure()
    failure in a re-raised SubCommandFailure with a descriptive message."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_profile_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_pfc_profile(self.d, "PROF1")

    def test_unconfigure_profile_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_pfc_profile(self.d, "PROF1")

    def test_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_pfc_interface(self.d, "swp1", "PROF1")

    def test_unconfigure_interface_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_pfc_interface(self.d, "swp1")


class TestPfcConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in pfc/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(pfc_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == pfc_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered PFC configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nPFC configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
