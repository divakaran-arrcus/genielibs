#!/usr/bin/env python3
"""Unit tests for arcOS SRv6 OAM configure/unconfigure APIs
(full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.srv6_oam.configure builds an arcOS CLI
config list (starting with the `oam profile <profile_name>` context)
and calls device.configure(config). Tests mock device.configure and
assert on a distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.srv6_oam import configure as srv6_oam_configure
from genie.libs.sdk.apis.arcos.srv6_oam.configure import (
    configure_srv6_oam_profile,
    unconfigure_srv6_oam_profile,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureSrv6OamProfile(unittest.TestCase):
    """configure_srv6_oam_profile"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_profile_all_params(self):
        configure_srv6_oam_profile(
            self.d, profile_name="p1", enabled=True, latency=100,
            pkt_loss_percent=5, dampening_multiplier=3,
            max_consecutive_pkt_loss=10,
            monitor_interval="OAM_MONITOR_INTERVAL_10s",
        )
        c = self.d.cfg()
        self.assertIn("oam profile p1", c)
        self.assertIn("enable true", c)
        self.assertIn("latency 100", c)
        self.assertIn("pkt-loss-percent 5", c)
        self.assertIn("dampening-multiplier 3", c)
        self.assertIn("maximum-consecutive-pkt-loss 10", c)
        self.assertIn("monitor-interval OAM_MONITOR_INTERVAL_10s", c)

    def test_profile_defaults(self):
        configure_srv6_oam_profile(self.d)
        c = self.d.cfg()
        self.assertIn("oam profile global", c)
        self.assertIn("enable true", c)
        self.assertNotIn("latency", c)
        self.assertNotIn("pkt-loss-percent", c)
        self.assertNotIn("dampening-multiplier", c)
        self.assertNotIn("maximum-consecutive-pkt-loss", c)
        self.assertNotIn("monitor-interval", c)

    def test_profile_disabled(self):
        configure_srv6_oam_profile(self.d, profile_name="p2", enabled=False)
        c = self.d.cfg()
        self.assertIn("oam profile p2", c)
        self.assertIn("enable false", c)

    def test_profile_max_consecutive_pkt_loss_zero(self):
        # max_consecutive_pkt_loss=0 must still be emitted
        # (explicit `is not None` check)
        configure_srv6_oam_profile(
            self.d, profile_name="p3", max_consecutive_pkt_loss=0,
        )
        self.assertIn("maximum-consecutive-pkt-loss 0", self.d.cfg())


class TestUnconfigureSrv6OamProfile(unittest.TestCase):
    """unconfigure_srv6_oam_profile"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_unconfigure_profile_default(self):
        unconfigure_srv6_oam_profile(self.d)
        self.assertIn("no oam profile global", self.d.cfg())

    def test_unconfigure_profile_named(self):
        unconfigure_srv6_oam_profile(self.d, profile_name="p1")
        self.assertIn("no oam profile p1", self.d.cfg())


class TestSrv6OamConfigureSubCommandFailure(unittest.TestCase):
    """Every configure_*/unconfigure_* helper catches SubCommandFailure
    from device.configure() and re-raises a SubCommandFailure wrapping it.
    Table-driven so every function's raise path gets real coverage.
    """

    # (function, args, kwargs)
    CASES = [
        (configure_srv6_oam_profile, (), {"profile_name": "p1"}),
        (unconfigure_srv6_oam_profile, (), {}),
    ]

    def test_subcommandfailure_reraised(self):
        for func, args, kwargs in self.CASES:
            with self.subTest(func=func.__name__):
                device = _CfgDevice()
                device.configure = Mock(side_effect=SubCommandFailure("nope"))
                with self.assertRaises(SubCommandFailure):
                    func(device, *args, **kwargs)


class TestSrv6OamConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in srv6_oam/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(srv6_oam_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == srv6_oam_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested public functions in srv6_oam/configure.py: "
            f"{missing}"
        )

        configure_count = sum(
            1 for n in names if n.startswith("configure_")
        )
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_")
        )
        print(
            f"\nSRv6 OAM configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
