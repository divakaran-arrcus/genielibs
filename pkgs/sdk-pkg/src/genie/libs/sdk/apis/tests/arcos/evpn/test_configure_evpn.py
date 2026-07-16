#!/usr/bin/env python3
"""Unit tests for arcOS EVPN configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.evpn.configure builds a small ``evpn ...`` CLI
config list and calls ``device.configure(config)``. Tests mock
``device.configure`` and assert on a distinctive substring of the emitted
CLI. SubCommandFailure re-raise paths are also exercised.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.evpn import configure as evpn_configure
from genie.libs.sdk.apis.arcos.evpn.configure import (
    configure_evpn_anycast_gateway_mac,
    unconfigure_evpn_anycast_gateway_mac,
    configure_evpn_df_election_time,
    unconfigure_evpn_df_election_time,
    configure_evpn_duplicate_mac_detection,
    unconfigure_evpn_duplicate_mac_detection,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class _FailingDevice:
    """Device whose configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureEvpnAnycastGatewayMac(unittest.TestCase):
    """configure_evpn_anycast_gateway_mac / unconfigure_evpn_anycast_gateway_mac"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure(self):
        configure_evpn_anycast_gateway_mac(self.d, "aa:bb:cc:01:02:03")
        self.assertIn(
            "evpn anycast-gateway-mac aa:bb:cc:01:02:03", self.d.cfg()
        )

    def test_configure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_evpn_anycast_gateway_mac(failing, "aa:bb:cc:01:02:03")

    def test_unconfigure(self):
        unconfigure_evpn_anycast_gateway_mac(self.d)
        self.assertIn("no evpn anycast-gateway-mac", self.d.cfg())

    def test_unconfigure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_evpn_anycast_gateway_mac(failing)


class TestConfigureEvpnDfElectionTime(unittest.TestCase):
    """configure_evpn_df_election_time / unconfigure_evpn_df_election_time"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure(self):
        configure_evpn_df_election_time(self.d, 15)
        self.assertIn("evpn df-election-time 15", self.d.cfg())

    def test_configure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_evpn_df_election_time(failing, 15)

    def test_unconfigure(self):
        unconfigure_evpn_df_election_time(self.d)
        self.assertIn("no evpn df-election-time", self.d.cfg())

    def test_unconfigure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_evpn_df_election_time(failing)


class TestConfigureEvpnDuplicateMacDetection(unittest.TestCase):
    """configure_evpn_duplicate_mac_detection / unconfigure_evpn_duplicate_mac_detection"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_window_only(self):
        configure_evpn_duplicate_mac_detection(self.d, window=60)
        c = self.d.cfg()
        self.assertIn("evpn duplicate-mac-detection window 60", c)
        self.assertNotIn("threshold", c)
        self.assertNotIn("auto-recovery-time", c)

    def test_threshold_only(self):
        configure_evpn_duplicate_mac_detection(self.d, threshold=7)
        c = self.d.cfg()
        self.assertIn("evpn duplicate-mac-detection threshold 7", c)
        self.assertNotIn("window", c)

    def test_auto_recovery_time_only(self):
        configure_evpn_duplicate_mac_detection(self.d, auto_recovery_time=5)
        c = self.d.cfg()
        self.assertIn(
            "evpn duplicate-mac-detection auto-recovery-time 5", c
        )

    def test_all_params(self):
        configure_evpn_duplicate_mac_detection(
            self.d, window=180, threshold=5, auto_recovery_time=0
        )
        c = self.d.cfg()
        self.assertIn("evpn duplicate-mac-detection window 180", c)
        self.assertIn("evpn duplicate-mac-detection threshold 5", c)
        self.assertIn(
            "evpn duplicate-mac-detection auto-recovery-time 0", c
        )

    def test_no_params_does_not_call_configure(self):
        configure_evpn_duplicate_mac_detection(self.d)
        self.d.configure.assert_not_called()

    def test_configure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_evpn_duplicate_mac_detection(failing, window=60)

    def test_unconfigure(self):
        unconfigure_evpn_duplicate_mac_detection(self.d)
        c = self.d.cfg()
        self.assertIn("no evpn duplicate-mac-detection window", c)
        self.assertIn("no evpn duplicate-mac-detection threshold", c)
        self.assertIn(
            "no evpn duplicate-mac-detection auto-recovery-time", c
        )

    def test_unconfigure_raises_on_failure(self):
        failing = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_evpn_duplicate_mac_detection(failing)


class TestEvpnConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in evpn/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(evpn_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == evpn_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered EVPN configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nEVPN configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
