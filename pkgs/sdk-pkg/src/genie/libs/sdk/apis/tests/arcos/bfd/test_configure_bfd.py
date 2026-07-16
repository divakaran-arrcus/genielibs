#!/usr/bin/env python3
"""Unit tests for arcOS BFD configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.bfd.configure builds an arcOS CLI config list
(typically starting with the `bfd profile <name>` or
`bfd single-hop interface <name>` context) and calls device.configure(config).
Tests mock device.configure and assert on a distinctive substring of the
emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.bfd import configure as bfd_configure
from genie.libs.sdk.apis.arcos.bfd.configure import (
    configure_bfd_profile,
    unconfigure_bfd_profile,
    configure_bfd_profile_tx_interval,
    unconfigure_bfd_profile_tx_interval,
    configure_bfd_profile_rx_interval,
    unconfigure_bfd_profile_rx_interval,
    configure_bfd_profile_detection_multiplier,
    unconfigure_bfd_profile_detection_multiplier,
    configure_bfd_profile_enabled,
    unconfigure_bfd_profile_enabled,
    configure_bfd_profile_hw_offload,
    unconfigure_bfd_profile_hw_offload,
    configure_bfd_profile_dscp,
    unconfigure_bfd_profile_dscp,
    configure_bfd_single_hop_interface,
    unconfigure_bfd_single_hop_interface,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureBfdProfile(unittest.TestCase):
    """configure_bfd_profile / unconfigure_bfd_profile"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_profile_all_params(self):
        configure_bfd_profile(
            self.d, "fast", enabled=True, tx_interval=300, rx_interval=300,
            detection_multiplier=3, dscp_value=48, v4_hw_offload=True,
            v6_hw_offload=False,
        )
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("enabled true", c)
        self.assertIn("desired-minimum-tx-interval 300", c)
        self.assertIn("required-minimum-receive 300", c)
        self.assertIn("detection-multiplier 3", c)
        self.assertIn("dscp-value 48", c)
        self.assertIn("v4-hw-offload true", c)
        self.assertIn("v6-hw-offload false", c)

    def test_profile_minimal(self):
        configure_bfd_profile(self.d, "minimal")
        c = self.d.cfg()
        self.assertIn("bfd profile minimal", c)
        self.assertNotIn("enabled", c)
        self.assertNotIn("desired-minimum-tx-interval", c)

    def test_unconfigure_profile(self):
        unconfigure_bfd_profile(self.d, "fast")
        self.assertIn("no bfd profile fast", self.d.cfg())


class TestConfigureBfdProfileTxInterval(unittest.TestCase):
    """configure_bfd_profile_tx_interval / unconfigure_bfd_profile_tx_interval"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_tx_interval(self):
        configure_bfd_profile_tx_interval(self.d, "fast", 300)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("desired-minimum-tx-interval 300", c)

    def test_unconfigure_tx_interval(self):
        unconfigure_bfd_profile_tx_interval(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no desired-minimum-tx-interval", c)


class TestConfigureBfdProfileRxInterval(unittest.TestCase):
    """configure_bfd_profile_rx_interval / unconfigure_bfd_profile_rx_interval"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_rx_interval(self):
        configure_bfd_profile_rx_interval(self.d, "fast", 300)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("required-minimum-receive 300", c)

    def test_unconfigure_rx_interval(self):
        unconfigure_bfd_profile_rx_interval(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no required-minimum-receive", c)


class TestConfigureBfdProfileDetectionMultiplier(unittest.TestCase):
    """configure_bfd_profile_detection_multiplier /
    unconfigure_bfd_profile_detection_multiplier"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_detection_multiplier(self):
        configure_bfd_profile_detection_multiplier(self.d, "fast", 3)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("detection-multiplier 3", c)

    def test_unconfigure_detection_multiplier(self):
        unconfigure_bfd_profile_detection_multiplier(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no detection-multiplier", c)


class TestConfigureBfdProfileEnabled(unittest.TestCase):
    """configure_bfd_profile_enabled / unconfigure_bfd_profile_enabled"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_enabled_true(self):
        configure_bfd_profile_enabled(self.d, "fast", enabled=True)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("enabled true", c)

    def test_enabled_default_true(self):
        configure_bfd_profile_enabled(self.d, "fast")
        self.assertIn("enabled true", self.d.cfg())

    def test_enabled_false(self):
        configure_bfd_profile_enabled(self.d, "fast", enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_unconfigure_enabled(self):
        unconfigure_bfd_profile_enabled(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no enabled", c)


class TestConfigureBfdProfileHwOffload(unittest.TestCase):
    """configure_bfd_profile_hw_offload / unconfigure_bfd_profile_hw_offload"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_hw_offload_both(self):
        configure_bfd_profile_hw_offload(self.d, "fast", v4=True, v6=True)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("v4-hw-offload true", c)
        self.assertIn("v6-hw-offload true", c)

    def test_hw_offload_v4_only(self):
        configure_bfd_profile_hw_offload(self.d, "fast", v4=False)
        c = self.d.cfg()
        self.assertIn("v4-hw-offload false", c)
        self.assertNotIn("v6-hw-offload", c)

    def test_unconfigure_hw_offload_both(self):
        unconfigure_bfd_profile_hw_offload(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no v4-hw-offload", c)
        self.assertIn("no v6-hw-offload", c)

    def test_unconfigure_hw_offload_v6_only(self):
        unconfigure_bfd_profile_hw_offload(self.d, "fast", v4=False, v6=True)
        c = self.d.cfg()
        self.assertNotIn("no v4-hw-offload", c)
        self.assertIn("no v6-hw-offload", c)


class TestConfigureBfdProfileDscp(unittest.TestCase):
    """configure_bfd_profile_dscp / unconfigure_bfd_profile_dscp"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_dscp(self):
        configure_bfd_profile_dscp(self.d, "fast", 48)
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("dscp-value 48", c)

    def test_unconfigure_dscp(self):
        unconfigure_bfd_profile_dscp(self.d, "fast")
        c = self.d.cfg()
        self.assertIn("bfd profile fast", c)
        self.assertIn("no dscp-value", c)


class TestConfigureBfdSingleHopInterface(unittest.TestCase):
    """configure_bfd_single_hop_interface / unconfigure_bfd_single_hop_interface"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_single_hop_all_params(self):
        configure_bfd_single_hop_interface(
            self.d, "ethernet-1/1", tx_interval=300, rx_interval=300,
            detection_multiplier=3,
        )
        c = self.d.cfg()
        self.assertIn("bfd single-hop interface ethernet-1/1", c)
        self.assertIn("desired-minimum-tx-interval 300", c)
        self.assertIn("required-minimum-receive 300", c)
        self.assertIn("detection-multiplier 3", c)

    def test_single_hop_minimal(self):
        configure_bfd_single_hop_interface(self.d, "ethernet-1/1")
        c = self.d.cfg()
        self.assertIn("bfd single-hop interface ethernet-1/1", c)
        self.assertNotIn("desired-minimum-tx-interval", c)

    def test_unconfigure_single_hop(self):
        unconfigure_bfd_single_hop_interface(self.d, "ethernet-1/1")
        self.assertIn("no bfd single-hop interface ethernet-1/1", self.d.cfg())


class TestBfdConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in bfd/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(bfd_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == bfd_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered BFD configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nBFD configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
