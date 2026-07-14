#!/usr/bin/env python3
"""Unit tests for arcOS ISIS configure APIs (representative sample).

Configure helpers build an arcOS CLI config list (starting with the
`network-instance <ni> protocol ISIS <pi>` context) and call
`device.configure(config)`. Tests mock `device.configure`, invoke the helper,
and assert the emitted CLI + input validation. Covers the common patterns
(global knob, per-interface/per-level knob, range validation); the full 165
configure functions follow the same shape.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.isis.configure import (
    configure_isis_net_address,
    configure_isis_max_ecmp_paths,
    configure_isis_interface_metric,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def last_config(self):
        self.configure.assert_called()
        cfg = self.configure.call_args[0][0]
        return "\n".join(cfg) if isinstance(cfg, (list, tuple)) else str(cfg)


class TestConfigureIsis(unittest.TestCase):
    def setUp(self):
        self.device = _CfgDevice()

    def test_net_address(self):
        configure_isis_net_address(self.device, "49.0001.1921.6800.1001.00")
        cfg = self.device.last_config()
        self.assertIn("network-instance default protocol ISIS default", cfg)
        self.assertIn("global net [ 49.0001.1921.6800.1001.00 ]", cfg)

    def test_net_address_named_instances(self):
        configure_isis_net_address(
            self.device, "49.0001.0000.0000.0002.00",
            network_instance="red", protocol_instance="isis1",
        )
        self.assertIn(
            "network-instance red protocol ISIS isis1", self.device.last_config()
        )

    def test_max_ecmp_paths(self):
        configure_isis_max_ecmp_paths(self.device, 8)
        self.assertIn("global max-ecmp-paths 8", self.device.last_config())

    def test_max_ecmp_paths_out_of_range(self):
        with self.assertRaises(ValueError):
            configure_isis_max_ecmp_paths(self.device, 99)
        self.device.configure.assert_not_called()

    def test_interface_metric(self):
        configure_isis_interface_metric(
            self.device, interface="swp1", metric=10, level="level_2"
        )
        cfg = self.device.last_config()
        self.assertIn("metric 10", cfg)
        self.assertIn("level 2", cfg)

    def test_interface_metric_bad_level(self):
        with self.assertRaises(ValueError):
            configure_isis_interface_metric(
                self.device, interface="swp1", metric=10, level="bogus"
            )
        self.device.configure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
