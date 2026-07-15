#!/usr/bin/env python3
"""Unit tests for arcOS BGP configure APIs (representative sample).

Configure helpers build an arcOS CLI config list (starting with the
`network-instance <ni> protocol BGP <pi>` context) and call
`device.configure(config)`. Tests mock `device.configure` and assert the CLI.
The full configure surface follows the same shape.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.bgp.configure import (
    configure_bgp_as_number,
    configure_bgp_router_id,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def last_config(self):
        self.configure.assert_called()
        cfg = self.configure.call_args[0][0]
        return "\n".join(cfg) if isinstance(cfg, (list, tuple)) else str(cfg)


class TestConfigureBgp(unittest.TestCase):
    def setUp(self):
        self.device = _CfgDevice()

    def test_as_number(self):
        configure_bgp_as_number(self.device, 65001)
        cfg = self.device.last_config()
        self.assertIn("network-instance default protocol BGP default", cfg)
        self.assertIn("global as 65001", cfg)

    def test_router_id(self):
        configure_bgp_router_id(self.device, "1.1.1.1")
        self.assertIn("global router-id 1.1.1.1", self.device.last_config())

    def test_as_number_named_instances(self):
        configure_bgp_as_number(
            self.device, 65002, network_instance="red", protocol_instance="bgp1"
        )
        self.assertIn(
            "network-instance red protocol BGP bgp1", self.device.last_config()
        )


if __name__ == "__main__":
    unittest.main()
