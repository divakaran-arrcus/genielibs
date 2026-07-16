#!/usr/bin/env python3
"""Unit tests for the native Genie ArcOS Interface config plugin.

The arcOS interface conf is dispatched through the genie Interface *factory*, so
the arcOS plugin module must be imported first to register it (as the project's
AEtest does). With that import, build_config(apply=False) generates arcOS CLI
without a live device.
"""

import unittest
from unittest.mock import Mock

from genie.conf import Genie
from genie.conf.base import Testbed, Device
import genie.libs.conf.interface.arcos  # noqa: F401  register ArcOS interface plugin
from genie.libs.conf.interface import Interface


class TestNativeArcosInterface(unittest.TestCase):
    def setUp(self):
        testbed = Genie.testbed = Testbed()
        self.device = Device(testbed=testbed, name="rtr1", os="arcos", type="router")
        self.device.custom = {"instance_name": "default"}
        self.device.configure = Mock(return_value=True)

    def test_physical_mtu_and_description(self):
        intf = Interface(device=self.device, name="swp1")
        intf.mtu = 9000
        intf.description = "Uplink to spine"
        cfg = str(intf.build_config(apply=False))
        self.assertIn("interface swp1", cfg)
        self.assertIn("type    ethernetCsmacd", cfg)  # physical swp
        self.assertIn("mtu 9000", cfg)
        self.assertIn("Uplink to spine", cfg)

    def test_loopback_type(self):
        intf = Interface(device=self.device, name="loopback1")
        intf.description = "lo"
        cfg = str(intf.build_config(apply=False))
        self.assertIn("interface loopback1", cfg)
        self.assertIn("type    softwareLoopback", cfg)


if __name__ == "__main__":
    unittest.main()
