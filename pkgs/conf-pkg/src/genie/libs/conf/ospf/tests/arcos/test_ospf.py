#!/usr/bin/env python3
"""Unit tests for the native Genie ArcOS OSPF config plugin."""

import unittest
from unittest.mock import Mock

from genie.conf import Genie
from genie.conf.base import Testbed, Device
from genie.libs.conf.ospf import Ospf


class TestNativeArcosOspf(unittest.TestCase):
    def setUp(self):
        testbed = Genie.testbed = Testbed()
        self.device = Device(testbed=testbed, name="rtr1", os="arcos", type="router")
        self.device.custom = {"instance_name": "default"}
        self.device.configure = Mock(return_value=True)

    def test_global_router_id_and_ecmp(self):
        ospf = Ospf(pid="default")
        da = ospf.device_attr[self.device]
        da.router_id = "1.1.1.1"
        da.max_ecmp_paths = 8

        cfgs = ospf.build_config(devices=[self.device], apply=False)
        self.assertIn("rtr1", cfgs)
        cfg = str(cfgs["rtr1"])
        self.assertIn("protocol OSPF default", cfg)
        self.assertIn("global router-id 1.1.1.1", cfg)
        self.assertIn("global max-ecmp-paths 8", cfg)


if __name__ == "__main__":
    unittest.main()
