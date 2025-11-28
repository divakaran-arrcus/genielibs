#!/usr/bin/env python

import unittest

from genie.conf import Genie
from genie.conf.base import Testbed, Device

# Ensure ArcOS SegmentRouting plugin is registered
import genie.libs.conf.segment_routing.arcos  # noqa: F401

from genie.libs.conf.segment_routing import SegmentRouting


class TestArcosSegmentRouting(unittest.TestCase):
    """Unit tests for ArcOS SegmentRouting configuration."""

    def setUp(self):
        # Initialize the Genie testbed
        testbed = Testbed()
        Genie.testbed = testbed

        # Create a device with OS 'arcos'
        self.dev = Device(name="rtr1", testbed=testbed, os="arcos")
        # Provide a default network-instance name via custom data
        self.dev.custom = {"instance_name": "default"}

        # Initialize SegmentRouting and add it to the device
        self.sr = SegmentRouting()
        self.dev.add_feature(self.sr)

    def test_srv6_basic_config(self):
        """Verify basic SRv6 locator configuration for ArcOS."""
        dev_attr = self.sr.device_attr[self.dev]

        dev_attr.srv6_encap_source_address = "2400:2020:0:1191::91"
        dev_attr.srv6_locators = {
            "base_slice0": {
                "locator_node_length": 24,
                "prefix": "2400:2020:0:1191::/64",
                "function_length": 16,
            },
            "base_slice131": {
                "locator_node_length": 24,
                "prefix": "2400:2020:31:1191::/64",
                "function_length": 16,
                "algorithm": 131,
            },
            "base_slice132": {
                "locator_node_length": 24,
                "prefix": "2400:2020:32:1191::/64",
                "function_length": 16,
                "algorithm": 132,
            },
        }

        cfgs = self.sr.build_config(apply=False)
        cfg = cfgs.get(self.dev.name, cfgs)
        cfg_str = str(cfg)

        self.assertIn("network-instance default", cfg_str)
        self.assertIn(
            "srv6 encapsulation source-address 2400:2020:0:1191::91",
            cfg_str,
        )
        self.assertIn("srv6 locator base_slice0", cfg_str)
        self.assertIn("srv6 locator base_slice131", cfg_str)
        self.assertIn("srv6 locator base_slice132", cfg_str)
        self.assertIn("locator-node-length 24", cfg_str)
        self.assertIn("prefix 2400:2020:0:1191::/64", cfg_str)
        self.assertIn("function-length 16", cfg_str)
        self.assertIn("algorithm 131", cfg_str)
        self.assertIn("algorithm 132", cfg_str)

    def test_srv6_unconfig(self):
        """Verify SRv6 unconfiguration for ArcOS."""
        dev_attr = self.sr.device_attr[self.dev]
        dev_attr.srv6_encap_source_address = "2400:2020:0:1191::91"
        dev_attr.srv6_locators = {
            "base_slice0": {
                "locator_node_length": 24,
                "prefix": "2400:2020:0:1191::/64",
                "function_length": 16,
            }
        }

        cfgs = self.sr.build_unconfig(apply=False)
        cfg = cfgs.get(self.dev.name, cfgs)
        cfg_str = str(cfg)

        # Expect a single unconfig line targeting the SRv6 stanza under the NI
        self.assertIn("no network-instance default srv6", cfg_str)


if __name__ == "__main__":
    unittest.main()
