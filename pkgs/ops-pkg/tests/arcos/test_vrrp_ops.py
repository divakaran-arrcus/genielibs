"""Unit tests for ArcOS VRRP Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.vrrp.arcos.vrrp import Vrrp

MOD = "genie.libs.ops.vrrp.arcos.vrrp"

BASIC_OUTPUT = {
    "vrrp-groups": {
        "ethernet-1/1:0:ipv4:10.1.1.1:1": {
            "interface": "ethernet-1/1",
            "sub-id": 0,
            "af": "ipv4",
            "address": "10.1.1.1",
            "virtual-router-id": 1,
            "virtual-address": ["10.1.1.254"],
            "priority": 200,
            "current-priority": 200,
            "preempt": True,
            "accept-mode": True,
            "advertisement-interval": 1,
            "vrrp-version": "VRRP_V3",
            "virtual-router-mode": "MASTER",
            "virtual-mac-address": "00:00:5e:00:01:01",
            "advertisement-sent": "1234",
            "advertisement-received": "0",
            "advertisement-dropped": "0",
        }
    }
}

MULTIPLE_GROUPS_OUTPUT = {
    "vrrp-groups": {
        "ethernet-1/1:0:ipv4:10.1.1.1:1": {
            "interface": "ethernet-1/1",
            "sub-id": 0,
            "af": "ipv4",
            "address": "10.1.1.1",
            "virtual-router-id": 1,
            "virtual-address": ["10.1.1.254"],
            "priority": 200,
            "preempt": True,
            "virtual-router-mode": "MASTER",
            "vrrp-version": "VRRP_V3",
            "advertisement-interval": 1,
        },
        "ethernet-1/2:0:ipv4:10.2.2.1:2": {
            "interface": "ethernet-1/2",
            "sub-id": 0,
            "af": "ipv4",
            "address": "10.2.2.1",
            "virtual-router-id": 2,
            "virtual-address": ["10.2.2.254"],
            "priority": 100,
            "preempt": False,
            "virtual-router-mode": "BACKUP",
            "vrrp-version": "VRRP_V3",
            "advertisement-interval": 3,
        },
        "ethernet-1/3:10:ipv6:2001:db8::1:3": {
            "interface": "ethernet-1/3",
            "sub-id": 10,
            "af": "ipv6",
            "address": "2001:db8::1",
            "virtual-router-id": 3,
            "virtual-address": ["2001:db8::ffff"],
            "priority": 150,
            "preempt": True,
            "virtual-router-mode": "MASTER",
            "vrrp-version": "VRRP_V3",
            "advertisement-interval": 1,
        },
    }
}


class TestVrrpOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowVrrp")
    def test_learn_basic(self, mock_parser):
        """Test learn() with a single VRRP group."""
        mock_parser.return_value.parse.return_value = BASIC_OUTPUT

        ops = Vrrp(device=self.device)
        ops.learn()

        self.assertIn("vrrp_groups", ops.info)
        groups = ops.info["vrrp_groups"]
        self.assertEqual(len(groups), 1)

        key = "ethernet-1/1:0:ipv4:10.1.1.1:1"
        self.assertIn(key, groups)

        grp = groups[key]
        self.assertEqual(grp["interface"], "ethernet-1/1")
        self.assertEqual(grp["sub_id"], 0)
        self.assertEqual(grp["group_id"], 1)
        self.assertEqual(grp["address_family"], "ipv4")
        self.assertEqual(grp["address"], "10.1.1.1")
        self.assertEqual(grp["virtual_addresses"], ["10.1.1.254"])
        self.assertEqual(grp["priority"], 200)
        self.assertTrue(grp["preempt"])
        self.assertTrue(grp["accept_mode"])
        self.assertEqual(grp["state"], "MASTER")
        self.assertEqual(grp["advertisement_interval"], 1)
        self.assertEqual(grp["version"], "VRRP_V3")
        self.assertEqual(grp["virtual_mac_address"], "00:00:5e:00:01:01")

    @patch(f"{MOD}.ShowVrrp")
    def test_learn_empty(self, mock_parser):
        """Parser fails -- info should be empty."""
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = Vrrp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowVrrp")
    def test_learn_multiple_groups(self, mock_parser):
        """Test learn() with multiple VRRP groups across interfaces and AFs."""
        mock_parser.return_value.parse.return_value = MULTIPLE_GROUPS_OUTPUT

        ops = Vrrp(device=self.device)
        ops.learn()

        self.assertIn("vrrp_groups", ops.info)
        groups = ops.info["vrrp_groups"]
        self.assertEqual(len(groups), 3)

        # First group - MASTER
        g1 = groups["ethernet-1/1:0:ipv4:10.1.1.1:1"]
        self.assertEqual(g1["interface"], "ethernet-1/1")
        self.assertEqual(g1["group_id"], 1)
        self.assertEqual(g1["state"], "MASTER")
        self.assertEqual(g1["priority"], 200)
        self.assertTrue(g1["preempt"])

        # Second group - BACKUP
        g2 = groups["ethernet-1/2:0:ipv4:10.2.2.1:2"]
        self.assertEqual(g2["interface"], "ethernet-1/2")
        self.assertEqual(g2["group_id"], 2)
        self.assertEqual(g2["state"], "BACKUP")
        self.assertEqual(g2["priority"], 100)
        self.assertFalse(g2["preempt"])
        self.assertEqual(g2["advertisement_interval"], 3)

        # Third group - IPv6
        g3 = groups["ethernet-1/3:10:ipv6:2001:db8::1:3"]
        self.assertEqual(g3["interface"], "ethernet-1/3")
        self.assertEqual(g3["sub_id"], 10)
        self.assertEqual(g3["address_family"], "ipv6")
        self.assertEqual(g3["group_id"], 3)
        self.assertEqual(g3["virtual_addresses"], ["2001:db8::ffff"])

    @patch(f"{MOD}.ShowVrrp")
    def test_learn_minimal_group_fields(self, mock_parser):
        """Group data with only the mandatory virtual-router-id field --
        exercises every optional-field 'is not None' False branch in a
        single pass."""
        minimal_output = {
            "vrrp-groups": {
                "swp5:0:ipv4:10.5.5.5:5": {
                    "virtual-router-id": 5,
                }
            }
        }
        mock_parser.return_value.parse.return_value = minimal_output

        ops = Vrrp(device=self.device)
        ops.learn()

        self.assertIn("vrrp_groups", ops.info)
        groups = ops.info["vrrp_groups"]
        key = "swp5:0:ipv4:10.5.5.5:5"
        self.assertIn(key, groups)
        # Only group_id should be populated; every optional field absent.
        self.assertEqual(groups[key], {"group_id": 5})

    @patch(f"{MOD}.ShowVrrp")
    def test_learn_explicit_single_af_and_filters(self, mock_parser):
        """When af is explicitly given, only that AF is queried once (not
        both ipv4 and ipv6), and interface/sub_id/address are passed
        through instead of wildcards."""
        mock_parser.return_value.parse.return_value = BASIC_OUTPUT

        ops = Vrrp(device=self.device)
        ops.learn(
            interface="swp1", sub_id=5, af="ipv6", address="10.1.1.5",
        )

        mock_parser.return_value.parse.assert_called_once_with(
            interface="swp1", sub_id=5, af="ipv6", address="10.1.1.5",
        )
        self.assertIn("vrrp_groups", ops.info)


if __name__ == "__main__":
    unittest.main()
