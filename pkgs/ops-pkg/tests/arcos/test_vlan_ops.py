"""Unit tests for ArcOS VLAN Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.vlan.arcos.vlan import Vlan

# Module path for patching
MOD = "genie.libs.ops.vlan.arcos.vlan"

# ---------------------------------------------------------------------------
# Sample parser outputs
# ---------------------------------------------------------------------------

VLAN_OUTPUT_BASIC = {
    "vlans": {
        "100": {
            "vlan-id": 100,
            "name": "MGMT",
            "status": "ACTIVE",
            "members": ["swp1", "swp2"],
        },
    }
}

VLAN_OUTPUT_MULTIPLE = {
    "vlans": {
        "100": {
            "vlan-id": 100,
            "name": "MGMT",
            "status": "ACTIVE",
            "members": ["swp1", "swp2"],
        },
        "200": {
            "vlan-id": 200,
            "name": "DATA",
            "status": "ACTIVE",
            "members": ["swp3", "swp4", "swp5"],
        },
        "999": {
            "vlan-id": 999,
            "name": "QUARANTINE",
            "status": "SUSPEND",
        },
    }
}


class TestVlanOps(unittest.TestCase):
    """Test VLAN Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowVlanParser")
    def test_learn_basic(self, mock_vlan):
        """Basic learn with one VLAN."""
        mock_vlan.return_value.parse.return_value = VLAN_OUTPUT_BASIC

        ops = Vlan(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)
        self.assertIn("vlans", ops.info)
        self.assertIn("100", ops.info["vlans"])

        vlan = ops.info["vlans"]["100"]
        self.assertEqual(vlan["vlan_id"], "100")
        self.assertEqual(vlan["name"], "MGMT")
        self.assertEqual(vlan["state"], "active")
        self.assertFalse(vlan["shutdown"])
        self.assertEqual(vlan["interfaces"], ["swp1", "swp2"])

    @patch(f"{MOD}.ShowVlanParser")
    def test_learn_empty(self, mock_vlan):
        """Parser fails -- info should be empty dict."""
        mock_vlan.return_value.parse.side_effect = Exception("No data")

        ops = Vlan(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowVlanParser")
    def test_learn_multiple_vlans(self, mock_vlan):
        """Learn with multiple VLANs including a suspended one."""
        mock_vlan.return_value.parse.return_value = VLAN_OUTPUT_MULTIPLE

        ops = Vlan(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)
        vlans = ops.info["vlans"]
        self.assertEqual(len(vlans), 3)

        # Active VLANs
        self.assertIn("100", vlans)
        self.assertEqual(vlans["100"]["vlan_id"], "100")
        self.assertEqual(vlans["100"]["name"], "MGMT")
        self.assertEqual(vlans["100"]["state"], "active")
        self.assertFalse(vlans["100"]["shutdown"])
        self.assertEqual(vlans["100"]["interfaces"], ["swp1", "swp2"])

        self.assertIn("200", vlans)
        self.assertEqual(vlans["200"]["vlan_id"], "200")
        self.assertEqual(vlans["200"]["name"], "DATA")
        self.assertEqual(vlans["200"]["state"], "active")
        self.assertFalse(vlans["200"]["shutdown"])
        self.assertEqual(vlans["200"]["interfaces"], ["swp3", "swp4", "swp5"])

        # Suspended VLAN
        self.assertIn("999", vlans)
        self.assertEqual(vlans["999"]["vlan_id"], "999")
        self.assertEqual(vlans["999"]["name"], "QUARANTINE")
        self.assertEqual(vlans["999"]["state"], "suspend")
        self.assertTrue(vlans["999"]["shutdown"])
        # No members for suspended VLAN
        self.assertNotIn("interfaces", vlans["999"])


if __name__ == "__main__":
    unittest.main()
