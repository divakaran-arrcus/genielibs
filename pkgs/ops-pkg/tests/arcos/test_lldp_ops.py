"""Unit tests for ArcOS LLDP Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.lldp.arcos.lldp import Lldp

# Module path for patching
MOD = "genie.libs.ops.lldp.arcos.lldp"

# ---------------------------------------------------------------------------
# Sample parser outputs
# ---------------------------------------------------------------------------

STATE_OUTPUT = {
    "hello-timer": "30",
    "system-name": "rtr1",
    "system-description": "Arrcus ArcOS 5.2.0",
    "counters": {
        "frame-in": "1024",
        "frame-out": "980",
        "frame-error-in": "2",
        "frame-discard": "0",
        "tlv-discard": "1",
        "tlv-unknown": "3",
    },
}

INTERFACE_OUTPUT = {
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "mode": "BOTH",
            "counters": {
                "frame-in": "512",
                "frame-out": "490",
            },
            "neighbors": {
                "nbr1": {
                    "id": "nbr1",
                    "system-name": "rtr2",
                    "system-description": "Arrcus ArcOS 5.2.0",
                    "chassis-id": "00:11:22:33:44:55",
                    "port-id": "swp2",
                    "port-description": "Uplink to rtr1",
                    "management-address": "10.0.0.2",
                    "capabilities": {
                        "ROUTER": {
                            "name": "ROUTER",
                            "enabled": True,
                        },
                        "BRIDGE": {
                            "name": "BRIDGE",
                            "enabled": False,
                        },
                    },
                },
            },
        },
        "swp3": {
            "name": "swp3",
            "enabled": True,
            "mode": "BOTH",
            "neighbors": {
                "nbr2": {
                    "id": "nbr2",
                    "system-name": "rtr3",
                    "chassis-id": "aa:bb:cc:dd:ee:ff",
                    "port-id": "swp1",
                    "management-address": "10.0.0.3",
                },
            },
        },
    }
}

INTERFACE_OUTPUT_NO_NEIGHBORS = {
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "mode": "BOTH",
        },
        "swp2": {
            "name": "swp2",
            "enabled": False,
        },
    }
}


class TestLldpOps(unittest.TestCase):
    """Test LLDP Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowLldpInterface")
    @patch(f"{MOD}.ShowLldpState")
    def test_learn_basic(self, mock_state, mock_intf):
        """Full learn with global state, interfaces, and neighbors."""
        mock_state.return_value.parse.return_value = STATE_OUTPUT
        mock_intf.return_value.parse.return_value = INTERFACE_OUTPUT

        ops = Lldp(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)

        # Global state
        self.assertTrue(ops.info["enabled"])
        self.assertEqual(ops.info["hello_timer"], 30)
        self.assertEqual(ops.info["system_name"], "rtr1")
        self.assertEqual(ops.info["system_description"], "Arrcus ArcOS 5.2.0")

        # Global counters
        counters = ops.info["counters"]
        self.assertEqual(counters["frame_in"], 1024)
        self.assertEqual(counters["frame_out"], 980)
        self.assertEqual(counters["frame_error_in"], 2)
        self.assertEqual(counters["frame_discard"], 0)
        self.assertEqual(counters["tlv_discard"], 1)
        self.assertEqual(counters["tlv_unknown"], 3)

        # Interfaces
        self.assertIn("swp1", ops.info["interfaces"])
        self.assertIn("swp3", ops.info["interfaces"])

        swp1 = ops.info["interfaces"]["swp1"]
        self.assertEqual(swp1["if_name"], "swp1")
        self.assertTrue(swp1["enabled"])

        # Neighbor under swp1 -> port_id -> neighbors
        self.assertIn("port_id", swp1)
        self.assertIn("swp2", swp1["port_id"])
        nbr = swp1["port_id"]["swp2"]["neighbors"]["nbr1"]
        self.assertEqual(nbr["neighbor_id"], "nbr1")
        self.assertEqual(nbr["system_name"], "rtr2")
        self.assertEqual(nbr["chassis_id"], "00:11:22:33:44:55")
        self.assertEqual(nbr["port_id"], "swp2")
        self.assertEqual(nbr["port_description"], "Uplink to rtr1")
        self.assertEqual(nbr["management_address"], "10.0.0.2")

        # Capabilities
        caps = nbr["capabilities"]
        self.assertIn("ROUTER", caps)
        self.assertTrue(caps["ROUTER"]["enabled"])
        self.assertIn("BRIDGE", caps)
        self.assertFalse(caps["BRIDGE"]["enabled"])

        # Second interface (swp3)
        swp3 = ops.info["interfaces"]["swp3"]
        self.assertEqual(swp3["if_name"], "swp3")
        nbr2 = swp3["port_id"]["swp1"]["neighbors"]["nbr2"]
        self.assertEqual(nbr2["system_name"], "rtr3")
        self.assertEqual(nbr2["management_address"], "10.0.0.3")

    @patch(f"{MOD}.ShowLldpInterface")
    @patch(f"{MOD}.ShowLldpState")
    def test_learn_empty(self, mock_state, mock_intf):
        """All parsers fail -- info should be empty dict."""
        mock_state.return_value.parse.side_effect = Exception("No data")
        mock_intf.return_value.parse.side_effect = Exception("No data")

        ops = Lldp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowLldpInterface")
    @patch(f"{MOD}.ShowLldpState")
    def test_learn_no_neighbors(self, mock_state, mock_intf):
        """State present but interfaces have no neighbors."""
        mock_state.return_value.parse.return_value = STATE_OUTPUT
        mock_intf.return_value.parse.return_value = INTERFACE_OUTPUT_NO_NEIGHBORS

        ops = Lldp(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)

        # Global state is populated
        self.assertTrue(ops.info["enabled"])
        self.assertEqual(ops.info["hello_timer"], 30)

        # Interfaces exist but have no port_id (no neighbors)
        self.assertIn("swp1", ops.info["interfaces"])
        self.assertIn("swp2", ops.info["interfaces"])

        swp1 = ops.info["interfaces"]["swp1"]
        self.assertEqual(swp1["if_name"], "swp1")
        self.assertTrue(swp1["enabled"])
        self.assertNotIn("port_id", swp1)

        swp2 = ops.info["interfaces"]["swp2"]
        self.assertFalse(swp2["enabled"])
        self.assertNotIn("port_id", swp2)


if __name__ == "__main__":
    unittest.main()
