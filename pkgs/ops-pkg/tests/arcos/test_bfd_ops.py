"""Unit tests for ArcOS BFD Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.bfd.arcos.bfd import Bfd

MOD = "genie.libs.ops.bfd.arcos.bfd"

BASIC_OUTPUT = {
    "profile": {
        "GLOBAL-150m": {
            "id": "GLOBAL-150m",
            "enabled": True,
            "desired-minimum-tx-interval": 150000,
            "required-minimum-receive": 150000,
            "detection-multiplier": 3,
            "v4-hw-offload": True,
            "v6-hw-offload": False,
            "dscp-value": 48,
            "peers": {
                "20": {
                    "local-address": "10.1.1.1",
                    "remote-address": "10.1.1.2",
                    "subscribed-protocols": ["ISIS", "BGP"],
                    "session-state": "UP",
                    "remote-session-state": "UP",
                    "local-discriminator": 20,
                    "remote-discriminator": 30,
                    "interface": "ethernet-1/1",
                    "network-instance": "default",
                    "negotiated-tx-interval": 150000,
                    "negotiated-rx-interval": 150000,
                    "session-type": "MICRO_BFD",
                    "hw-offload-status": True,
                },
                "21": {
                    "local-address": "10.1.2.1",
                    "remote-address": "10.1.2.2",
                    "subscribed-protocols": ["ISIS"],
                    "session-state": "DOWN",
                    "remote-session-state": "DOWN",
                    "local-discriminator": 21,
                    "remote-discriminator": 0,
                    "interface": "ethernet-1/2",
                    "network-instance": "default",
                    "negotiated-tx-interval": 300000,
                    "negotiated-rx-interval": 300000,
                    "session-type": "SINGLE_HOP",
                    "hw-offload-status": False,
                },
            },
        }
    }
}

PROFILE_ONLY_OUTPUT = {
    "profile": {
        "BFD-SLOW": {
            "id": "BFD-SLOW",
            "enabled": True,
            "desired-minimum-tx-interval": 1000000,
            "required-minimum-receive": 1000000,
            "detection-multiplier": 5,
        }
    }
}


class TestBfdOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowBfd")
    def test_learn_basic_with_peers(self, mock_parser):
        """Test learn() with a profile containing two peer sessions."""
        mock_parser.return_value.parse.return_value = BASIC_OUTPUT

        ops = Bfd(device=self.device)
        ops.learn()

        self.assertIn("profiles", ops.info)
        profiles = ops.info["profiles"]
        self.assertIn("GLOBAL-150m", profiles)

        profile = profiles["GLOBAL-150m"]
        self.assertEqual(profile["id"], "GLOBAL-150m")
        self.assertTrue(profile["enabled"])
        self.assertEqual(profile["desired_minimum_tx_interval"], 150000)
        self.assertEqual(profile["required_minimum_receive"], 150000)
        self.assertEqual(profile["detection_multiplier"], 3)
        self.assertTrue(profile["v4_hw_offload"])
        self.assertFalse(profile["v6_hw_offload"])
        self.assertEqual(profile["dscp_value"], 48)

        # Sessions
        self.assertIn("sessions", profile)
        sessions = profile["sessions"]
        self.assertEqual(len(sessions), 2)

        s20 = sessions["20"]
        self.assertEqual(s20["local_address"], "10.1.1.1")
        self.assertEqual(s20["remote_address"], "10.1.1.2")
        self.assertEqual(s20["session_state"], "UP")
        self.assertEqual(s20["remote_session_state"], "UP")
        self.assertEqual(s20["local_discriminator"], 20)
        self.assertEqual(s20["remote_discriminator"], 30)
        self.assertEqual(s20["interface"], "ethernet-1/1")
        self.assertEqual(s20["network_instance"], "default")
        self.assertEqual(s20["subscribed_protocols"], ["ISIS", "BGP"])
        self.assertEqual(s20["negotiated_tx_interval"], 150000)
        self.assertEqual(s20["negotiated_rx_interval"], 150000)
        self.assertEqual(s20["session_type"], "MICRO_BFD")
        self.assertTrue(s20["hw_offload_status"])

        s21 = sessions["21"]
        self.assertEqual(s21["session_state"], "DOWN")
        self.assertEqual(s21["interface"], "ethernet-1/2")
        self.assertFalse(s21["hw_offload_status"])

    @patch(f"{MOD}.ShowBfd")
    def test_learn_empty(self, mock_parser):
        """Parser fails -- info should be empty."""
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = Bfd(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowBfd")
    def test_learn_profile_only(self, mock_parser):
        """Profile exists but has no peer sessions."""
        mock_parser.return_value.parse.return_value = PROFILE_ONLY_OUTPUT

        ops = Bfd(device=self.device)
        ops.learn()

        self.assertIn("profiles", ops.info)
        profile = ops.info["profiles"]["BFD-SLOW"]
        self.assertEqual(profile["id"], "BFD-SLOW")
        self.assertTrue(profile["enabled"])
        self.assertEqual(profile["desired_minimum_tx_interval"], 1000000)
        self.assertEqual(profile["detection_multiplier"], 5)
        self.assertNotIn("sessions", profile)


if __name__ == "__main__":
    unittest.main()
