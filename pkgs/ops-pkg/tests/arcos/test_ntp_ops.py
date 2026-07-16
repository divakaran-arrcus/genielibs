"""Unit tests for ArcOS NTP Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.ntp.arcos.ntp import Ntp

MOD = "genie.libs.ops.ntp.arcos.ntp"

PARSED_OUTPUT = {
    "network-instance": "default",
    "associations": {
        "216.229.0.49": {
            "address": "216.229.0.49",
            "stratum": 2,
            "root-delay": 22,
            "root-dispersion": "27",
            "offset": "81",
            "poll-interval": 64,
            "reach": 377,
            "time-since-last-response": "60",
            "association-status": "SYNC_SOURCE",
        },
        "66.118.228.14": {
            "address": "66.118.228.14",
            "stratum": 2,
            "root-delay": 12,
            "root-dispersion": "21",
            "offset": "81",
            "poll-interval": 64,
            "reach": 377,
            "association-status": "COMBINED",
        },
        "67.217.246.204": {
            "address": "67.217.246.204",
            "stratum": 3,
            "root-delay": 165,
            "offset": "115",
            "poll-interval": 64,
            "reach": 377,
            "association-status": "COMBINED",
        },
    },
}


class TestNtpOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr2"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowNtp")
    def test_learn_basic(self, mock_parser):
        mock_parser.return_value.parse.return_value = PARSED_OUTPUT

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertIn("clock_state", ops.info)
        cs = ops.info["clock_state"]["system_status"]
        self.assertEqual(cs["associations_address"], "216.229.0.49")
        self.assertEqual(cs["clock_stratum"], 2)

        # VRF associations
        vrf = ops.info["vrf"]["default"]
        assocs = vrf["associations"]["address"]
        self.assertIn("216.229.0.49", assocs)
        self.assertIn("66.118.228.14", assocs)
        self.assertIn("67.217.246.204", assocs)

        # Check sync source peer
        sync = assocs["216.229.0.49"]["local_mode"]["client"]["isconfigured"][True]
        self.assertEqual(sync["address"], "216.229.0.49")
        self.assertEqual(sync["stratum"], 2)
        self.assertEqual(sync["poll"], 64)
        self.assertEqual(sync["reach"], 377)
        self.assertEqual(sync["delay"], "22")
        self.assertTrue(sync["isconfigured"])

    @patch(f"{MOD}.ShowNtp")
    def test_learn_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowNtp")
    def test_learn_no_sync_source(self, mock_parser):
        """All peers COMBINED, no SYNC_SOURCE — no clock_state."""
        mock_parser.return_value.parse.return_value = {
            "associations": {
                "1.1.1.1": {
                    "address": "1.1.1.1",
                    "stratum": 2,
                    "association-status": "COMBINED",
                },
            },
        }

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertNotIn("clock_state", ops.info)
        self.assertIn("vrf", ops.info)

    @patch(f"{MOD}.ShowNtp")
    def test_learn_parsed_empty_dict(self, mock_parser):
        """Parser returns an empty dict (falsy) -- info stays empty."""
        mock_parser.return_value.parse.return_value = {}

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowNtp")
    def test_learn_no_associations_key(self, mock_parser):
        """Parser returns data with no 'associations' key -- info stays empty."""
        mock_parser.return_value.parse.return_value = {
            "network-instance": "default",
        }

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowNtp")
    def test_learn_empty_associations_dict(self, mock_parser):
        """Parser returns an empty 'associations' dict -- info stays empty."""
        mock_parser.return_value.parse.return_value = {
            "network-instance": "default",
            "associations": {},
        }

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowNtp")
    def test_learn_sync_source_no_stratum(self, mock_parser):
        """SYNC_SOURCE peer present but missing stratum -- clock_stratum omitted."""
        mock_parser.return_value.parse.return_value = {
            "associations": {
                "10.0.0.1": {
                    "address": "10.0.0.1",
                    "association-status": "SYNC_SOURCE",
                },
            },
        }

        ops = Ntp(device=self.device)
        ops.learn()

        cs = ops.info["clock_state"]["system_status"]
        self.assertEqual(cs["associations_address"], "10.0.0.1")
        self.assertNotIn("clock_stratum", cs)

    @patch(f"{MOD}.ShowNtp")
    def test_learn_peer_missing_optional_fields(self, mock_parser):
        """Peer with no stratum/poll/reach/offset/delay -- optional keys omitted."""
        mock_parser.return_value.parse.return_value = {
            "associations": {
                "192.0.2.1": {
                    "address": "192.0.2.1",
                    "association-status": "CANDIDATE",
                },
            },
        }

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertNotIn("clock_state", ops.info)

        peer = ops.info["vrf"]["default"]["associations"]["address"]["192.0.2.1"]
        config = peer["local_mode"]["client"]["isconfigured"][True]
        self.assertEqual(config["address"], "192.0.2.1")
        self.assertEqual(config["vrf"], "default")
        self.assertTrue(config["isconfigured"])
        self.assertNotIn("stratum", config)
        self.assertNotIn("poll", config)
        self.assertNotIn("reach", config)
        self.assertNotIn("offset", config)
        self.assertNotIn("delay", config)

    @patch(f"{MOD}.ShowNtp")
    def test_learn_custom_vrf(self, mock_parser):
        """Non-default network-instance is threaded through to vrf and peer entries."""
        mock_parser.return_value.parse.return_value = {
            "network-instance": "mgmt",
            "associations": {
                "203.0.113.1": {
                    "address": "203.0.113.1",
                    "stratum": 4,
                    "association-status": "COMBINED",
                },
            },
        }

        ops = Ntp(device=self.device)
        ops.learn()

        self.assertIn("mgmt", ops.info["vrf"])
        peer = ops.info["vrf"]["mgmt"]["associations"]["address"]["203.0.113.1"]
        config = peer["local_mode"]["client"]["isconfigured"][True]
        self.assertEqual(config["vrf"], "mgmt")


if __name__ == "__main__":
    unittest.main()
