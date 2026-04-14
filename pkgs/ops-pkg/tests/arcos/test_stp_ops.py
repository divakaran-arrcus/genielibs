"""Unit tests for ArcOS STP Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.stp.arcos.stp import Stp

MOD = "genie.libs.ops.stp.arcos.stp"

GLOBAL_RAPID_PVST = {
    "bridge-assurance": True,
    "bpdu-guard": True,
    "enabled-protocol": "RAPID_PVST",
}

GLOBAL_PVST = {
    "bridge-assurance": False,
    "bpdu-guard": False,
    "enabled-protocol": "PVST",
}

GLOBAL_MSTP = {
    "bridge-assurance": True,
    "bpdu-guard": False,
    "enabled-protocol": "MSTP",
}


class TestStpOps(unittest.TestCase):
    """Test STP Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowStpGlobal")
    def test_learn_basic(self, mock_parser):
        """Test basic STP learn with RAPID_PVST and all fields."""
        mock_parser.return_value.parse.return_value = GLOBAL_RAPID_PVST

        ops = Stp(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)

        # Global section
        self.assertIn("global", ops.info)
        self.assertTrue(ops.info["global"]["bpdu_guard"])
        self.assertTrue(ops.info["global"]["bridge_assurance"])

        # Protocol mode section
        self.assertIn("rapid_pvst", ops.info)
        self.assertIn("default", ops.info["rapid_pvst"])
        self.assertEqual(ops.info["rapid_pvst"]["default"], {})

    @patch(f"{MOD}.ShowStpGlobal")
    def test_learn_empty(self, mock_parser):
        """Parser fails -- info should be empty dict."""
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = Stp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowStpGlobal")
    def test_learn_rapid_pvst(self, mock_parser):
        """Test RAPID_PVST protocol creates correct mode key."""
        mock_parser.return_value.parse.return_value = GLOBAL_RAPID_PVST

        ops = Stp(device=self.device)
        ops.learn()

        self.assertIn("rapid_pvst", ops.info)
        self.assertNotIn("pvst", ops.info)
        self.assertNotIn("mstp", ops.info)
        self.assertTrue(ops.info["global"]["bpdu_guard"])
        self.assertTrue(ops.info["global"]["bridge_assurance"])

    @patch(f"{MOD}.ShowStpGlobal")
    def test_learn_pvst(self, mock_parser):
        """Test PVST protocol creates correct mode key."""
        mock_parser.return_value.parse.return_value = GLOBAL_PVST

        ops = Stp(device=self.device)
        ops.learn()

        self.assertIn("pvst", ops.info)
        self.assertNotIn("rapid_pvst", ops.info)
        self.assertNotIn("mstp", ops.info)
        self.assertFalse(ops.info["global"]["bpdu_guard"])
        self.assertFalse(ops.info["global"]["bridge_assurance"])

    @patch(f"{MOD}.ShowStpGlobal")
    def test_learn_mstp(self, mock_parser):
        """Test MSTP protocol creates correct mode key."""
        mock_parser.return_value.parse.return_value = GLOBAL_MSTP

        ops = Stp(device=self.device)
        ops.learn()

        self.assertIn("mstp", ops.info)
        self.assertNotIn("rapid_pvst", ops.info)
        self.assertNotIn("pvst", ops.info)
        self.assertTrue(ops.info["global"]["bridge_assurance"])
        self.assertFalse(ops.info["global"]["bpdu_guard"])


if __name__ == "__main__":
    unittest.main()
