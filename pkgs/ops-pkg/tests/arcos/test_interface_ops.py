"""Unit tests for ArcOS Interface Ops model."""
import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.interface.arcos.interface import Interface

MOD = "genie.libs.ops.interface.arcos.interface"

PARSED = {
    "swp1": {
        "name": "swp1",
        "type": "ethernetCsmacd",
        "mtu": 9000,
        "enabled": True,
        "oper_status": "up",
        "description": "link to rtr2",
    }
}


class TestInterfaceOps(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowInterface")
    def test_learn(self, mock_parser):
        # ops calls ShowInterface(device).cli() directly
        mock_parser.return_value.cli.return_value = PARSED
        ops = Interface(device=self.device)
        ops.learn()
        info = ops.info["interface"]["info"]["swp1"]
        self.assertEqual(info["mtu"], 9000)
        self.assertEqual(info["description"], "link to rtr2")
        self.assertEqual(info["type"], "ethernetCsmacd")
        self.assertTrue(info["enabled"])


if __name__ == "__main__":
    unittest.main()
