"""Unit tests for ArcOS ISIS Ops model."""
import unittest
from unittest.mock import Mock

from genie.libs.ops.isis.arcos.isis import Isis


GLOBAL = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "system_id": "0000.0000.0005",
                        "area_address": "49.0000",
                    }
                }
            }
        }
    }
}

INTERFACE = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "interfaces": {
                        "swp1": {
                            "circuit_type": "LEVEL_2",
                            "network_type": "POINT_TO_POINT",
                            "passive": False,
                            "levels": {2: {"priority": 64, "metric": 10}},
                        }
                    }
                }
            }
        }
    }
}


def _fake_parse(command):
    if command == "show isis global":
        return GLOBAL
    if command == "show isis interface":
        return INTERFACE
    return {}  # lsp / adjacency / route -> empty; learn() degrades gracefully


class TestIsisOps(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"
        self.device.parse = Mock(side_effect=_fake_parse)

    def test_learn_instance_vrf(self):
        ops = Isis(device=self.device)
        ops.learn()
        self.assertIn("instance", ops.info)
        inst = ops.info["instance"]["default"]
        self.assertEqual(inst["process_id"], "default")
        vrf = inst["vrf"]["default"]
        self.assertEqual(vrf["vrf"], "default")
        self.assertEqual(vrf["system_id"], "0000.0000.0005")
        self.assertTrue(vrf["enable"])

    def test_learn_interface_mapping(self):
        ops = Isis(device=self.device)
        ops.learn()
        intf = ops.info["instance"]["default"]["vrf"]["default"]["interfaces"]["swp1"]
        self.assertEqual(intf["name"], "swp1")
        self.assertEqual(intf["level_type"], "level-2-only")  # LEVEL_2 mapping
        metric = intf["topologies"]["0"]["metric"]["level-2"]["metric"]
        self.assertEqual(metric, 10)

    def test_learn_no_system_id_disabled(self):
        self.device.parse = Mock(side_effect=lambda c: {})
        ops = Isis(device=self.device)
        ops.learn()
        vrf = ops.info["instance"]["default"]["vrf"]["default"]
        self.assertFalse(vrf["enable"])


if __name__ == "__main__":
    unittest.main()
