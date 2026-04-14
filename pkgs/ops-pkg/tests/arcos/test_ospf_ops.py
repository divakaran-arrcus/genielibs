"""Unit tests for ArcOS OSPF Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.ospf.arcos.ospf import Ospf

# Module path for patching
MOD = "genie.libs.ops.ospf.arcos.ospf"

# Sample parser outputs (based on real rtr2 device data)
GLOBAL_OUTPUT = {
    "router-id": "2.2.2.2",
    "log-adjacency-changes": "LOG_ADJ_ENABLE_LIMITED",
    "max-ecmp-paths": 128,
    "abr-router": True,
    "asbr-router": False,
    "area-count": 2,
    "full-neighbor-count": 1,
}

SPF_OUTPUT = {
    "spf-initial-delay": 50,
    "spf-short-delay": 200,
    "spf-long-delay": 5000,
}

AREA_OUTPUT = {
    "areas": {
        "0": {
            "identifier": 0,
            "area-type": "AREA_TYPE_NORMAL",
            "stub-default-cost": 1,
            "up-interface-count": 2,
            "full-neighbor-count": 1,
        },
        "1": {
            "identifier": 1,
            "area-type": "AREA_TYPE_STUB",
            "stub-default-cost": 10,
            "up-interface-count": 2,
            "full-neighbor-count": 1,
        },
    }
}

INTERFACE_OUTPUT = {
    "areas": {
        "0": {
            "interfaces": {
                "loopback0": {
                    "id": "loopback0",
                    "network-type": "POINT_TO_POINT_NETWORK",
                    "metric": 10,
                    "passive": True,
                    "interface-up": True,
                },
                "swp1": {
                    "id": "swp1",
                    "network-type": "POINT_TO_POINT_NETWORK",
                    "metric": 320,
                    "passive": False,
                    "interface-up": True,
                },
            }
        }
    }
}

NEIGHBOR_OUTPUT = {
    "neighbors": {
        "0:swp1:1.1.1.1": {
            "area": 0,
            "interface": "swp1",
            "neighbor-router-id": "1.1.1.1",
            "neighbor-ip-address": "10.12.1.1",
            "adjacency-state": "NEIGHBOR_FULL",
            "priority": 1,
        },
    }
}

LSDB_OUTPUT = {
    "areas": {
        "0": {
            "lsa-types": {
                "ROUTER_LSA": {
                    "type": "ROUTER_LSA",
                    "lsas": {
                        "1.1.1.1:1.1.1.1": {
                            "link-state-id": "1.1.1.1",
                            "advertising-router": "1.1.1.1",
                            "sequence-number": "80:00:00:03",
                            "age": 77,
                            "checksum": 58494,
                            "router-lsa": {
                                "flags": "B",
                                "num-links": 3,
                                "links": {
                                    "0": {
                                        "type": "ROUTER_LSA_P2P",
                                        "link-id": "2.2.2.2",
                                        "link-data": "10.12.1.1",
                                        "metric": 320,
                                    }
                                },
                            },
                        },
                    },
                },
            }
        }
    }
}

NI_OUTPUT = {
    "network-instances": {
        "default": {
            "table-connections": [
                {
                    "src-protocol": "CONNECTED",
                    "dst-protocol": "OSPF",
                    "address-family": "IPV4",
                },
                {
                    "src-protocol": "STATIC",
                    "dst-protocol": "OSPF",
                    "address-family": "IPV4",
                },
            ]
        }
    }
}


class TestOspfOps(unittest.TestCase):
    """Test OSPF Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr2"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowNetworkInstance")
    @patch(f"{MOD}.ShowOspfLsdb")
    @patch(f"{MOD}.ShowOspfNeighbor")
    @patch(f"{MOD}.ShowOspfInterface")
    @patch(f"{MOD}.ShowOspfArea")
    @patch(f"{MOD}.ShowOspfSpfThrottle")
    @patch(f"{MOD}.ShowOspfGlobal")
    def test_learn_basic(self, mock_global, mock_spf, mock_area,
                         mock_intf, mock_nbr, mock_lsdb, mock_ni):
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        mock_spf.return_value.parse.return_value = SPF_OUTPUT
        mock_area.return_value.parse.return_value = AREA_OUTPUT
        mock_intf.return_value.parse.return_value = INTERFACE_OUTPUT
        mock_nbr.return_value.parse.return_value = NEIGHBOR_OUTPUT
        mock_lsdb.return_value.parse.return_value = LSDB_OUTPUT
        mock_ni.return_value.parse.return_value = NI_OUTPUT

        ops = Ospf(device=self.device)
        ops.learn()

        self.assertIsInstance(ops.info, dict)
        self.assertIn("vrf", ops.info)

        inst = ops.info["vrf"]["default"]["address_family"]["ipv4"]["instance"]["default"]

        # Router ID
        self.assertEqual(inst["router_id"], "2.2.2.2")

        # SPF control
        spf = inst["spf_control"]["throttle"]["spf"]
        self.assertEqual(spf["start"], 50)
        self.assertEqual(spf["hold"], 200)
        self.assertEqual(spf["maximum"], 5000)

        # Redistribution
        self.assertIn("connected", inst["redistribution"])
        self.assertTrue(inst["redistribution"]["connected"]["enabled"])
        self.assertIn("static", inst["redistribution"])

        # Areas
        self.assertIn("0", inst["areas"])
        self.assertIn("1", inst["areas"])
        self.assertEqual(inst["areas"]["0"]["area_type"], "normal")
        self.assertEqual(inst["areas"]["1"]["area_type"], "stub")
        self.assertEqual(inst["areas"]["1"]["default_cost"], 10)

        # Interfaces
        intfs = inst["areas"]["0"]["interfaces"]
        self.assertIn("loopback0", intfs)
        self.assertIn("swp1", intfs)
        self.assertEqual(intfs["loopback0"]["interface_type"], "point-to-point")
        self.assertTrue(intfs["loopback0"]["passive"])
        self.assertEqual(intfs["swp1"]["cost"], 320)
        self.assertFalse(intfs["swp1"]["passive"])

        # Neighbors
        nbrs = intfs["swp1"]["neighbors"]
        self.assertIn("1.1.1.1", nbrs)
        self.assertEqual(nbrs["1.1.1.1"]["address"], "10.12.1.1")

        # LSDB
        lsa_types = inst["areas"]["0"]["database"]["lsa_types"]
        self.assertIn("ROUTER_LSA", lsa_types)
        lsas = lsa_types["ROUTER_LSA"]["lsas"]
        self.assertIn("1.1.1.1:1.1.1.1", lsas)
        lsa = lsas["1.1.1.1:1.1.1.1"]
        self.assertEqual(lsa["lsa_id"], "1.1.1.1")
        self.assertEqual(lsa["ospfv2"]["header"]["seq_num"], "80:00:00:03")

    @patch(f"{MOD}.ShowNetworkInstance")
    @patch(f"{MOD}.ShowOspfLsdb")
    @patch(f"{MOD}.ShowOspfNeighbor")
    @patch(f"{MOD}.ShowOspfInterface")
    @patch(f"{MOD}.ShowOspfArea")
    @patch(f"{MOD}.ShowOspfSpfThrottle")
    @patch(f"{MOD}.ShowOspfGlobal")
    def test_learn_empty(self, mock_global, mock_spf, mock_area,
                         mock_intf, mock_nbr, mock_lsdb, mock_ni):
        """All parsers fail — info should be empty dict."""
        for m in (mock_global, mock_spf, mock_area, mock_intf,
                  mock_nbr, mock_lsdb, mock_ni):
            m.return_value.parse.side_effect = Exception("No data")

        ops = Ospf(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowNetworkInstance")
    @patch(f"{MOD}.ShowOspfLsdb")
    @patch(f"{MOD}.ShowOspfNeighbor")
    @patch(f"{MOD}.ShowOspfInterface")
    @patch(f"{MOD}.ShowOspfArea")
    @patch(f"{MOD}.ShowOspfSpfThrottle")
    @patch(f"{MOD}.ShowOspfGlobal")
    def test_learn_partial(self, mock_global, mock_spf, mock_area,
                           mock_intf, mock_nbr, mock_lsdb, mock_ni):
        """Only global succeeds — info should have router_id only."""
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        for m in (mock_spf, mock_area, mock_intf,
                  mock_nbr, mock_lsdb, mock_ni):
            m.return_value.parse.side_effect = Exception("No data")

        ops = Ospf(device=self.device)
        ops.learn()

        inst = ops.info["vrf"]["default"]["address_family"]["ipv4"]["instance"]["default"]
        self.assertEqual(inst["router_id"], "2.2.2.2")
        self.assertNotIn("areas", inst)


if __name__ == "__main__":
    unittest.main()
