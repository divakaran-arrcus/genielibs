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

# OSPFv3 sample data
V3_GLOBAL_OUTPUT = {
    "router-id": "2.2.2.2",
    "area-count": 1,
    "neighbor-count": 1,
    "full-neighbor-count": 1,
}

V3_NEIGHBOR_OUTPUT = {
    "neighbors": {
        "0:swp1:1.1.1.1": {
            "area": 0,
            "interface": "swp1",
            "neighbor-router-id": "1.1.1.1",
            "neighbor-ip-address": "fe80::1",
            "adjacency-state": "NEIGHBOR_FULL",
            "priority": 1,
        },
    }
}

# Patch list covering all 9 parsers (v2 + v3)
_ALL_PATCHES = [
    f"{MOD}.ShowOspfv3Neighbor",
    f"{MOD}.ShowOspfv3Global",
    f"{MOD}.ShowNetworkInstance",
    f"{MOD}.ShowOspfLsdb",
    f"{MOD}.ShowOspfNeighbor",
    f"{MOD}.ShowOspfInterface",
    f"{MOD}.ShowOspfArea",
    f"{MOD}.ShowOspfSpfThrottle",
    f"{MOD}.ShowOspfGlobal",
]


def _fail_all(*mocks):
    """Set all mocks to raise Exception."""
    for m in mocks:
        m.return_value.parse.side_effect = Exception("No data")


class TestOspfOps(unittest.TestCase):
    """Test OSPF Ops model learn()."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr2"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowOspfv3Neighbor")
    @patch(f"{MOD}.ShowOspfv3Global")
    @patch(f"{MOD}.ShowNetworkInstance")
    @patch(f"{MOD}.ShowOspfLsdb")
    @patch(f"{MOD}.ShowOspfNeighbor")
    @patch(f"{MOD}.ShowOspfInterface")
    @patch(f"{MOD}.ShowOspfArea")
    @patch(f"{MOD}.ShowOspfSpfThrottle")
    @patch(f"{MOD}.ShowOspfGlobal")
    def test_learn_basic(self, mock_global, mock_spf, mock_area,
                         mock_intf, mock_nbr, mock_lsdb, mock_ni,
                         mock_v3_global, mock_v3_nbr):
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        mock_spf.return_value.parse.return_value = SPF_OUTPUT
        mock_area.return_value.parse.return_value = AREA_OUTPUT
        mock_intf.return_value.parse.return_value = INTERFACE_OUTPUT
        mock_nbr.return_value.parse.return_value = NEIGHBOR_OUTPUT
        mock_lsdb.return_value.parse.return_value = LSDB_OUTPUT
        mock_ni.return_value.parse.return_value = NI_OUTPUT
        # v3 parsers fail — no OSPFv3 on this device
        mock_v3_global.return_value.parse.side_effect = Exception("No v3")
        mock_v3_nbr.return_value.parse.side_effect = Exception("No v3")

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

    @patch(*_ALL_PATCHES[:1])  # dummy — we use _fail_all below
    def _not_used(self):
        pass

    def test_learn_empty(self):
        """All parsers fail — info should be empty dict."""
        with patch(f"{MOD}.ShowOspfGlobal") as m1, \
             patch(f"{MOD}.ShowOspfSpfThrottle") as m2, \
             patch(f"{MOD}.ShowOspfArea") as m3, \
             patch(f"{MOD}.ShowOspfInterface") as m4, \
             patch(f"{MOD}.ShowOspfNeighbor") as m5, \
             patch(f"{MOD}.ShowOspfLsdb") as m6, \
             patch(f"{MOD}.ShowNetworkInstance") as m7, \
             patch(f"{MOD}.ShowOspfv3Global") as m8, \
             patch(f"{MOD}.ShowOspfv3Neighbor") as m9:
            _fail_all(m1, m2, m3, m4, m5, m6, m7, m8, m9)

            ops = Ospf(device=self.device)
            ops.learn()
            self.assertEqual(ops.info, {})

    def test_learn_partial_v2_only(self):
        """Only v2 global succeeds — ipv4 populated, no ipv6."""
        with patch(f"{MOD}.ShowOspfGlobal") as m1, \
             patch(f"{MOD}.ShowOspfSpfThrottle") as m2, \
             patch(f"{MOD}.ShowOspfArea") as m3, \
             patch(f"{MOD}.ShowOspfInterface") as m4, \
             patch(f"{MOD}.ShowOspfNeighbor") as m5, \
             patch(f"{MOD}.ShowOspfLsdb") as m6, \
             patch(f"{MOD}.ShowNetworkInstance") as m7, \
             patch(f"{MOD}.ShowOspfv3Global") as m8, \
             patch(f"{MOD}.ShowOspfv3Neighbor") as m9:
            m1.return_value.parse.return_value = GLOBAL_OUTPUT
            _fail_all(m2, m3, m4, m5, m6, m7, m8, m9)

            ops = Ospf(device=self.device)
            ops.learn()

            af = ops.info["vrf"]["default"]["address_family"]
            self.assertIn("ipv4", af)
            self.assertNotIn("ipv6", af)
            inst = af["ipv4"]["instance"]["default"]
            self.assertEqual(inst["router_id"], "2.2.2.2")

    def test_learn_v3_only(self):
        """Only v3 parsers succeed — ipv6 populated, no ipv4."""
        with patch(f"{MOD}.ShowOspfGlobal") as m1, \
             patch(f"{MOD}.ShowOspfSpfThrottle") as m2, \
             patch(f"{MOD}.ShowOspfArea") as m3, \
             patch(f"{MOD}.ShowOspfInterface") as m4, \
             patch(f"{MOD}.ShowOspfNeighbor") as m5, \
             patch(f"{MOD}.ShowOspfLsdb") as m6, \
             patch(f"{MOD}.ShowNetworkInstance") as m7, \
             patch(f"{MOD}.ShowOspfv3Global") as m8, \
             patch(f"{MOD}.ShowOspfv3Neighbor") as m9:
            _fail_all(m1, m2, m3, m4, m5, m6, m7)
            m8.return_value.parse.return_value = V3_GLOBAL_OUTPUT
            m9.return_value.parse.return_value = V3_NEIGHBOR_OUTPUT

            ops = Ospf(device=self.device)
            ops.learn()

            af = ops.info["vrf"]["default"]["address_family"]
            self.assertNotIn("ipv4", af)
            self.assertIn("ipv6", af)

            v3_inst = af["ipv6"]["instance"]["default"]
            self.assertEqual(v3_inst["router_id"], "2.2.2.2")

            # Neighbors
            nbrs = v3_inst["areas"]["0"]["interfaces"]["swp1"]["neighbors"]
            self.assertIn("1.1.1.1", nbrs)
            self.assertEqual(nbrs["1.1.1.1"]["address"], "fe80::1")

    @patch(f"{MOD}.ShowOspfv3Neighbor")
    @patch(f"{MOD}.ShowOspfv3Global")
    @patch(f"{MOD}.ShowNetworkInstance")
    @patch(f"{MOD}.ShowOspfLsdb")
    @patch(f"{MOD}.ShowOspfNeighbor")
    @patch(f"{MOD}.ShowOspfInterface")
    @patch(f"{MOD}.ShowOspfArea")
    @patch(f"{MOD}.ShowOspfSpfThrottle")
    @patch(f"{MOD}.ShowOspfGlobal")
    def test_learn_v2_and_v3(self, mock_global, mock_spf, mock_area,
                              mock_intf, mock_nbr, mock_lsdb, mock_ni,
                              mock_v3_global, mock_v3_nbr):
        """Both v2 and v3 parsers succeed — both ipv4 and ipv6 populated."""
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        mock_spf.return_value.parse.return_value = SPF_OUTPUT
        mock_area.return_value.parse.return_value = AREA_OUTPUT
        mock_intf.return_value.parse.return_value = INTERFACE_OUTPUT
        mock_nbr.return_value.parse.return_value = NEIGHBOR_OUTPUT
        mock_lsdb.return_value.parse.return_value = LSDB_OUTPUT
        mock_ni.return_value.parse.return_value = NI_OUTPUT
        mock_v3_global.return_value.parse.return_value = V3_GLOBAL_OUTPUT
        mock_v3_nbr.return_value.parse.return_value = V3_NEIGHBOR_OUTPUT

        ops = Ospf(device=self.device)
        ops.learn()

        af = ops.info["vrf"]["default"]["address_family"]

        # Both address families present
        self.assertIn("ipv4", af)
        self.assertIn("ipv6", af)

        # v2 (ipv4)
        v2 = af["ipv4"]["instance"]["default"]
        self.assertEqual(v2["router_id"], "2.2.2.2")
        self.assertIn("areas", v2)
        self.assertIn("redistribution", v2)

        # v3 (ipv6)
        v3 = af["ipv6"]["instance"]["default"]
        self.assertEqual(v3["router_id"], "2.2.2.2")
        nbrs = v3["areas"]["0"]["interfaces"]["swp1"]["neighbors"]
        self.assertIn("1.1.1.1", nbrs)
        self.assertEqual(nbrs["1.1.1.1"]["address"], "fe80::1")


if __name__ == "__main__":
    unittest.main()
