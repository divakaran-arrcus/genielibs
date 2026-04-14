"""Unit tests for ArcOS BGP Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.bgp.arcos.bgp import Bgp

MOD = "genie.libs.ops.bgp.arcos.bgp"

GLOBAL_OUTPUT = {
    "as": 65001,
    "router-id": "1.1.1.1",
    "total-paths": 15,
    "total-prefixes": 10,
    "total-configured-neighbors": 2,
    "total-established-neighbors": 2,
    "cluster-id": "1.1.1.1",
    "segment-routing-enabled": False,
}

AFI_SAFI_OUTPUT = {
    "afi-safis": {
        "IPV4_UNICAST": {
            "enabled": True,
            "total-paths": 8,
            "total-prefixes": 5,
            "paths-received": 3,
            "paths-sent": 5,
        },
        "IPV6_UNICAST": {
            "enabled": True,
            "total-paths": 7,
            "total-prefixes": 5,
        },
    }
}

NEIGHBOR_OUTPUT = {
    "neighbors": {
        "10.12.1.2": {
            "neighbor-address": "10.12.1.2",
            "peer-as": 65002,
            "local-as": 65001,
            "peer-type": "EXTERNAL",
            "session-state": "ESTABLISHED",
            "description": "rtr2-ebgp",
            "shutdown": False,
            "peer-group": "EBGP-PEERS",
            "transport": {
                "local-address": "10.12.1.1",
                "local-port": 179,
                "remote-address": "10.12.1.2",
                "remote-port": 45123,
            },
            "messages-sent": {
                "UPDATE": 5,
                "NOTIFICATION": 0,
                "TOTAL": 120,
            },
            "messages-received": {
                "UPDATE": 3,
                "NOTIFICATION": 0,
                "TOTAL": 118,
            },
            "afi-safis": ["IPV4_UNICAST", "IPV6_UNICAST"],
        },
        "10.13.1.3": {
            "neighbor-address": "10.13.1.3",
            "peer-as": 65001,
            "local-as": 65001,
            "peer-type": "INTERNAL",
            "session-state": "ESTABLISHED",
            "shutdown": False,
            "afi-safis": ["IPV4_UNICAST"],
        },
    }
}

RIB_OUTPUT = {
    "routes": {
        "10.0.0.0/24": {
            "prefix": "10.0.0.0/24",
            "paths": [
                {
                    "next-hop": "10.12.1.2",
                    "origin": "IGP",
                    "valid-route": True,
                },
            ],
        },
        "10.1.0.0/24": {
            "prefix": "10.1.0.0/24",
            "paths": [
                {
                    "next-hop": "10.12.1.2",
                    "origin": "EGP",
                    "valid-route": True,
                },
            ],
        },
    }
}


class TestBgpOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowBgpRibRoute")
    @patch(f"{MOD}.ShowBgpNeighbor")
    @patch(f"{MOD}.ShowBgpGlobalAfiSafi")
    @patch(f"{MOD}.ShowBgpGlobalState")
    def test_learn_basic(self, mock_global, mock_afi, mock_nbr, mock_rib):
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        mock_afi.return_value.parse.return_value = AFI_SAFI_OUTPUT
        mock_nbr.return_value.parse.return_value = NEIGHBOR_OUTPUT
        mock_rib.return_value.parse.return_value = RIB_OUTPUT

        ops = Bgp(device=self.device)
        ops.learn()

        self.assertIn("instance", ops.info)
        inst = ops.info["instance"]["default"]

        # BGP ID
        self.assertEqual(inst["bgp_id"], 65001)

        # VRF level
        vrf = inst["vrf"]["default"]
        self.assertEqual(vrf["router_id"], "1.1.1.1")
        self.assertEqual(vrf["cluster_id"], "1.1.1.1")

        # Address families
        af = vrf["address_family"]
        self.assertIn("ipv4 unicast", af)
        self.assertIn("ipv6 unicast", af)
        self.assertEqual(af["ipv4 unicast"]["total_paths"], 8)
        self.assertEqual(af["ipv4 unicast"]["total_prefixes"], 5)

        # Neighbors
        nbrs = vrf["neighbor"]
        self.assertIn("10.12.1.2", nbrs)
        self.assertIn("10.13.1.3", nbrs)

        n1 = nbrs["10.12.1.2"]
        self.assertEqual(n1["session_state"], "Established")
        self.assertEqual(n1["remote_as"], 65002)
        self.assertEqual(n1["local_as"], 65001)
        self.assertEqual(n1["description"], "rtr2-ebgp")
        self.assertFalse(n1["shutdown"])
        self.assertEqual(n1["bgp_peer_group"], "EBGP-PEERS")

        # Transport
        transport = n1["bgp_session_transport"]["connection"]
        self.assertEqual(transport["local_host"], "10.12.1.1")
        self.assertEqual(transport["foreign_host"], "10.12.1.2")

        # Messages
        counters = n1["bgp_neighbor_counters"]["messages"]
        self.assertEqual(counters["sent"]["update"], 5)
        self.assertEqual(counters["received"]["update"], 3)

        # Per-neighbor AFI-SAFIs
        self.assertIn("ipv4 unicast", n1["address_family"])
        self.assertIn("ipv6 unicast", n1["address_family"])
        self.assertTrue(n1["address_family"]["ipv4 unicast"]["enabled"])

        # iBGP neighbor
        n2 = nbrs["10.13.1.3"]
        self.assertEqual(n2["session_state"], "Established")
        self.assertEqual(n2["remote_as"], 65001)

    @patch(f"{MOD}.ShowBgpRibRoute")
    @patch(f"{MOD}.ShowBgpNeighbor")
    @patch(f"{MOD}.ShowBgpGlobalAfiSafi")
    @patch(f"{MOD}.ShowBgpGlobalState")
    def test_learn_with_routes(self, mock_global, mock_afi, mock_nbr, mock_rib):
        """Test learn() with address_family filter populates routes."""
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        mock_afi.return_value.parse.return_value = AFI_SAFI_OUTPUT
        mock_nbr.return_value.parse.return_value = NEIGHBOR_OUTPUT
        mock_rib.return_value.parse.return_value = RIB_OUTPUT

        ops = Bgp(device=self.device)
        ops.learn(address_family="IPV4_UNICAST")

        vrf = ops.info["instance"]["default"]["vrf"]["default"]
        af = vrf["address_family"]["ipv4 unicast"]
        self.assertIn("prefixes", af)
        self.assertIn("10.0.0.0/24", af["prefixes"])
        self.assertEqual(
            af["prefixes"]["10.0.0.0/24"]["index"]["0"]["next_hop"],
            "10.12.1.2"
        )

    @patch(f"{MOD}.ShowBgpRibRoute")
    @patch(f"{MOD}.ShowBgpNeighbor")
    @patch(f"{MOD}.ShowBgpGlobalAfiSafi")
    @patch(f"{MOD}.ShowBgpGlobalState")
    def test_learn_empty(self, mock_global, mock_afi, mock_nbr, mock_rib):
        """All parsers fail — info should be empty."""
        for m in (mock_global, mock_afi, mock_nbr, mock_rib):
            m.return_value.parse.side_effect = Exception("No data")

        ops = Bgp(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowBgpRibRoute")
    @patch(f"{MOD}.ShowBgpNeighbor")
    @patch(f"{MOD}.ShowBgpGlobalAfiSafi")
    @patch(f"{MOD}.ShowBgpGlobalState")
    def test_learn_partial_global_only(self, mock_global, mock_afi,
                                       mock_nbr, mock_rib):
        """Only global succeeds — bgp_id populated, no neighbors."""
        mock_global.return_value.parse.return_value = GLOBAL_OUTPUT
        for m in (mock_afi, mock_nbr, mock_rib):
            m.return_value.parse.side_effect = Exception("No data")

        ops = Bgp(device=self.device)
        ops.learn()

        inst = ops.info["instance"]["default"]
        self.assertEqual(inst["bgp_id"], 65001)
        self.assertNotIn("neighbor", inst.get("vrf", {}).get("default", {}))


if __name__ == "__main__":
    unittest.main()
