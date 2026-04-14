"""Unit tests for ArcOS Static Routing Ops model."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.ops.static_routing.arcos.static_routing import StaticRouting

MOD = "genie.libs.ops.static_routing.arcos.static_routing"

PARSED_OUTPUT = {
    "network-instances": {
        "default": {
            "protocols": {
                "default": {
                    "identifier": "STATIC",
                    "name": "default",
                    "static-routes": {
                        "10.0.0.0/8": {
                            "prefix": "10.0.0.0/8",
                            "next-hops": {
                                "1": {
                                    "index": "1",
                                    "next-hop": "10.1.1.1",
                                    "interface": "swp1",
                                    "metric": 100,
                                }
                            },
                        },
                        "192.168.0.0/16": {
                            "prefix": "192.168.0.0/16",
                            "next-hops": {
                                "1": {
                                    "index": "1",
                                    "next-hop": "DROP",
                                }
                            },
                        },
                        "2001:db8::/32": {
                            "prefix": "2001:db8::/32",
                            "next-hops": {
                                "1": {
                                    "index": "1",
                                    "next-hop": "fe80::1",
                                    "interface": "swp1",
                                }
                            },
                        },
                    },
                }
            }
        }
    }
}


class TestStaticRoutingOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_basic(self, mock_parser):
        mock_parser.return_value.parse.return_value = PARSED_OUTPUT

        ops = StaticRouting(device=self.device)
        ops.learn()

        self.assertIn("vrf", ops.info)
        vrf = ops.info["vrf"]["default"]

        # IPv4 routes
        ipv4 = vrf["address_family"]["ipv4"]["routes"]
        self.assertIn("10.0.0.0/8", ipv4)
        route = ipv4["10.0.0.0/8"]
        self.assertEqual(route["route"], "10.0.0.0/8")
        nh = route["next_hop"]["next_hop_list"]["1"]
        self.assertEqual(nh["next_hop"], "10.1.1.1")
        self.assertEqual(nh["outgoing_interface"], "swp1")
        self.assertTrue(nh["active"])

        # Drop route
        self.assertIn("192.168.0.0/16", ipv4)
        drop = ipv4["192.168.0.0/16"]["next_hop"]["next_hop_list"]["1"]
        self.assertEqual(drop["next_hop"], "DROP")

        # IPv6 route
        ipv6 = vrf["address_family"]["ipv6"]["routes"]
        self.assertIn("2001:db8::/32", ipv6)
        v6nh = ipv6["2001:db8::/32"]["next_hop"]["next_hop_list"]["1"]
        self.assertEqual(v6nh["next_hop"], "fe80::1")

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("No data")

        ops = StaticRouting(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_interface_only(self, mock_parser):
        """Route with interface only (no next-hop IP)."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "identifier": "STATIC",
                            "name": "default",
                            "static-routes": {
                                "172.16.0.0/12": {
                                    "prefix": "172.16.0.0/12",
                                    "next-hops": {
                                        "1": {
                                            "index": "1",
                                            "interface": "swp2",
                                        }
                                    },
                                },
                            },
                        }
                    }
                }
            }
        }

        ops = StaticRouting(device=self.device)
        ops.learn()

        route = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"]["172.16.0.0/12"]
        intf = route["next_hop"]["outgoing_interface"]["swp2"]
        self.assertEqual(intf["outgoing_interface"], "swp2")
        self.assertTrue(intf["active"])


if __name__ == "__main__":
    unittest.main()
