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

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_interface_only_with_preference(self, mock_parser):
        """Interface-only next-hop that also carries a preference value ->
        hits the `if pref is not None` branch inside the `elif intf` path."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "static-routes": {
                                "172.20.0.0/16": {
                                    "prefix": "172.20.0.0/16",
                                    "next-hops": {
                                        "1": {
                                            "index": "1",
                                            "interface": "swp3",
                                            "preference": 10,
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

        intf = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"][
            "172.20.0.0/16"
        ]["next_hop"]["outgoing_interface"]["swp3"]
        self.assertEqual(intf["preference"], 10)

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_next_hop_bare_no_interface_no_preference(self, mock_parser):
        """next-hop IP with neither interface nor preference/metric -> hop
        entry omits both `outgoing_interface` and `preference` keys."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "static-routes": {
                                "10.40.0.0/16": {
                                    "prefix": "10.40.0.0/16",
                                    "next-hops": {
                                        "1": {"index": "1", "next-hop": "10.5.5.5"}
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

        hop = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"][
            "10.40.0.0/16"
        ]["next_hop"]["next_hop_list"]["1"]
        self.assertEqual(hop["next_hop"], "10.5.5.5")
        self.assertNotIn("outgoing_interface", hop)
        self.assertNotIn("preference", hop)

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_openconfig_prefixed_drop_is_stripped(self, mock_parser):
        """next-hop value carrying the 'openconfig-*:' namespace prefix must
        be stripped before the DROP comparison (covers the `.split(':')[-1]`
        line as well as the final `elif nh_addr.upper() == 'DROP'` branch)."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "static-routes": {
                                "203.0.113.0/24": {
                                    "prefix": "203.0.113.0/24",
                                    "next-hops": {
                                        "1": {
                                            "index": "1",
                                            "next-hop": "openconfig-local-routing:DROP",
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

        hop = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"][
            "203.0.113.0/24"
        ]["next_hop"]["next_hop_list"]["1"]
        self.assertEqual(hop["next_hop"], "DROP")

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_route_with_no_next_hops_key(self, mock_parser):
        """Route with an empty next-hops dict -> `if next_hops:` is False,
        so the route entry never gets a `next_hop` key."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "static-routes": {
                                "198.51.100.0/24": {
                                    "prefix": "198.51.100.0/24",
                                    "next-hops": {},
                                },
                            },
                        }
                    }
                }
            }
        }

        ops = StaticRouting(device=self.device)
        ops.learn()

        route = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"][
            "198.51.100.0/24"
        ]
        self.assertEqual(route["route"], "198.51.100.0/24")
        self.assertNotIn("next_hop", route)

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_next_hop_entry_with_no_addr_and_no_interface(self, mock_parser):
        """A next-hop entry with neither `next-hop` nor `interface` maps to
        nothing (`_map_next_hops` returns {}), so `if nh_info:` is False and
        the route entry never gets a `next_hop` key even though `next-hops`
        itself was non-empty."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {
                            "static-routes": {
                                "10.90.0.0/16": {
                                    "prefix": "10.90.0.0/16",
                                    "next-hops": {
                                        "1": {"index": "1", "metric": 50},
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

        route = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"][
            "10.90.0.0/16"
        ]
        self.assertNotIn("next_hop", route)

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_protocol_instance_with_no_static_routes_is_skipped(self, mock_parser):
        """A protocol instance with an empty static-routes dict hits the
        `if not static_routes: continue` branch, while a sibling protocol
        instance with real routes is still learned."""
        mock_parser.return_value.parse.return_value = {
            "network-instances": {
                "default": {
                    "protocols": {
                        "default": {"static-routes": {}},
                        "pi2": {
                            "static-routes": {
                                "10.0.0.0/8": {
                                    "prefix": "10.0.0.0/8",
                                    "next-hops": {
                                        "1": {"index": "1", "next-hop": "10.1.1.1"}
                                    },
                                },
                            }
                        },
                    }
                }
            }
        }

        ops = StaticRouting(device=self.device)
        ops.learn()

        routes = ops.info["vrf"]["default"]["address_family"]["ipv4"]["routes"]
        self.assertIn("10.0.0.0/8", routes)

    @patch(f"{MOD}.ShowStaticRoutingConfig")
    def test_learn_parser_returns_falsy(self, mock_parser):
        """parser.parse() returning an empty dict (no exception) also hits
        `if not parsed: return` in learn()."""
        mock_parser.return_value.parse.return_value = {}

        ops = StaticRouting(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})


if __name__ == "__main__":
    unittest.main()
