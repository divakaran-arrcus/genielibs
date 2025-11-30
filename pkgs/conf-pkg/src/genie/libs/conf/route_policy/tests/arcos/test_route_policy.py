# import python
import unittest

# import genie
from genie.tests.conf import TestCase
from genie.conf import Genie
from genie.conf.base import Testbed, Device
from genie.libs.conf.route_policy import RoutePolicy


class TestRoutePolicyArcos(TestCase):

    def test_defined_sets_and_basic_policies(self):
        """Verify ArcOS RoutePolicy config builder for defined-sets and
        basic policy-definitions including match_tag_set and IGP actions.
        """

        Genie.testbed = testbed = Testbed()
        dev = Device(testbed=testbed, name="rtr1", os="arcos")

        # Create a RoutePolicy feature. Name is not used directly by ArcOS
        # builder; routing_policy tree is attached to device_attr instead.
        rpl = RoutePolicy(name="dummy")
        dev.add_feature(rpl)

        # Attach a normalized routing_policy tree matching the ArcOS
        # parser/ops model.
        rpl.device_attr[dev].routing_policy = {
            "defined_sets": {
                "prefix_sets": {
                    "__IPV4_MARTIAN_PREFIX_SET__": {
                        "name": "__IPV4_MARTIAN_PREFIX_SET__",
                        "prefixes": [
                            {
                                "ip_prefix": "0.0.0.0/8",
                                "masklength_range": "8..32",
                            },
                            {
                                "ip_prefix": "127.0.0.0/8",
                                "masklength_range": "8..32",
                            },
                        ],
                    }
                },
                "next_hop_sets": {
                    "next-hop-set-all": {
                        "name": "next-hop-set-all",
                        "addresses": ["SELF", "10.1.1.1", "10:1:1::1"],
                    }
                },
            },
            "policy_definitions": {
                "pass-martians": {
                    "name": "pass-martians",
                    "statements": {
                        "10": {
                            "name": "10",
                            "conditions": {
                                "match_prefix_set": {
                                    "prefix_set": "__IPV4_MARTIAN_PREFIX_SET__",
                                    "match_set_options": "ANY",
                                },
                            },
                            "actions": {
                                "accept_route": True,
                            },
                        },
                    },
                },
                "tag-and-level": {
                    "name": "tag-and-level",
                    "statements": {
                        "20": {
                            "name": "20",
                            "conditions": {
                                "match_tag_set": {
                                    "tag_set": "pqr",
                                    "match_set_options": "ANY",
                                },
                                "match_next_hop_set": {
                                    "next_hop_set": "next-hop-set-all",
                                    "match_set_options": "ALL",
                                },
                            },
                            "actions": {
                                "igp_actions": {
                                    "set_tag": 111,
                                    "isis_actions": {
                                        "set_level": 2,
                                    },
                                },
                                "reject_route": True,
                            },
                        },
                    },
                },
            },
        }

        cfgs = rpl.build_config(apply=False)
        self.assertCountEqual(cfgs.keys(), [dev.name])

        cfg_str = str(cfgs[dev.name]).strip().splitlines()

        # Expect prefix-set and next-hop-set rendered
        self.assertIn(
            "routing-policy defined-sets prefix-set __IPV4_MARTIAN_PREFIX_SET__",
            cfg_str,
        )
        self.assertIn(" prefix 0.0.0.0/8 8..32", cfg_str)
        self.assertIn(" prefix 127.0.0.0/8 8..32", cfg_str)
        self.assertIn("routing-policy defined-sets next-hop-set next-hop-set-all", cfg_str)
        self.assertIn(" address [ SELF 10.1.1.1 10:1:1::1 ]", cfg_str)

        # Expect policy pass-martians with match-prefix-set and accept-route
        self.assertIn("routing-policy policy-definition pass-martians", cfg_str)
        self.assertIn(" statement 10", cfg_str)
        self.assertIn(
            "  conditions match-prefix-set prefix-set __IPV4_MARTIAN_PREFIX_SET__",
            cfg_str,
        )
        self.assertIn(
            "  conditions match-prefix-set match-set-options ANY",
            cfg_str,
        )
        self.assertIn("  actions accept-route", cfg_str)

        # Expect policy tag-and-level with match-tag-set, match-next-hop-set,
        # and igp-actions set-tag/set-level plus reject-route.
        self.assertIn("routing-policy policy-definition tag-and-level", cfg_str)
        self.assertIn(" statement 20", cfg_str)
        self.assertIn("  conditions match-tag-set tag-set pqr", cfg_str)
        self.assertIn("  conditions match-tag-set match-set-options ANY", cfg_str)
        self.assertIn(
            "  conditions match-next-hop-set next-hop-set next-hop-set-all",
            cfg_str,
        )
        self.assertIn(
            "  conditions match-next-hop-set match-set-options ALL",
            cfg_str,
        )
        self.assertIn("  actions igp-actions set-tag 111", cfg_str)
        self.assertIn("  actions igp-actions isis-actions set-level 2", cfg_str)
        self.assertIn("  actions reject-route", cfg_str)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
