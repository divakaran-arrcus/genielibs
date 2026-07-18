import unittest

from genie.libs.sdk.apis.arcos.route_policy import (
    get_routing_policy_defined_sets,
    get_prefix_set,
    get_string_set,
    get_tag_set,
    get_next_hop_set,
    get_routing_policy_policy_definitions,
    get_policy_definition,
    get_policy_statements,
    get_policy_statement,
    get_running_config_routing_policy,
)


class _DummyDevice:
    """Minimal dummy device that returns pre-canned parsed outputs."""

    def __init__(self, mapping):
        self._mapping = mapping

    def parse(self, command):  # pragma: no cover - simple helper
        return self._mapping[command]


# Sample normalized structures matching the ArcOS routing-policy parser model
# (see genie.libs.parser.arcos.show_routing_policy). The parsers emit
# hyphenated OpenConfig-style keys at every level, so the fixtures below use
# the same hyphenated convention that get.py's ``_parse_*`` helpers extract.

_DEFINED_SETS = {
    "routing-policy": {
        "defined-sets": {
            "prefix-sets": {
                "ps1": {
                    "name": "ps1",
                    "prefixes": [
                        {"ip-prefix": "10.0.0.0/8", "masklength-range": "8..32"},
                    ],
                }
            },
            "string-sets": {
                "ss1": {
                    "name": "ss1",
                    "strings": [
                        {"value": "foo", "match-type": "EXACT"},
                    ],
                }
            },
            "tag-sets": {
                "ts1": {
                    "name": "ts1",
                    "tags": [55],
                }
            },
            "next-hop-sets": {
                "nh1": {
                    "name": "nh1",
                    "addresses": ["SELF", "192.0.2.1"],
                }
            },
        }
    }
}

_POLICY_DEFS = {
    "routing-policy": {
        "policy-definitions": {
            "pol1": {
                "name": "pol1",
                "statements": {
                    "10": {
                        "name": "10",
                        "conditions": {
                            "match-prefix-set": {
                                "prefix-set": "ps1",
                                "match-set-options": "ANY",
                            },
                        },
                        "actions": {
                            "accept-route": True,
                        },
                    },
                },
            },
            "pol2": {
                "name": "pol2",
                "statements": {
                    "20": {
                        "name": "20",
                        "conditions": {
                            "match-tag-set": {
                                "match-set-options": "ANY",
                            },
                            "match-next-hop-set": {
                                "match-set-options": "ALL",
                            },
                        },
                        "actions": {
                            "igp-actions": {
                                "set-tag": 111,
                                "isis-actions": {"set-level": 2},
                            },
                            "reject-route": True,
                        },
                    },
                },
            },
        }
    }
}

_RUNNING_CFG = {
    "routing-policy": {
        "defined-sets": _DEFINED_SETS["routing-policy"]["defined-sets"],
        "policy-definitions": _POLICY_DEFS["routing-policy"]["policy-definitions"],
    }
}


class TestArcosRoutePolicyGetApis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = _DummyDevice(
            {
                "show routing-policy defined-sets": _DEFINED_SETS,
                "show routing-policy policy-definition": _POLICY_DEFS,
                "show running-config routing-policy": _RUNNING_CFG,
            }
        )

    def test_get_routing_policy_defined_sets(self):
        ds = get_routing_policy_defined_sets(self.device)
        self.assertIn("prefix-sets", ds)
        self.assertIn("string-sets", ds)
        self.assertIn("tag-sets", ds)
        self.assertIn("next-hop-sets", ds)
        self.assertIn("ps1", ds["prefix-sets"])

    def test_get_individual_defined_sets(self):
        ps = get_prefix_set(self.device, "ps1")
        self.assertIsNotNone(ps)
        self.assertEqual(ps["name"], "ps1")
        self.assertEqual(
            ps["prefixes"],
            [{"ip-prefix": "10.0.0.0/8", "masklength-range": "8..32"}],
        )

        ss = get_string_set(self.device, "ss1")
        self.assertIsNotNone(ss)
        self.assertEqual(ss["name"], "ss1")

        ts = get_tag_set(self.device, "ts1")
        self.assertIsNotNone(ts)
        self.assertEqual(ts["tags"], [55])

        nh = get_next_hop_set(self.device, "nh1")
        self.assertIsNotNone(nh)
        self.assertIn("SELF", nh["addresses"])

        self.assertIsNone(get_prefix_set(self.device, "does-not-exist"))

    def test_get_policy_definitions_and_statements(self):
        pdefs = get_routing_policy_policy_definitions(self.device)
        self.assertIn("pol1", pdefs)
        self.assertIn("pol2", pdefs)

        pol1 = get_policy_definition(self.device, "pol1")
        self.assertIsNotNone(pol1)
        stmts = get_policy_statements(self.device, "pol1")
        self.assertIn("10", stmts)

        stmt10 = get_policy_statement(self.device, "pol1", "10")
        self.assertIsNotNone(stmt10)
        acts = stmt10.get("actions", {})
        self.assertTrue(acts.get("accept-route"))

        # Negative lookup
        self.assertIsNone(get_policy_definition(self.device, "missing"))
        self.assertIsNone(get_policy_statement(self.device, "pol1", "999"))

    def test_get_running_config_routing_policy(self):
        rc = get_running_config_routing_policy(self.device)
        self.assertIn("defined-sets", rc)
        self.assertIn("policy-definitions", rc)
        self.assertIn("ps1", rc["defined-sets"].get("prefix-sets", {}))
        self.assertIn("pol2", rc["policy-definitions"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
