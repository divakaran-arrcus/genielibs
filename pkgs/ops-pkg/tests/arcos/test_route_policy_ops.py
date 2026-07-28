"""Unit tests for ArcOS RoutePolicy Ops model.

``genie.libs.ops.route_policy.arcos.route_policy.RoutePolicy.learn()``
obtains data by directly instantiating the two ArcOS parser classes
(``ShowRoutingPolicyDefinedSets`` and ``ShowRoutingPolicyPolicyDefinition``
from ``genie.libs.parser.arcos.show_routing_policy``) and calling
``.parse()`` on them -- it does NOT go through ``device.parse()``. Tests
patch those two classes on the ops module.

The parsers emit hyphenated OpenConfig-style keys
(``"routing-policy"`` -> ``"defined-sets"`` / ``"policy-definitions"``),
which ``learn()`` reads with matching hyphen keys and then re-exposes under
its own underscored contract keys ``self.info["defined_sets"]`` and
``self.info["policy_definitions"]``.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.ops.route_policy.arcos.route_policy import RoutePolicy

MOD = "genie.libs.ops.route_policy.arcos.route_policy"

# Realistic normalized output matching the real ArcOS parser schema
# (genie.libs.parser.arcos.show_routing_policy) -- note the hyphenated keys.
DEFINED_SETS_OUTPUT = {
    "routing-policy": {
        "defined-sets": {
            "prefix-sets": {
                "ps1": {
                    "name": "ps1",
                    "prefixes": [
                        {"ip-prefix": "10.0.0.0/8", "masklength-range": "8..32"}
                    ],
                }
            },
            "tag-sets": {"ts1": {"name": "ts1", "tags": [55]}},
        }
    }
}

POLICY_DEFS_OUTPUT = {
    "routing-policy": {
        "policy-definitions": {
            "pol1": {
                "name": "pol1",
                "statements": {
                    "10": {"name": "10", "actions": {"accept-route": True}},
                },
            }
        }
    }
}

EMPTY_DEFINED_SETS = {"routing-policy": {"defined-sets": {}}}
EMPTY_POLICY_DEFS = {"routing-policy": {"policy-definitions": {}}}


class TestRoutePolicyOps(unittest.TestCase):

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        self.device.os = "arcos"

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_basic_populates_info(self, mock_ds, mock_pd):
        """Basic case: both parsers return populated (hyphen-keyed) data;
        learn() must surface it under the underscored info contract, with
        nested values flowing through unchanged.
        """
        mock_ds.return_value.parse.return_value = DEFINED_SETS_OUTPUT
        mock_pd.return_value.parse.return_value = POLICY_DEFS_OUTPUT

        ops = RoutePolicy(device=self.device)
        ops.learn()

        # Contract keys are underscored on self.info
        self.assertIn("defined_sets", ops.info)
        self.assertIn("policy_definitions", ops.info)

        # defined_sets: nested value flows through
        prefix_sets = ops.info["defined_sets"]["prefix-sets"]
        self.assertIn("ps1", prefix_sets)
        self.assertEqual(prefix_sets["ps1"]["name"], "ps1")
        self.assertEqual(
            prefix_sets["ps1"]["prefixes"],
            [{"ip-prefix": "10.0.0.0/8", "masklength-range": "8..32"}],
        )
        self.assertEqual(
            ops.info["defined_sets"]["tag-sets"]["ts1"]["tags"], [55]
        )

        # policy_definitions: nested value flows through
        pol1 = ops.info["policy_definitions"]["pol1"]
        self.assertEqual(pol1["name"], "pol1")
        self.assertTrue(
            pol1["statements"]["10"]["actions"]["accept-route"]
        )

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_only_defined_sets(self, mock_ds, mock_pd):
        """Degrade: only defined-sets present -> info has defined_sets only,
        policy_definitions key omitted (empty -> falsy -> not stored).
        """
        mock_ds.return_value.parse.return_value = DEFINED_SETS_OUTPUT
        mock_pd.return_value.parse.return_value = EMPTY_POLICY_DEFS

        ops = RoutePolicy(device=self.device)
        ops.learn()

        self.assertIn("defined_sets", ops.info)
        self.assertNotIn("policy_definitions", ops.info)

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_only_policy_definitions(self, mock_ds, mock_pd):
        """Degrade: only policy-definitions present -> info has
        policy_definitions only, defined_sets key omitted.
        """
        mock_ds.return_value.parse.return_value = EMPTY_DEFINED_SETS
        mock_pd.return_value.parse.return_value = POLICY_DEFS_OUTPUT

        ops = RoutePolicy(device=self.device)
        ops.learn()

        self.assertIn("policy_definitions", ops.info)
        self.assertNotIn("defined_sets", ops.info)

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_empty_when_parsers_return_no_data(self, mock_ds, mock_pd):
        """Empty branch: both parsers return empty subtrees -> info is {}."""
        mock_ds.return_value.parse.return_value = EMPTY_DEFINED_SETS
        mock_pd.return_value.parse.return_value = EMPTY_POLICY_DEFS

        ops = RoutePolicy(device=self.device)
        ops.learn()

        self.assertEqual(ops.info, {})

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_propagates_defined_sets_parser_exception(
        self, mock_ds, mock_pd
    ):
        """learn() has no try/except around the parser calls -- an exception
        raised by ShowRoutingPolicyDefinedSets.parse() propagates directly.
        """
        mock_ds.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        mock_pd.return_value.parse.return_value = EMPTY_POLICY_DEFS

        ops = RoutePolicy(device=self.device)
        with self.assertRaises(SchemaEmptyParserError):
            ops.learn()

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_propagates_policy_definition_parser_exception(
        self, mock_ds, mock_pd
    ):
        """Same as above, but the second parser (policy-definitions) raises."""
        mock_ds.return_value.parse.return_value = EMPTY_DEFINED_SETS
        mock_pd.return_value.parse.side_effect = SchemaEmptyParserError("empty")

        ops = RoutePolicy(device=self.device)
        with self.assertRaises(SchemaEmptyParserError):
            ops.learn()

    @patch(f"{MOD}.ShowRoutingPolicyPolicyDefinition")
    @patch(f"{MOD}.ShowRoutingPolicyDefinedSets")
    def test_learn_calls_both_parsers_with_device(self, mock_ds, mock_pd):
        """learn() instantiates each parser with device=self.device."""
        mock_ds.return_value.parse.return_value = EMPTY_DEFINED_SETS
        mock_pd.return_value.parse.return_value = EMPTY_POLICY_DEFS

        ops = RoutePolicy(device=self.device)
        ops.learn()

        mock_ds.assert_called_once_with(device=self.device)
        mock_pd.assert_called_once_with(device=self.device)


if __name__ == "__main__":
    unittest.main()
