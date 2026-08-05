#!/usr/bin/env python3
"""Unit tests for arcOS routing-policy configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
``genie.libs.sdk.apis.arcos.route_policy.configure`` builds an arcOS CLI
config list (typically starting with the
``routing-policy defined-sets ...`` or ``routing-policy policy-definition
... statement ...`` context) and calls ``device.configure(config)``. Tests
mock ``device.configure`` and assert on a distinctive substring of the
emitted CLI.

The final ``TestCoverage`` class asserts that every public
configure_*/unconfigure_* function defined in the source module is
referenced by name somewhere in this test file's source -- an order-safe
source-scan (mirrors ``ospf/test_get_ospf.py``) rather than a runtime
call-recording registry, since the latter is order-dependent under
`python -m unittest`'s alphabetical class ordering.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.route_policy import configure as configure_mod
from genie.libs.sdk.apis.arcos.route_policy.configure import (
    # Prefix Set
    configure_prefix_set,
    unconfigure_prefix_set,
    configure_prefix_set_entry,
    unconfigure_prefix_set_entry,
    # Policy Definition
    configure_routing_policy,
    unconfigure_routing_policy,
    # Ext-Community Set
    configure_ext_community_set,
    unconfigure_ext_community_set,
    # Advanced Policy Statement (BGP conditions + actions)
    configure_routing_policy_bgp_actions,
    configure_routing_policy_bgp_conditions,
    # Community Set / AS-Path Set
    configure_community_set,
    unconfigure_community_set,
    configure_as_path_set,
    unconfigure_as_path_set,
    # Additional BGP Actions
    configure_routing_policy_set_community,
    configure_routing_policy_set_as_path_prepend,
    # Additional BGP Conditions
    configure_routing_policy_match_community_set,
    configure_routing_policy_match_as_path_set,
    # Large Community Set
    configure_large_community_set,
    unconfigure_large_community_set,
    # Remaining BGP Actions
    configure_routing_policy_set_route_origin,
    configure_routing_policy_adjust_local_pref,
    configure_routing_policy_set_aigp,
    configure_routing_policy_adjust_med,
    configure_routing_policy_drop_attr,
    # Remaining Conditions
    configure_routing_policy_match_interface,
    configure_routing_policy_match_large_community_set,
    configure_routing_policy_call_policy,
    # ISIS-Specific Actions
    configure_routing_policy_isis_actions_set_level,
    unconfigure_routing_policy_isis_actions_set_level,
    configure_routing_policy_isis_actions_set_metric,
    unconfigure_routing_policy_isis_actions_set_metric,
)


import genie.libs.sdk.apis.arcos.route_policy.configure as configure_module
def _all_configure_unconfigure_functions():
    """All public configure_*/unconfigure_* functions defined in the module."""
    return {
        name
        for name, obj in inspect.getmembers(configure_mod, inspect.isfunction)
        if obj.__module__ == configure_mod.__name__
        and (name.startswith("configure_") or name.startswith("unconfigure_"))
    }


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


# ---------------------------------------------------------------------------
# Prefix Set APIs
# ---------------------------------------------------------------------------


class TestPrefixSetApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_prefix_set(self):
        configure_prefix_set(self.d,
            "LEAK-L2-TO-L1",
            [
                {"prefix": "6.6.6.6/32", "masklength_range": "exact"},
                {"prefix": "10.0.0.0/8", "masklength_range": "8..24"},
            ],
        )
        c = self.d.cfg()
        self.assertIn("routing-policy defined-sets prefix-set LEAK-L2-TO-L1", c)
        self.assertIn("prefix 6.6.6.6/32 exact", c)
        self.assertIn("prefix 10.0.0.0/8 8..24", c)

    def test_unconfigure_prefix_set(self):
        unconfigure_prefix_set(self.d, "LEAK-L2-TO-L1")
        self.assertIn(
            "no routing-policy defined-sets prefix-set LEAK-L2-TO-L1", self.d.cfg()
        )

    def test_configure_prefix_set_entry(self):
        configure_prefix_set_entry(self.d, "MY-SET", "10.0.0.0/8", "8..24")
        c = self.d.cfg()
        self.assertIn("routing-policy defined-sets prefix-set MY-SET", c)
        self.assertIn("prefix 10.0.0.0/8 8..24", c)

    def test_unconfigure_prefix_set_entry(self):
        unconfigure_prefix_set_entry(self.d, "MY-SET", "10.0.0.0/8", "8..24")
        self.assertIn("no prefix 10.0.0.0/8 8..24", self.d.cfg())


# ---------------------------------------------------------------------------
# Policy Definition APIs
# ---------------------------------------------------------------------------


class TestPolicyDefinitionApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy(self):
        configure_routing_policy(self.d, "ALLOW-ALL")
        c = self.d.cfg()
        self.assertIn("routing-policy policy-definition ALLOW-ALL", c)
        self.assertIn("statement pass-all", c)
        self.assertIn("actions accept-route", c)

    def test_configure_routing_policy_with_match(self):
        configure_routing_policy(self.d,
            "MATCH-LEAKED",
            action="accept-route",
            statement_name="10",
            match_prefix_set="LEAK-PREFIXES",
            match_set_options="ANY",
        )
        c = self.d.cfg()
        self.assertIn(
            "conditions match-prefix-set prefix-set LEAK-PREFIXES", c
        )
        self.assertIn(
            "conditions match-prefix-set match-set-options ANY", c
        )

    def test_unconfigure_routing_policy(self):
        unconfigure_routing_policy(self.d, "ALLOW-ALL")
        self.assertIn(
            "no routing-policy policy-definition ALLOW-ALL", self.d.cfg()
        )


# ---------------------------------------------------------------------------
# Ext-Community / Community / AS-Path / Large-Community Set APIs
# ---------------------------------------------------------------------------


class TestSetApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ext_community_set(self):
        configure_ext_community_set(self.d,
            "RT-SET-1",
            ["route-target:2001:2001"],
        )
        c = self.d.cfg()
        self.assertIn(
            "routing-policy defined-sets bgp-defined-sets ext-community-set RT-SET-1",
            c,
        )
        self.assertIn("ext-community-member [ route-target:2001:2001 ]", c)

    def test_unconfigure_ext_community_set(self):
        unconfigure_ext_community_set(self.d, "RT-SET-1")
        self.assertIn(
            "no routing-policy defined-sets bgp-defined-sets "
            "ext-community-set RT-SET-1",
            self.d.cfg(),
        )

    def test_configure_community_set(self):
        configure_community_set(self.d, "COMM-SET-1", ["65001:100"])
        c = self.d.cfg()
        self.assertIn(
            "routing-policy defined-sets bgp-defined-sets community-set COMM-SET-1",
            c,
        )
        self.assertIn("community-member [ 65001:100 ]", c)

    def test_unconfigure_community_set(self):
        unconfigure_community_set(self.d, "COMM-SET-1")
        self.assertIn(
            "no routing-policy defined-sets bgp-defined-sets community-set "
            "COMM-SET-1",
            self.d.cfg(),
        )

    def test_configure_as_path_set(self):
        configure_as_path_set(self.d, "AS-SET-1", ["^65001_"])
        c = self.d.cfg()
        self.assertIn(
            "routing-policy defined-sets bgp-defined-sets as-path-set AS-SET-1",
            c,
        )
        self.assertIn("as-path-set-member [ ^65001_ ]", c)

    def test_unconfigure_as_path_set(self):
        unconfigure_as_path_set(self.d, "AS-SET-1")
        self.assertIn(
            "no routing-policy defined-sets bgp-defined-sets as-path-set "
            "AS-SET-1",
            self.d.cfg(),
        )

    def test_configure_large_community_set(self):
        configure_large_community_set(self.d, "LC-SET-1", ["65001:100:200"])
        c = self.d.cfg()
        self.assertIn(
            "routing-policy defined-sets bgp-defined-sets large-community-set "
            "LC-SET-1",
            c,
        )
        self.assertIn("large-community-member [ 65001:100:200 ]", c)

    def test_unconfigure_large_community_set(self):
        unconfigure_large_community_set(self.d, "LC-SET-1")
        self.assertIn(
            "no routing-policy defined-sets bgp-defined-sets "
            "large-community-set LC-SET-1",
            self.d.cfg(),
        )


# ---------------------------------------------------------------------------
# BGP Actions + Conditions on a policy statement
# ---------------------------------------------------------------------------


class TestBgpActionsAndConditionsApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy_bgp_actions(self):
        configure_routing_policy_bgp_actions(self.d,
            "MY-POLICY",
            "10",
            set_local_pref=220,
            set_med=50,
            set_next_hop="SELF",
            set_ext_community_method="INLINE",
            set_ext_community_options="ADD",
            set_ext_community_inline=["route-target:1:1"],
            set_ext_community_ref="RT-SET-1",
        )
        c = self.d.cfg()
        self.assertIn("routing-policy policy-definition MY-POLICY", c)
        self.assertIn("statement 10", c)
        self.assertIn("actions bgp-actions set-local-pref 220", c)
        self.assertIn("actions bgp-actions set-med 50", c)
        self.assertIn("actions bgp-actions set-next-hop SELF", c)
        self.assertIn(
            "actions bgp-actions set-ext-community method INLINE", c
        )
        self.assertIn(
            "actions bgp-actions set-ext-community options ADD", c
        )
        self.assertIn(
            "actions bgp-actions set-ext-community inline "
            "ext-communities [ route-target:1:1 ]",
            c,
        )
        self.assertIn(
            "actions bgp-actions set-ext-community reference "
            "ext-community-set-ref RT-SET-1",
            c,
        )

    def test_configure_routing_policy_bgp_conditions(self):
        configure_routing_policy_bgp_conditions(self.d,
            "MY-POLICY",
            "10",
            match_ext_community_set="RT-SET-1",
            match_set_options="ANY",
        )
        c = self.d.cfg()
        self.assertIn(
            "conditions bgp-conditions match-ext-community-set "
            "ext-community-set RT-SET-1",
            c,
        )
        self.assertIn(
            "conditions bgp-conditions match-ext-community-set "
            "match-set-options ANY",
            c,
        )


# ---------------------------------------------------------------------------
# Additional BGP Actions / Conditions
# ---------------------------------------------------------------------------


class TestAdditionalBgpActionsAndConditionsApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy_set_community(self):
        configure_routing_policy_set_community(self.d,
            "MY-POLICY",
            "10",
            method="INLINE",
            options="ADD",
            inline_communities=["65001:100"],
        )
        c = self.d.cfg()
        self.assertIn("actions bgp-actions set-community method INLINE", c)
        self.assertIn("actions bgp-actions set-community options ADD", c)
        self.assertIn(
            "actions bgp-actions set-community inline communities [ 65001:100 ]",
            c,
        )

    def test_configure_routing_policy_set_community_reference(self):
        configure_routing_policy_set_community(self.d,
            "MY-POLICY",
            "10",
            method="REFERENCE",
            options="REPLACE",
            reference_set="COMM-SET-1",
        )
        c = self.d.cfg()
        self.assertIn(
            "actions bgp-actions set-community reference "
            "community-set-ref COMM-SET-1",
            c,
        )

    def test_configure_routing_policy_set_as_path_prepend(self):
        configure_routing_policy_set_as_path_prepend(self.d,
            "MY-POLICY",
            "10",
            3,
        )
        self.assertIn(
            "actions bgp-actions set-as-path-prepend repeat-n 3", self.d.cfg()
        )

    def test_configure_routing_policy_match_community_set(self):
        configure_routing_policy_match_community_set(self.d,
            "MY-POLICY",
            "10",
            "COMM-SET-1",
            match_set_options="ANY",
        )
        c = self.d.cfg()
        self.assertIn(
            "conditions bgp-conditions match-community-set "
            "community-set COMM-SET-1",
            c,
        )
        self.assertIn(
            "conditions bgp-conditions match-community-set "
            "match-set-options ANY",
            c,
        )

    def test_configure_routing_policy_match_as_path_set(self):
        configure_routing_policy_match_as_path_set(self.d,
            "MY-POLICY",
            "10",
            "AS-SET-1",
            match_set_options="ALL",
        )
        c = self.d.cfg()
        self.assertIn(
            "conditions bgp-conditions match-as-path-set as-path-set AS-SET-1",
            c,
        )
        self.assertIn(
            "conditions bgp-conditions match-as-path-set match-set-options ALL",
            c,
        )


# ---------------------------------------------------------------------------
# Remaining BGP Actions
# ---------------------------------------------------------------------------


class TestRemainingBgpActionsApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy_set_route_origin(self):
        configure_routing_policy_set_route_origin(self.d,
            "MY-POLICY",
            "10",
            "IGP",
        )
        self.assertIn("actions bgp-actions set-route-origin IGP", self.d.cfg())

    def test_configure_routing_policy_adjust_local_pref(self):
        configure_routing_policy_adjust_local_pref(self.d,
            "MY-POLICY",
            "10",
            -50,
        )
        self.assertIn(
            "actions bgp-actions adjust-local-pref offset -50", self.d.cfg()
        )

    def test_configure_routing_policy_set_aigp(self):
        configure_routing_policy_set_aigp(self.d, "MY-POLICY", "10", 1000)
        self.assertIn("actions bgp-actions set-aigp 1000", self.d.cfg())

    def test_configure_routing_policy_adjust_med(self):
        configure_routing_policy_adjust_med(self.d, "MY-POLICY", "10", 25)
        self.assertIn(
            "actions bgp-actions adjust-med offset 25", self.d.cfg()
        )

    def test_configure_routing_policy_drop_attr(self):
        configure_routing_policy_drop_attr(self.d,
            "MY-POLICY",
            "10",
            [4, 5, 16],
        )
        self.assertIn(
            "actions bgp-actions drop-attr [ 4 5 16 ]", self.d.cfg()
        )


# ---------------------------------------------------------------------------
# Remaining Conditions
# ---------------------------------------------------------------------------


class TestRemainingConditionsApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy_match_interface(self):
        configure_routing_policy_match_interface(self.d,
            "MY-POLICY",
            "10",
            "ethernet-1/1",
        )
        self.assertIn(
            "conditions match-interface interface ethernet-1/1", self.d.cfg()
        )

    def test_configure_routing_policy_match_large_community_set(self):
        configure_routing_policy_match_large_community_set(self.d,
            "MY-POLICY",
            "10",
            "LC-SET-1",
            match_set_options="ANY",
        )
        c = self.d.cfg()
        self.assertIn(
            "conditions bgp-conditions match-large-community-set "
            "large-community-set LC-SET-1",
            c,
        )
        self.assertIn(
            "conditions bgp-conditions match-large-community-set "
            "match-set-options ANY",
            c,
        )

    def test_configure_routing_policy_call_policy(self):
        configure_routing_policy_call_policy(self.d,
            "MY-POLICY",
            "10",
            "CALLED-POLICY",
        )
        self.assertIn("conditions call-policy CALLED-POLICY", self.d.cfg())


# ---------------------------------------------------------------------------
# ISIS-Specific Actions
# ---------------------------------------------------------------------------


class TestIsisActionsApis(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_routing_policy_isis_actions_set_level(self):
        configure_routing_policy_isis_actions_set_level(self.d,
            "v4-statics-fltr",
            "10",
            1,
        )
        c = self.d.cfg()
        self.assertIn("routing-policy policy-definition v4-statics-fltr", c)
        self.assertIn("actions igp-actions isis-actions set-level 1", c)

    def test_configure_routing_policy_isis_actions_set_level_invalid(self):
        with self.assertRaises(ValueError):
            configure_routing_policy_isis_actions_set_level(
                self.d, "v4-statics-fltr", "10", 3
            )

    def test_unconfigure_routing_policy_isis_actions_set_level(self):
        unconfigure_routing_policy_isis_actions_set_level(self.d,
            "v4-statics-fltr",
            "10",
        )
        self.assertIn(
            "no actions igp-actions isis-actions set-level", self.d.cfg()
        )

    def test_configure_routing_policy_isis_actions_set_metric(self):
        configure_routing_policy_isis_actions_set_metric(self.d,
            "v4-statics-fltr",
            "10",
            metric=50,
        )
        self.assertIn(
            "actions igp-actions isis-actions set-metric 50", self.d.cfg()
        )

    def test_unconfigure_routing_policy_isis_actions_set_metric(self):
        unconfigure_routing_policy_isis_actions_set_metric(self.d,
            "v4-statics-fltr",
            "10",
        )
        self.assertIn(
            "no actions igp-actions isis-actions set-metric", self.d.cfg()
        )


# ---------------------------------------------------------------------------
# SubCommandFailure propagation -- one per function
# ---------------------------------------------------------------------------


class TestSubCommandFailurePropagation(unittest.TestCase):
    """Every configure_*/unconfigure_* function wraps device.configure() in a
    try/except SubCommandFailure and re-raises. Drive each function with a
    device whose .configure() raises, and assert SubCommandFailure escapes.
    """

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_all_functions_propagate_subcommandfailure(self):
        cases = [
            (configure_prefix_set, ("SET1", [{"prefix": "1.1.1.1/32"}]), {}),
            (unconfigure_prefix_set, ("SET1",), {}),
            (configure_prefix_set_entry, ("SET1", "1.1.1.1/32"), {}),
            (unconfigure_prefix_set_entry, ("SET1", "1.1.1.1/32"), {}),
            (configure_routing_policy, ("POL1",), {}),
            (unconfigure_routing_policy, ("POL1",), {}),
            (configure_ext_community_set, ("ECS1", ["rt:1:1"]), {}),
            (unconfigure_ext_community_set, ("ECS1",), {}),
            (configure_routing_policy_bgp_actions, ("POL1", "10"), {"set_local_pref": 100}),
            (configure_routing_policy_bgp_conditions, ("POL1", "10"), {"match_ext_community_set": "ECS1"}),
            (configure_community_set, ("CS1", ["65001:1"]), {}),
            (unconfigure_community_set, ("CS1",), {}),
            (configure_as_path_set, ("AS1", ["^1_"]), {}),
            (unconfigure_as_path_set, ("AS1",), {}),
            (configure_routing_policy_set_community, ("POL1", "10"), {"inline_communities": ["65001:1"]}),
            (configure_routing_policy_set_as_path_prepend, ("POL1", "10", 2), {}),
            (configure_routing_policy_match_community_set, ("POL1", "10", "CS1"), {}),
            (configure_routing_policy_match_as_path_set, ("POL1", "10", "AS1"), {}),
            (configure_large_community_set, ("LCS1", ["1:1:1"]), {}),
            (unconfigure_large_community_set, ("LCS1",), {}),
            (configure_routing_policy_set_route_origin, ("POL1", "10", "IGP"), {}),
            (configure_routing_policy_adjust_local_pref, ("POL1", "10", 10), {}),
            (configure_routing_policy_set_aigp, ("POL1", "10", 5), {}),
            (configure_routing_policy_adjust_med, ("POL1", "10", 5), {}),
            (configure_routing_policy_drop_attr, ("POL1", "10", [4]), {}),
            (configure_routing_policy_match_interface, ("POL1", "10", "eth-1/1"), {}),
            (configure_routing_policy_match_large_community_set, ("POL1", "10", "LCS1"), {}),
            (configure_routing_policy_call_policy, ("POL1", "10", "POL2"), {}),
            (configure_routing_policy_isis_actions_set_level, ("POL1", "10", 1), {}),
            (unconfigure_routing_policy_isis_actions_set_level, ("POL1", "10"), {}),
            (configure_routing_policy_isis_actions_set_metric, ("POL1", "10"), {"metric": 5}),
            (unconfigure_routing_policy_isis_actions_set_metric, ("POL1", "10"), {}),
        ]
        for func, args, kwargs in cases:
            with self.subTest(func=func.__name__):
                with self.assertRaises(SubCommandFailure):
                    func(self.d, *args, **kwargs)


# ---------------------------------------------------------------------------
# Coverage check: machine-checked, order-safe under both pytest and
# `python -m unittest` (alphabetical class order) since it scans this file's
# own source text instead of relying on a runtime call-recording registry
# populated by other test classes running first.
# ---------------------------------------------------------------------------


class TestCoverage(unittest.TestCase):
    def test_all_configure_functions_exercised(self):
        with open(__file__, "r") as f:
            source = f.read()

        expected = _all_configure_unconfigure_functions()
        missing = [n for n in expected if n not in source]
        self.assertEqual(
            missing,
            [],
            f"configure/unconfigure functions never referenced in this test "
            f"file: {sorted(missing)}",
        )
        # Sanity: the reference census counted 32 configure_/unconfigure_ fns.
        self.assertEqual(len(expected), 32)




class TestRoutePolicyConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure/unconfigure function in
    route_policy/configure.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(configure_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == configure_module.__name__
            and (name.startswith("configure_") or name.startswith("unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered route_policy configure functions: {missing}")
if __name__ == "__main__":
    unittest.main()
