"""Unit tests for the ArcOS configure APIs added by missing-API batch T2R-A.

Source: ``arcos_pyats_sanity/docs/config-coverage/01-isis-sr-srv6.md`` as corrected
by T2R-00. Proposal:
``orchestrator/proposals/pending/t2r_a_verified_hole_extensions.md``.

Covers the 4 configure/unconfigure pairs:
  - configure/unconfigure_routing_policy_next_hop_set        (audit row 210)
  - configure/unconfigure_routing_policy_match_next_hop_set  (audit row 211)
  - configure/unconfigure_bgp_global_import_policy            (audit row 287)
  - configure/unconfigure_bgp_global_export_policy            (audit row 258)

plus a regression test for the ``qppb`` bug fix.

These tests assert the CLI list each API *emits*. That every one of those lists is
also ACCEPTED by arcOS, and that each unconfigure actually removes the leaf, was
confirmed separately on rtr1 (arcOS docker, build R8.6.1.EFT1:Aug_17_26:8_9_AM,
2026-08-20) by commit + running-config read-back in both directions — see the
proposal's verification table.

Two knobs in the original batch scope have no API and no test here, deliberately:

  - ``srv6 locator ... mobile`` does not exist on this build (the locator context
    offers algorithm/anycast/function-length/locator-node-length/
    micro-segment-behavior-unode/prefix only). It is a not-on-build row, not an
    API gap.
  - ``srv6 locator ... anycast`` exists in the CLI tree but is documented in no
    adoc, and ``ISIS-SR-MPLS.adoc:90`` states "we dont support anycast SID".
    Not built rather than risk another known-dead API.

``TestDeliberatelyNotShipped`` guards both so a future session does not add them
back without re-checking the device.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.route_policy.configure import (
    configure_routing_policy_next_hop_set,
    unconfigure_routing_policy_next_hop_set,
    configure_routing_policy_match_next_hop_set,
    unconfigure_routing_policy_match_next_hop_set,
)
from genie.libs.sdk.apis.arcos.bgp.configure import (
    configure_bgp_global_import_policy,
    unconfigure_bgp_global_import_policy,
    configure_bgp_global_export_policy,
    unconfigure_bgp_global_export_policy,
)

BGP_CTX = "network-instance default protocol BGP default"


class ArcosT2raTestCase(unittest.TestCase):
    """Shared mock device setup."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        """Return the config list passed to device.configure."""
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


# ---------------------------------------------------------------------------
# route_policy — next-hop-set defined-set (audit row 210)
# ---------------------------------------------------------------------------


class TestRoutingPolicyNextHopSet(ArcosT2raTestCase):

    def test_configure_single_address_as_list(self):
        configure_routing_policy_next_hop_set(
            self.device, "NH1", ["cafe::/16"])
        self.assertEqual(
            self.emitted(),
            [
                "routing-policy defined-sets next-hop-set NH1",
                "address [ cafe::/16 ]",
                "!",
            ],
        )

    def test_configure_multiple_addresses_space_joined(self):
        configure_routing_policy_next_hop_set(
            self.device, "NH1", ["cafe::/16", "beef::/32", "SELF"])
        self.assertEqual(
            self.emitted()[1],
            "address [ cafe::/16 beef::/32 SELF ]",
        )

    def test_configure_accepts_bare_string(self):
        configure_routing_policy_next_hop_set(self.device, "NH1", "SELF")
        self.assertEqual(self.emitted()[1], "address [ SELF ]")

    def test_unconfigure(self):
        unconfigure_routing_policy_next_hop_set(self.device, "NH1")
        self.assertEqual(
            self.emitted(),
            ["no routing-policy defined-sets next-hop-set NH1", "!"],
        )

    def test_unconfigure_is_exact_inverse_of_configure(self):
        """The unconfigure must remove the same node the configure creates."""
        configure_routing_policy_next_hop_set(
            self.device, "NH1", ["cafe::/16"])
        created = self.emitted()[0]
        self.device.configure.reset_mock()
        unconfigure_routing_policy_next_hop_set(self.device, "NH1")
        self.assertEqual(self.emitted()[0], f"no {created}")


# ---------------------------------------------------------------------------
# route_policy — match-next-hop-set condition (audit row 211)
# ---------------------------------------------------------------------------


class TestRoutingPolicyMatchNextHopSet(ArcosT2raTestCase):

    def test_configure_defaults_to_any(self):
        configure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10", "NH1")
        self.assertEqual(
            self.emitted(),
            [
                "routing-policy policy-definition POL1",
                "statement 10",
                "conditions match-next-hop-set next-hop-set NH1",
                "conditions match-next-hop-set match-set-options ANY",
                "!",
            ],
        )

    def test_configure_honours_match_set_options(self):
        configure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10", "NH1", match_set_options="INVERT")
        self.assertIn(
            "conditions match-next-hop-set match-set-options INVERT",
            self.emitted(),
        )

    def test_set_name_goes_under_the_next_hop_set_subleaf(self):
        """Regression guard: the bare form is REJECTED by the device.

        ``conditions match-next-hop-set NH1`` (no ``next-hop-set`` keyword)
        produces a syntax error on arcOS and nothing lands. This is exactly the
        bug that shipped in qppb/configure.py:29.
        """
        configure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10", "NH1")
        emitted = self.emitted()
        self.assertIn("conditions match-next-hop-set next-hop-set NH1", emitted)
        self.assertNotIn("conditions match-next-hop-set NH1", emitted)

    def test_unconfigure_is_flat_and_container_level(self):
        """Flat form: a bare ``no`` after a submode line can hit the parent."""
        unconfigure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10")
        self.assertEqual(
            self.emitted(),
            [
                "no routing-policy policy-definition POL1 statement 10 "
                "conditions match-next-hop-set",
                "!",
            ],
        )

    def test_unconfigure_never_emits_bare_no_conditions(self):
        """``no conditions`` would wipe every condition on the statement."""
        unconfigure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10")
        for line in self.emitted():
            self.assertNotEqual(line.strip(), "no conditions")

    def test_does_not_emit_actions(self):
        """Unlike the qppb helper, this must not force accept-route."""
        configure_routing_policy_match_next_hop_set(
            self.device, "POL1", "10", "NH1")
        for line in self.emitted():
            self.assertNotIn("actions", line)


# ---------------------------------------------------------------------------
# bgp — global apply-policy (audit rows 258 + 287)
# ---------------------------------------------------------------------------


class TestBgpGlobalImportPolicy(ArcosT2raTestCase):

    def test_configure(self):
        configure_bgp_global_import_policy(
            self.device, "IPV4_UNICAST", ["X1"])
        self.assertEqual(
            self.emitted(),
            [
                BGP_CTX,
                "global afi-safi IPV4_UNICAST",
                "apply-policy import-policy [ X1 ]",
                "!",
            ],
        )

    def test_configure_multiple_policies_space_joined(self):
        configure_bgp_global_import_policy(
            self.device, "IPV4_UNICAST", ["X1", "X2"])
        self.assertEqual(
            self.emitted()[2], "apply-policy import-policy [ X1 X2 ]")

    def test_configure_accepts_bare_string(self):
        configure_bgp_global_import_policy(self.device, "IPV4_UNICAST", "X1")
        self.assertEqual(
            self.emitted()[2], "apply-policy import-policy [ X1 ]")

    def test_unconfigure(self):
        unconfigure_bgp_global_import_policy(self.device, "IPV4_UNICAST")
        self.assertEqual(
            self.emitted(),
            [
                BGP_CTX,
                "no global afi-safi IPV4_UNICAST apply-policy import-policy",
                "!",
            ],
        )

    def test_unconfigure_does_not_touch_export(self):
        unconfigure_bgp_global_import_policy(self.device, "IPV4_UNICAST")
        for line in self.emitted():
            self.assertNotIn("export-policy", line)

    def test_is_global_scope_not_neighbor_or_peer_group(self):
        configure_bgp_global_import_policy(
            self.device, "IPV4_UNICAST", ["X1"])
        for line in self.emitted():
            self.assertNotIn("neighbor", line)
            self.assertNotIn("peer-group", line)


class TestBgpGlobalExportPolicy(ArcosT2raTestCase):

    def test_configure(self):
        configure_bgp_global_export_policy(
            self.device, "IPV4_UNICAST", ["add-color"])
        self.assertEqual(
            self.emitted(),
            [
                BGP_CTX,
                "global afi-safi IPV4_UNICAST",
                "apply-policy export-policy [ add-color ]",
                "!",
            ],
        )

    def test_configure_multiple_policies_space_joined(self):
        configure_bgp_global_export_policy(
            self.device, "IPV4_UNICAST", ["X1", "X2"])
        self.assertEqual(
            self.emitted()[2], "apply-policy export-policy [ X1 X2 ]")

    def test_configure_accepts_bare_string(self):
        configure_bgp_global_export_policy(self.device, "IPV4_UNICAST", "X1")
        self.assertEqual(
            self.emitted()[2], "apply-policy export-policy [ X1 ]")

    def test_unconfigure(self):
        unconfigure_bgp_global_export_policy(self.device, "IPV4_UNICAST")
        self.assertEqual(
            self.emitted(),
            [
                BGP_CTX,
                "no global afi-safi IPV4_UNICAST apply-policy export-policy",
                "!",
            ],
        )

    def test_unconfigure_does_not_touch_import(self):
        unconfigure_bgp_global_export_policy(self.device, "IPV4_UNICAST")
        for line in self.emitted():
            self.assertNotIn("import-policy", line)

    def test_import_and_export_do_not_leak(self):
        """Each direction must emit only its own leaf."""
        configure_bgp_global_import_policy(
            self.device, "IPV4_UNICAST", ["X1"])
        self.assertNotIn(
            "apply-policy export-policy [ X1 ]", self.emitted())
        self.device.configure.reset_mock()
        configure_bgp_global_export_policy(
            self.device, "IPV4_UNICAST", ["X1"])
        self.assertNotIn(
            "apply-policy import-policy [ X1 ]", self.emitted())


# ---------------------------------------------------------------------------
# qppb — regression test for the shipped bug this batch fixes
# ---------------------------------------------------------------------------


class TestEmptyListIsRejectedNotSilentlyIgnored(ArcosT2raTestCase):
    """An empty list must raise, never emit ``[  ]``.

    Device-verified on rtr1 2026-08-25, build R8.6.1.EFT1:Aug_17_26:8_9_AM:
    in a single candidate, ``apply-policy import-policy [  ]`` was absent from
    ``show configuration`` while ``apply-policy export-policy [ P ]`` in the
    same session landed; likewise a next-hop-set whose only leaf was
    ``address [  ]`` did not materialise at all. arcOS accepts the empty form
    and silently configures nothing, so without this guard the caller gets a
    successful return and an unconfigured box.
    """

    def test_bgp_import_policy_empty_list_raises(self):
        with self.assertRaises(ValueError):
            configure_bgp_global_import_policy(
                self.device, "IPV4_UNICAST", [])
        self.device.configure.assert_not_called()

    def test_bgp_export_policy_empty_list_raises(self):
        with self.assertRaises(ValueError):
            configure_bgp_global_export_policy(
                self.device, "IPV4_UNICAST", [])
        self.device.configure.assert_not_called()

    def test_next_hop_set_empty_list_raises(self):
        with self.assertRaises(ValueError):
            configure_routing_policy_next_hop_set(self.device, "NH1", [])
        self.device.configure.assert_not_called()

    def test_empty_tuple_is_rejected_too(self):
        with self.assertRaises(ValueError):
            configure_bgp_global_import_policy(
                self.device, "IPV4_UNICAST", ())
        self.device.configure.assert_not_called()

    def test_no_emission_ever_contains_an_empty_bracket_pair(self):
        """The literal '[  ]' must not be reachable from any of the three."""
        configure_bgp_global_import_policy(self.device, "IPV4_UNICAST", ["P"])
        configure_bgp_global_export_policy(self.device, "IPV4_UNICAST", ["P"])
        configure_routing_policy_next_hop_set(self.device, "NH1", ["cafe::/16"])
        for call in self.device.configure.call_args_list:
            for line in call[0][0]:
                self.assertNotIn("[  ]", line)


class TestQppbMatchNextHopSetBugFix(ArcosT2raTestCase):
    """qppb/configure.py:29 emitted the set name without its sub-leaf.

    The bare form is rejected by arcOS with a syntax error and nothing lands,
    so ``configure_routing_policy_set_qos_class_id(..., match_next_hop_set=X)``
    raised SubCommandFailure unconditionally before this fix.
    """

    def test_emits_the_next_hop_set_keyword(self):
        from genie.libs.sdk.apis.arcos.qppb.configure import (
            configure_routing_policy_set_qos_class_id,
        )
        configure_routing_policy_set_qos_class_id(
            self.device, "P1", "10", 5, match_next_hop_set="NH1")
        emitted = self.emitted()
        self.assertIn(
            "conditions match-next-hop-set next-hop-set NH1", emitted)
        self.assertNotIn("conditions match-next-hop-set NH1", emitted)

    def test_exact_emission_full_line_list(self):
        """Pin every line qppb emits, not just the condition pair.

        The four lines outside the ``match_next_hop_set`` block had no pin at
        all, and this is the only test file importing qppb -- so mutating
        ``policy-definition``, ``statement``, ``actions accept-route`` or
        ``set-qos-class-id`` survived the whole suite.
        """
        from genie.libs.sdk.apis.arcos.qppb.configure import (
            configure_routing_policy_set_qos_class_id,
        )
        configure_routing_policy_set_qos_class_id(
            self.device, "P1", "10", 5, match_next_hop_set="NH1")
        self.assertEqual(
            self.emitted(),
            [
                "routing-policy policy-definition P1",
                "statement 10",
                "conditions match-next-hop-set next-hop-set NH1",
                "conditions match-next-hop-set match-set-options ANY",
                "actions accept-route",
                "actions bgp-actions set-qos-class-id 5",
                "!",
            ],
        )

    def test_exact_emission_without_next_hop_set(self):
        """Same pin for the no-condition path."""
        from genie.libs.sdk.apis.arcos.qppb.configure import (
            configure_routing_policy_set_qos_class_id,
        )
        configure_routing_policy_set_qos_class_id(self.device, "P1", "10", 5)
        self.assertEqual(
            self.emitted(),
            [
                "routing-policy policy-definition P1",
                "statement 10",
                "actions accept-route",
                "actions bgp-actions set-qos-class-id 5",
                "!",
            ],
        )

    def test_match_set_options_line_unchanged(self):
        from genie.libs.sdk.apis.arcos.qppb.configure import (
            configure_routing_policy_set_qos_class_id,
        )
        configure_routing_policy_set_qos_class_id(
            self.device, "P1", "10", 5, match_next_hop_set="NH1",
            match_set_options="ALL")
        self.assertIn(
            "conditions match-next-hop-set match-set-options ALL",
            self.emitted(),
        )

    def test_no_match_set_still_emits_no_condition_lines(self):
        from genie.libs.sdk.apis.arcos.qppb.configure import (
            configure_routing_policy_set_qos_class_id,
        )
        configure_routing_policy_set_qos_class_id(self.device, "P1", "10", 5)
        for line in self.emitted():
            self.assertNotIn("match-next-hop-set", line)


# ---------------------------------------------------------------------------
# Cross-cutting triad
# ---------------------------------------------------------------------------


ALL_FUNCS = [
    (configure_routing_policy_next_hop_set,
     {"set_name": "NH1", "addresses": ["cafe::/16"]}),
    (unconfigure_routing_policy_next_hop_set, {"set_name": "NH1"}),
    (configure_routing_policy_match_next_hop_set,
     {"policy_name": "POL1", "statement_name": "10", "next_hop_set": "NH1"}),
    (unconfigure_routing_policy_match_next_hop_set,
     {"policy_name": "POL1", "statement_name": "10"}),
    (configure_bgp_global_import_policy,
     {"afi_safi": "IPV4_UNICAST", "policies": ["X1"]}),
    (unconfigure_bgp_global_import_policy, {"afi_safi": "IPV4_UNICAST"}),
    (configure_bgp_global_export_policy,
     {"afi_safi": "IPV4_UNICAST", "policies": ["X1"]}),
    (unconfigure_bgp_global_export_policy, {"afi_safi": "IPV4_UNICAST"}),
]

BGP_FUNCS = [
    (configure_bgp_global_import_policy,
     {"afi_safi": "IPV4_UNICAST", "policies": ["X1"]}),
    (unconfigure_bgp_global_import_policy, {"afi_safi": "IPV4_UNICAST"}),
    (configure_bgp_global_export_policy,
     {"afi_safi": "IPV4_UNICAST", "policies": ["X1"]}),
    (unconfigure_bgp_global_export_policy, {"afi_safi": "IPV4_UNICAST"}),
]


class TestNoStrayExit(ArcosT2raTestCase):
    """A zero-submode leaf setter must emit no 'exit' — a 20-site invariant."""

    def test_no_function_emits_exit(self):
        for fn, kwargs in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                for line in self.device.configure.call_args[0][0]:
                    self.assertNotEqual(line.strip(), "exit")


class TestCustomInstanceRendering(ArcosT2raTestCase):
    """The BGP functions must honour a non-default network/protocol instance.

    The route_policy functions are global — ``routing-policy`` is not scoped by
    network-instance — so they take no instance parameter and are excluded here
    rather than asserted vacuously.
    """

    def test_bgp_functions_render_custom_instances(self):
        for fn, kwargs in BGP_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="vrf-1",
                   protocol_instance="bgp1", **kwargs)
                self.assertEqual(
                    self.device.configure.call_args[0][0][0],
                    "network-instance vrf-1 protocol BGP bgp1",
                )

    def test_route_policy_functions_take_no_instance_param(self):
        for fn in (configure_routing_policy_next_hop_set,
                   unconfigure_routing_policy_next_hop_set,
                   configure_routing_policy_match_next_hop_set,
                   unconfigure_routing_policy_match_next_hop_set):
            with self.subTest(fn=fn.__name__):
                params = inspect.signature(fn).parameters
                self.assertNotIn("network_instance", params)
                self.assertNotIn("protocol_instance", params)


class TestFailurePropagation(ArcosT2raTestCase):
    """Every function must propagate SubCommandFailure, not swallow it."""

    def test_all_eight_propagate(self):
        for fn, kwargs in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure(
                    "device said no")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)


class TestImportableFromModule(unittest.TestCase):
    """Every T2R-A function must be importable from its configure module.

    Note: unlike ``isis``, neither ``bgp`` nor ``qppb`` has an ``__init__.py``,
    and ``route_policy/__init__.py`` exports only ``get_*`` helpers — its 23
    pre-existing ``configure_*`` functions are not exported either. So this
    asserts module-path importability, which is how Genie discovers these APIs,
    rather than package-level export.
    """

    def test_route_policy_functions_importable(self):
        from genie.libs.sdk.apis.arcos.route_policy import configure as rp
        for name in (
            "configure_routing_policy_next_hop_set",
            "unconfigure_routing_policy_next_hop_set",
            "configure_routing_policy_match_next_hop_set",
            "unconfigure_routing_policy_match_next_hop_set",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(rp, name))

    def test_bgp_functions_importable(self):
        from genie.libs.sdk.apis.arcos.bgp import configure as bgp_cfg
        for name in (
            "configure_bgp_global_import_policy",
            "unconfigure_bgp_global_import_policy",
            "configure_bgp_global_export_policy",
            "unconfigure_bgp_global_export_policy",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(bgp_cfg, name))


class TestDeliberatelyNotShipped(unittest.TestCase):
    """Guards for the two knobs this batch deliberately did NOT ship."""

    def test_srv6_locator_has_no_mobile_kwarg(self):
        """``srv6 locator ... mobile`` is NOT ON THIS BUILD.

        Verified on rtr1 2026-08-20: ``srv6 locator <name> ?`` offers
        algorithm/anycast/function-length/locator-node-length/
        micro-segment-behavior-unode/prefix — no ``mobile``. Documented at
        SRv6_Mobile.adoc:637 as a GTP-encapsulation prerequisite, so the doc
        and the build disagree. Do not add this kwarg without re-probing the
        device first.
        """
        from genie.libs.sdk.apis.arcos.segment_routing.configure import (
            configure_srv6_locator,
        )
        self.assertNotIn(
            "mobile", inspect.signature(configure_srv6_locator).parameters)

    def test_srv6_locator_has_no_anycast_kwarg(self):
        """``anycast`` exists on the CLI node but was deliberately not built.

        It appears in no adoc, and ISIS-SR-MPLS.adoc:90 states "we dont support
        anycast SID". Shipping an API for an undocumented leaf next to an
        explicit not-supported note risks another known-dead function. Revisit
        only with documentation or a consuming test.
        """
        from genie.libs.sdk.apis.arcos.segment_routing.configure import (
            configure_srv6_locator,
        )
        self.assertNotIn(
            "anycast", inspect.signature(configure_srv6_locator).parameters)


if __name__ == "__main__":
    unittest.main()
