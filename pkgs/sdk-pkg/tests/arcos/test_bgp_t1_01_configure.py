"""Unit tests for ArcOS BGP configure APIs added by missing-API batch T1-01.

Source: ``arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md``.
Proposal: ``orchestrator/proposals/approved/bgp_api_t1_01_session_transport.md``.

Covers 12 configure/unconfigure pairs (session, transport and security knobs) in
``genie.libs.sdk.apis.arcos.bgp.configure``.

These tests assert the CLI list each API *emits*. That every list is also ACCEPTED
by arcOS, and that each unconfigure actually removes the leaf, was confirmed
separately on rtr1 (2026-08-17) by commit + running-config read-back in both
directions — see the proposal's verification table.

Coverage shape follows the T1-04 super-review (R1): custom-instance rendering and
SubCommandFailure propagation are asserted across ALL functions from the start,
rather than for a sampled few.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.bgp.configure import (
    BGP_REMOVE_PRIVATE_AS_MODES,
    configure_bgp_neighbor_ebgp_local_as,
    unconfigure_bgp_neighbor_ebgp_local_as,
    configure_bgp_neighbor_remove_private_as,
    unconfigure_bgp_neighbor_remove_private_as,
    configure_bgp_neighbor_as_path_options,
    unconfigure_bgp_neighbor_as_path_options,
    configure_bgp_neighbor_ebgp_multihop,
    unconfigure_bgp_neighbor_ebgp_multihop,
    configure_bgp_neighbor_ttl_security_hops,
    unconfigure_bgp_neighbor_ttl_security_hops,
    configure_bgp_neighbor_auth_password,
    unconfigure_bgp_neighbor_auth_password,
    configure_bgp_neighbor_dscp,
    unconfigure_bgp_neighbor_dscp,
    configure_bgp_neighbor_transport_tcp_mss,
    unconfigure_bgp_neighbor_transport_tcp_mss,
    configure_bgp_neighbor_transport_passive_mode,
    unconfigure_bgp_neighbor_transport_passive_mode,
    configure_bgp_neighbor_enforce_first_as,
    unconfigure_bgp_neighbor_enforce_first_as,
    configure_bgp_neighbor_disable_fast_deactivation,
    unconfigure_bgp_neighbor_disable_fast_deactivation,
    configure_bgp_neighbor_inbound_soft_reconfiguration,
    unconfigure_bgp_neighbor_inbound_soft_reconfiguration,
)

NBR = "10.1.1.2"
CTX = f"network-instance default protocol BGP default neighbor {NBR}"

# (function, kwargs) for every function in the batch — drives the cross-cutting suites.
ALL_FUNCS = [
    (configure_bgp_neighbor_ebgp_local_as, {"local_as": 58067}),
    (unconfigure_bgp_neighbor_ebgp_local_as, {}),
    (configure_bgp_neighbor_remove_private_as, {"mode": "PRIVATE_AS_REMOVE_ALL"}),
    (unconfigure_bgp_neighbor_remove_private_as, {}),
    (configure_bgp_neighbor_as_path_options, {"allow_own_as": 3}),
    (unconfigure_bgp_neighbor_as_path_options, {}),
    (configure_bgp_neighbor_ebgp_multihop, {"multihop_ttl": 5}),
    (unconfigure_bgp_neighbor_ebgp_multihop, {}),
    (configure_bgp_neighbor_ttl_security_hops, {"hops": 1}),
    (unconfigure_bgp_neighbor_ttl_security_hops, {}),
    (configure_bgp_neighbor_auth_password, {"password": "arrcus"}),
    (unconfigure_bgp_neighbor_auth_password, {}),
    (configure_bgp_neighbor_dscp, {"dscp": 56}),
    (unconfigure_bgp_neighbor_dscp, {}),
    (configure_bgp_neighbor_transport_tcp_mss, {"tcp_mss": 1000}),
    (unconfigure_bgp_neighbor_transport_tcp_mss, {}),
    (configure_bgp_neighbor_transport_passive_mode, {}),
    (unconfigure_bgp_neighbor_transport_passive_mode, {}),
    (configure_bgp_neighbor_enforce_first_as, {}),
    (unconfigure_bgp_neighbor_enforce_first_as, {}),
    (configure_bgp_neighbor_disable_fast_deactivation, {}),
    (unconfigure_bgp_neighbor_disable_fast_deactivation, {}),
    (configure_bgp_neighbor_inbound_soft_reconfiguration, {"afi_safi": "IPV4_UNICAST"}),
    (unconfigure_bgp_neighbor_inbound_soft_reconfiguration, {"afi_safi": "IPV4_UNICAST"}),
]


class ArcosBgpConfigureTestCase(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestEbgpLocalAs(ArcosBgpConfigureTestCase):

    def test_configure_minimal(self):
        configure_bgp_neighbor_ebgp_local_as(self.device, neighbor=NBR, local_as=58067)
        self.assertEqual(self.emitted(), [CTX, "ebgp-local-as local-as 58067", "!"])

    def test_configure_all_sub_leaves(self):
        configure_bgp_neighbor_ebgp_local_as(
            self.device, neighbor=NBR, local_as=58067,
            no_prepend=True, replace_as=True, dual_as=False)
        self.assertEqual(self.emitted(), [
            CTX,
            "ebgp-local-as local-as 58067",
            "ebgp-local-as no-prepend true",
            "ebgp-local-as replace-as true",
            "ebgp-local-as dual-as false",
            "!",
        ])

    def test_dual_as_false_is_emitted_not_skipped(self):
        """False must be emitted; only None means 'leave unset'."""
        configure_bgp_neighbor_ebgp_local_as(
            self.device, neighbor=NBR, local_as=1, dual_as=False)
        self.assertIn("ebgp-local-as dual-as false", self.emitted())

    def test_unconfigure(self):
        unconfigure_bgp_neighbor_ebgp_local_as(self.device, neighbor=NBR)
        self.assertEqual(self.emitted(), [CTX, "no ebgp-local-as", "!"])


class TestRemovePrivateAs(ArcosBgpConfigureTestCase):

    def test_configure_remove_all(self):
        configure_bgp_neighbor_remove_private_as(
            self.device, neighbor=NBR, mode="PRIVATE_AS_REMOVE_ALL")
        self.assertEqual(
            self.emitted(), [CTX, "remove-private-as PRIVATE_AS_REMOVE_ALL", "!"])

    def test_configure_replace_all(self):
        configure_bgp_neighbor_remove_private_as(
            self.device, neighbor=NBR, mode="PRIVATE_AS_REPLACE_ALL")
        self.assertIn("remove-private-as PRIVATE_AS_REPLACE_ALL", self.emitted())

    def test_invalid_mode_raises_before_configure(self):
        """arcOS silently accepts some bad values — reject in Python instead."""
        for bad in ("remove-all", "PRIVATE_AS_REMOVE", "", None):
            with self.subTest(mode=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    configure_bgp_neighbor_remove_private_as(
                        self.device, neighbor=NBR, mode=bad)
                self.device.configure.assert_not_called()

    def test_every_documented_mode_is_accepted(self):
        for mode in BGP_REMOVE_PRIVATE_AS_MODES:
            with self.subTest(mode=mode):
                self.device.configure.reset_mock()
                configure_bgp_neighbor_remove_private_as(
                    self.device, neighbor=NBR, mode=mode)

    def test_unconfigure(self):
        unconfigure_bgp_neighbor_remove_private_as(self.device, neighbor=NBR)
        self.assertEqual(self.emitted(), [CTX, "no remove-private-as", "!"])


class TestAsPathOptions(ArcosBgpConfigureTestCase):

    def test_allow_own_as_only(self):
        configure_bgp_neighbor_as_path_options(
            self.device, neighbor=NBR, allow_own_as=3)
        self.assertEqual(self.emitted(), [CTX, "as-path-options allow-own-as 3", "!"])

    def test_both_options(self):
        configure_bgp_neighbor_as_path_options(
            self.device, neighbor=NBR, allow_own_as=3, replace_peer_as=True)
        self.assertEqual(self.emitted(), [
            CTX,
            "as-path-options allow-own-as 3",
            "as-path-options replace-peer-as true",
            "!",
        ])

    def test_no_options_raises_before_configure(self):
        """A call with neither option would emit a context and nothing else."""
        with self.assertRaises(ValueError):
            configure_bgp_neighbor_as_path_options(self.device, neighbor=NBR)
        self.device.configure.assert_not_called()

    def test_unconfigure(self):
        unconfigure_bgp_neighbor_as_path_options(self.device, neighbor=NBR)
        self.assertEqual(self.emitted(), [CTX, "no as-path-options", "!"])


class TestSimpleLeaves(ArcosBgpConfigureTestCase):
    """The eight single-leaf pairs, asserted as exact emitted lists."""

    CASES = [
        (configure_bgp_neighbor_ebgp_multihop, {"multihop_ttl": 5},
         "ebgp-multihop multihop-ttl 5"),
        (configure_bgp_neighbor_ttl_security_hops, {"hops": 1},
         "ttl-security-hops 1"),
        (configure_bgp_neighbor_auth_password, {"password": "arrcus"},
         "auth-password arrcus"),
        (configure_bgp_neighbor_dscp, {"dscp": 56}, "dscp 56"),
        (configure_bgp_neighbor_transport_tcp_mss, {"tcp_mss": 1000},
         "transport tcp-mss 1000"),
        (configure_bgp_neighbor_transport_passive_mode, {"enabled": True},
         "transport passive-mode true"),
        (configure_bgp_neighbor_enforce_first_as, {"enabled": False},
         "enforce-first-as false"),
        (configure_bgp_neighbor_disable_fast_deactivation, {"disabled": True},
         "disable-fast-deactivation true"),
    ]

    UNCONFIGURE_CASES = [
        (unconfigure_bgp_neighbor_ebgp_multihop, "no ebgp-multihop"),
        (unconfigure_bgp_neighbor_ttl_security_hops, "no ttl-security-hops"),
        (unconfigure_bgp_neighbor_auth_password, "no auth-password"),
        (unconfigure_bgp_neighbor_dscp, "no dscp"),
        (unconfigure_bgp_neighbor_transport_tcp_mss, "no transport tcp-mss"),
        (unconfigure_bgp_neighbor_transport_passive_mode, "no transport passive-mode"),
        (unconfigure_bgp_neighbor_enforce_first_as, "no enforce-first-as"),
        (unconfigure_bgp_neighbor_disable_fast_deactivation,
         "no disable-fast-deactivation"),
    ]

    def test_configure_lists(self):
        for fn, kwargs, line in self.CASES:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, neighbor=NBR, **kwargs)
                self.assertEqual(self.emitted(), [CTX, line, "!"])

    def test_unconfigure_lists(self):
        for fn, line in self.UNCONFIGURE_CASES:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, neighbor=NBR)
                self.assertEqual(self.emitted(), [CTX, line, "!"])

    def test_disable_fast_deactivation_inverted_sense(self):
        """The leaf disables a feature that is ON by default — disabled=False
        must emit 'false', re-enabling fast deactivation."""
        configure_bgp_neighbor_disable_fast_deactivation(
            self.device, neighbor=NBR, disabled=False)
        self.assertIn("disable-fast-deactivation false", self.emitted())


class TestDscpValidation(ArcosBgpConfigureTestCase):
    """The device documents dscp <0..63>; arcOS silently accepts out-of-range
    values, so the bound is enforced in Python before the device is touched."""

    def test_valid_boundaries_accepted(self):
        for v in (0, 1, 56, 63):
            with self.subTest(dscp=v):
                self.device.configure.reset_mock()
                configure_bgp_neighbor_dscp(self.device, neighbor=NBR, dscp=v)
                self.assertEqual(self.emitted(), [CTX, f"dscp {v}", "!"])

    def test_out_of_range_and_wrong_type_rejected(self):
        for bad in (-1, 64, 255, "56", 3.5, None, True):
            with self.subTest(dscp=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    configure_bgp_neighbor_dscp(self.device, neighbor=NBR, dscp=bad)
                self.device.configure.assert_not_called()


class TestInboundSoftReconfiguration(ArcosBgpConfigureTestCase):

    def test_configure(self):
        configure_bgp_neighbor_inbound_soft_reconfiguration(
            self.device, neighbor=NBR, afi_safi="IPV4_UNICAST")
        self.assertEqual(self.emitted(), [
            CTX,
            "afi-safi IPV4_UNICAST inbound-soft-reconfiguration true",
            "!",
        ])

    def test_unconfigure(self):
        unconfigure_bgp_neighbor_inbound_soft_reconfiguration(
            self.device, neighbor=NBR, afi_safi="IPV6_UNICAST")
        self.assertEqual(self.emitted(), [
            CTX,
            "no afi-safi IPV6_UNICAST inbound-soft-reconfiguration",
            "!",
        ])

    def test_single_line_never_enters_afi_safi_submode(self):
        """A bare 'afi-safi X' line would enter the submode and leave the
        following leaf ambiguous — the flat form must never emit one."""
        configure_bgp_neighbor_inbound_soft_reconfiguration(
            self.device, neighbor=NBR, afi_safi="IPV4_UNICAST")
        self.assertNotIn("afi-safi IPV4_UNICAST", self.emitted())
        self.assertNotIn("exit", self.emitted())


class TestNoSubmodeExits(ArcosBgpConfigureTestCase):
    """T1-04 M1 regression guard: this batch enters no submode, so no function
    may emit 'exit'. Every list must be [context, ...leaves, '!']."""

    def test_no_function_emits_exit(self):
        for fn, kwargs in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, neighbor=NBR, **kwargs)
                cfg = self.emitted()
                self.assertNotIn("exit", cfg)
                self.assertEqual(cfg[0], CTX)
                self.assertEqual(cfg[-1], "!")


class TestCustomInstanceRendering(ArcosBgpConfigureTestCase):
    """All 24 must honour a non-default network/protocol instance."""

    OTHER_CTX = f"network-instance red protocol BGP bgp1 neighbor {NBR}"

    def test_all_functions(self):
        for fn, kwargs in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, neighbor=NBR, network_instance="red",
                   protocol_instance="bgp1", **kwargs)
                self.assertEqual(self.emitted()[0], self.OTHER_CTX)


class TestFailurePropagation(ArcosBgpConfigureTestCase):
    """A SubCommandFailure from the device must propagate from all 24."""

    def test_all_functions(self):
        for fn, kwargs in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("device said no")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, neighbor=NBR, **kwargs)


if __name__ == "__main__":
    unittest.main()
