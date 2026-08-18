"""Unit tests for ArcOS BGP configure APIs added by missing-API batch T1-03.

Source: ``arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md``.
Proposal: ``orchestrator/proposals/approved/bgp_api_t1_03_operational_afi.md``.

Covers 17 configure/unconfigure pairs (operational and AFI-specific knobs) in
``genie.libs.sdk.apis.arcos.bgp.configure``.

All 34 emitted lists were confirmed ACCEPTED by arcOS on rtr1 (2026-08-17) and every
unconfigure confirmed to remove the leaf, by commit + read-back in both directions.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.bgp.configure import (
    BGP_NEXT_HOP_TYPES,
    BGP_UPDATE_WAIT_AFI_SAFIS,
    BGP_FLOWSPEC_AFI_SAFIS,
    BGP_RT_REDIRECT_NEXT_HOPS,
    configure_bgp_shutdown_protocol, unconfigure_bgp_shutdown_protocol,
    configure_bgp_shutdown_all_sessions, unconfigure_bgp_shutdown_all_sessions,
    configure_bgp_silent_drop, unconfigure_bgp_silent_drop,
    configure_bgp_mandate_ebgp_policy, unconfigure_bgp_mandate_ebgp_policy,
    configure_bgp_compatibility_suppress_nexthop_attribute,
    unconfigure_bgp_compatibility_suppress_nexthop_attribute,
    configure_bgp_compatibility_strict_common_afi_safi_check,
    unconfigure_bgp_compatibility_strict_common_afi_safi_check,
    configure_bgp_update_wait_data_plane, unconfigure_bgp_update_wait_data_plane,
    configure_bgp_rtfilter_vpn_update_delay, unconfigure_bgp_rtfilter_vpn_update_delay,
    configure_bgp_neighbor_egress_peer_engineering,
    unconfigure_bgp_neighbor_egress_peer_engineering,
    configure_bgp_neighbor_rtfilter_send_default_route,
    unconfigure_bgp_neighbor_rtfilter_send_default_route,
    configure_bgp_graceful_shutdown, unconfigure_bgp_graceful_shutdown,
    configure_bgp_neighbor_graceful_shutdown, unconfigure_bgp_neighbor_graceful_shutdown,
    configure_bgp_neighbor_next_hop, unconfigure_bgp_neighbor_next_hop,
    configure_bgp_flowspec_sample_and_drop, unconfigure_bgp_flowspec_sample_and_drop,
    configure_bgp_flowspec_rt_redirect_next_hop,
    unconfigure_bgp_flowspec_rt_redirect_next_hop,
    configure_bgp_telemetry, unconfigure_bgp_telemetry,
    configure_bgp_rtr_server, unconfigure_bgp_rtr_server,
)

NBR = "10.1.1.2"
P = "network-instance default protocol BGP default"
N = f"{P} neighbor {NBR}"

ALL_FUNCS = [
    (configure_bgp_shutdown_protocol, {}, P),
    (unconfigure_bgp_shutdown_protocol, {}, P),
    (configure_bgp_shutdown_all_sessions, {}, P),
    (unconfigure_bgp_shutdown_all_sessions, {}, P),
    (configure_bgp_silent_drop, {}, P),
    (unconfigure_bgp_silent_drop, {}, P),
    (configure_bgp_mandate_ebgp_policy, {}, P),
    (unconfigure_bgp_mandate_ebgp_policy, {}, P),
    (configure_bgp_compatibility_suppress_nexthop_attribute, {}, P),
    (unconfigure_bgp_compatibility_suppress_nexthop_attribute, {}, P),
    (configure_bgp_compatibility_strict_common_afi_safi_check, {}, P),
    (unconfigure_bgp_compatibility_strict_common_afi_safi_check, {}, P),
    (configure_bgp_update_wait_data_plane, {"afi_safi": "IPV4_UNICAST"}, P),
    (unconfigure_bgp_update_wait_data_plane, {"afi_safi": "IPV4_UNICAST"}, P),
    (configure_bgp_rtfilter_vpn_update_delay, {"delay": 90}, P),
    (unconfigure_bgp_rtfilter_vpn_update_delay, {}, P),
    (configure_bgp_neighbor_egress_peer_engineering, {"neighbor": NBR}, N),
    (unconfigure_bgp_neighbor_egress_peer_engineering, {"neighbor": NBR}, N),
    (configure_bgp_neighbor_rtfilter_send_default_route, {"neighbor": NBR}, N),
    (unconfigure_bgp_neighbor_rtfilter_send_default_route, {"neighbor": NBR}, N),
    (configure_bgp_graceful_shutdown, {}, P),
    (unconfigure_bgp_graceful_shutdown, {}, P),
    (configure_bgp_neighbor_graceful_shutdown, {"neighbor": NBR}, N),
    (unconfigure_bgp_neighbor_graceful_shutdown, {"neighbor": NBR}, N),
    (configure_bgp_neighbor_next_hop,
     {"neighbor": NBR, "afi_safi": "IPV4_UNICAST", "next_hop": "SELF"}, N),
    (unconfigure_bgp_neighbor_next_hop, {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"}, N),
    (configure_bgp_flowspec_sample_and_drop, {"afi_safi": "IPV4_FLOWSPEC"}, P),
    (unconfigure_bgp_flowspec_sample_and_drop, {"afi_safi": "IPV4_FLOWSPEC"}, P),
    (configure_bgp_flowspec_rt_redirect_next_hop,
     {"afi_safi": "IPV4_FLOWSPEC", "next_hop": "DEFAULT"}, P),
    (unconfigure_bgp_flowspec_rt_redirect_next_hop, {"afi_safi": "IPV4_FLOWSPEC"}, P),
    (configure_bgp_telemetry, {"neighbor_stream": True}, P),
    (unconfigure_bgp_telemetry, {}, P),
    (configure_bgp_rtr_server, {"server_name": "rpki-rtr"}, P),
    (unconfigure_bgp_rtr_server, {"server_name": "rpki-rtr"}, P),
]


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestExactEmission(Base):
    """Exact emitted list — the lines lab-verified on rtr1."""

    CASES = [
        (configure_bgp_shutdown_protocol, {}, [P, "global shutdown-protocol true", "!"]),
        (unconfigure_bgp_shutdown_protocol, {}, [P, "no global shutdown-protocol", "!"]),
        (configure_bgp_shutdown_all_sessions, {}, [P, "global shutdown-all-sessions true", "!"]),
        (configure_bgp_silent_drop, {}, [P, "global silent-drop true", "!"]),
        (configure_bgp_mandate_ebgp_policy, {}, [P, "global mandate-ebgp-policy true", "!"]),
        (configure_bgp_compatibility_suppress_nexthop_attribute, {},
         [P, "global compatibility suppress-nexthop-attribute true", "!"]),
        (configure_bgp_compatibility_strict_common_afi_safi_check, {},
         [P, "global compatibility strict-common-afi-safi-check true", "!"]),
        (configure_bgp_update_wait_data_plane, {"afi_safi": "IPV6_UNICAST"},
         [P, "global afi-safi IPV6_UNICAST update-wait-data-plane true", "!"]),
        (unconfigure_bgp_update_wait_data_plane, {"afi_safi": "IPV6_UNICAST"},
         [P, "no global afi-safi IPV6_UNICAST update-wait-data-plane", "!"]),
        (configure_bgp_rtfilter_vpn_update_delay, {"delay": 90},
         [P, "global afi-safi RTFILTER vpn-update-delay 90", "!"]),
        (unconfigure_bgp_rtfilter_vpn_update_delay, {},
         [P, "no global afi-safi RTFILTER vpn-update-delay", "!"]),
        (configure_bgp_neighbor_egress_peer_engineering, {"neighbor": NBR},
         [N, "egress-peer-engineering labeled-unicast enable true", "!"]),
        (unconfigure_bgp_neighbor_egress_peer_engineering, {"neighbor": NBR},
         [N, "no egress-peer-engineering", "!"]),
        (configure_bgp_neighbor_rtfilter_send_default_route,
         {"neighbor": NBR, "enabled": False},
         [N, "afi-safi RTFILTER send-default-route false", "!"]),
        (configure_bgp_neighbor_next_hop,
         {"neighbor": NBR, "afi_safi": "IPV4_UNICAST", "next_hop": "SELF"},
         [N, "afi-safi IPV4_UNICAST next-hop SELF", "!"]),
        (configure_bgp_flowspec_sample_and_drop, {"afi_safi": "IPV4_FLOWSPEC"},
         [P, "global afi-safi IPV4_FLOWSPEC sample-and-drop true", "!"]),
        (configure_bgp_flowspec_rt_redirect_next_hop,
         {"afi_safi": "IPV6_FLOWSPEC", "next_hop": "BGP_NLRI"},
         [P, "global afi-safi IPV6_FLOWSPEC rt-redirect next-hop BGP_NLRI", "!"]),
        (unconfigure_bgp_flowspec_rt_redirect_next_hop, {"afi_safi": "IPV4_FLOWSPEC"},
         [P, "no global afi-safi IPV4_FLOWSPEC rt-redirect", "!"]),
    ]

    def test_cases(self):
        for fn, kwargs, expected in self.CASES:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                self.assertEqual(self.emitted(), expected)


class TestShutdownKnobsAreNamedShutdown(Base):
    """M1 guard: these default to taking BGP down, so the param must not read
    as `enabled` (which would suggest the opposite)."""

    def test_param_is_named_shutdown(self):
        import inspect
        for fn in (configure_bgp_shutdown_protocol,
                   configure_bgp_shutdown_all_sessions):
            with self.subTest(fn=fn.__name__):
                params = inspect.signature(fn).parameters
                self.assertIn("shutdown", params)
                self.assertNotIn("enabled", params)

    def test_shutdown_false_emits_false(self):
        configure_bgp_shutdown_protocol(self.device, shutdown=False)
        self.assertEqual(self.emitted(), [P, "global shutdown-protocol false", "!"])


class TestGracefulShutdown(Base):
    """The leaf is spelled `enable`, not `enabled` — unlike most arcOS booleans."""

    def test_global_minimal_uses_enable_not_enabled(self):
        configure_bgp_graceful_shutdown(self.device)
        self.assertEqual(self.emitted(), [P, "global graceful-shutdown enable true", "!"])
        self.assertNotIn("global graceful-shutdown enabled true", self.emitted())

    def test_global_all_leaves(self):
        configure_bgp_graceful_shutdown(
            self.device, set_local_preference_zero=True, set_med_maximum=True)
        self.assertEqual(self.emitted(), [
            P,
            "global graceful-shutdown enable true",
            "global graceful-shutdown set-local-preference-zero true",
            "global graceful-shutdown set-med-maximum true",
            "!",
        ])

    def test_neighbor_form_has_no_global_prefix(self):
        configure_bgp_neighbor_graceful_shutdown(
            self.device, neighbor=NBR, set_med_maximum=False)
        self.assertEqual(self.emitted(), [
            N,
            "graceful-shutdown enable true",
            "graceful-shutdown set-med-maximum false",
            "!",
        ])

    def test_unconfigures(self):
        unconfigure_bgp_graceful_shutdown(self.device)
        self.assertEqual(self.emitted(), [P, "no global graceful-shutdown", "!"])
        self.device.configure.reset_mock()
        unconfigure_bgp_neighbor_graceful_shutdown(self.device, neighbor=NBR)
        self.assertEqual(self.emitted(), [N, "no graceful-shutdown", "!"])


class TestEnumValidation(Base):

    def test_next_hop_enum(self):
        for good in BGP_NEXT_HOP_TYPES:
            with self.subTest(v=good):
                self.device.configure.reset_mock()
                configure_bgp_neighbor_next_hop(
                    self.device, neighbor=NBR, afi_safi="IPV4_UNICAST", next_hop=good)
        for bad in ("self", "SELF ", "NEXTHOP_SELF", "", None):
            with self.subTest(v=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    configure_bgp_neighbor_next_hop(
                        self.device, neighbor=NBR, afi_safi="IPV4_UNICAST", next_hop=bad)
                self.device.configure.assert_not_called()

    def test_flowspec_af_enum_both_directions(self):
        for fn in (configure_bgp_flowspec_sample_and_drop,
                   unconfigure_bgp_flowspec_sample_and_drop,
                   configure_bgp_flowspec_rt_redirect_next_hop,
                   unconfigure_bgp_flowspec_rt_redirect_next_hop):
            for bad in ("IPV4_UNICAST", "L2VPN_EVPN", ""):
                with self.subTest(fn=fn.__name__, af=bad):
                    self.device.configure.reset_mock()
                    kw = {"afi_safi": bad}
                    if fn is configure_bgp_flowspec_rt_redirect_next_hop:
                        kw["next_hop"] = "DEFAULT"
                    with self.assertRaises(ValueError):
                        fn(self.device, **kw)
                    self.device.configure.assert_not_called()

    def test_rt_redirect_next_hop_enum(self):
        for bad in ("default", "NLRI", ""):
            with self.subTest(v=bad):
                self.device.configure.reset_mock()
                with self.assertRaises(ValueError):
                    configure_bgp_flowspec_rt_redirect_next_hop(
                        self.device, afi_safi="IPV4_FLOWSPEC", next_hop=bad)
                self.device.configure.assert_not_called()
        self.assertEqual(set(BGP_RT_REDIRECT_NEXT_HOPS), {"DEFAULT", "BGP_NLRI"})


class TestReviewGuards(Base):
    """Guards added for review findings M4, M5 and M7."""

    def test_m4_update_wait_af_is_enforced(self):
        """The docstring restricted the AF to two values; nothing checked it."""
        self.assertEqual(set(BGP_UPDATE_WAIT_AFI_SAFIS),
                         {"IPV4_UNICAST", "IPV6_UNICAST"})
        for fn in (configure_bgp_update_wait_data_plane,
                   unconfigure_bgp_update_wait_data_plane):
            for good in BGP_UPDATE_WAIT_AFI_SAFIS:
                with self.subTest(fn=fn.__name__, af=good):
                    self.device.configure.reset_mock()
                    fn(self.device, afi_safi=good)
            for bad in ("L2VPN_EVPN", "L3VPN_IPV4_UNICAST", "RTFILTER", ""):
                with self.subTest(fn=fn.__name__, af=bad):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, afi_safi=bad)
                    self.device.configure.assert_not_called()

    def test_m7_sub_leaves_require_enable_true(self):
        """adoc:1182 — graceful-shutdown must be enabled before the other
        parameters can be configured. Emitting `enable false` then a sub-leaf
        is an ordering the adoc forbids."""
        for fn, kw in ((configure_bgp_graceful_shutdown, {}),
                       (configure_bgp_neighbor_graceful_shutdown, {"neighbor": NBR})):
            for extra in ({"set_local_preference_zero": True},
                          {"set_med_maximum": True}):
                with self.subTest(fn=fn.__name__, extra=extra):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, enable=False, **kw, **extra)
                    self.device.configure.assert_not_called()

    def test_m7_enable_false_alone_is_still_allowed(self):
        configure_bgp_graceful_shutdown(self.device, enable=False)
        self.assertEqual(
            self.emitted(), [P, "global graceful-shutdown enable false", "!"])


class TestTelemetryAndRtrServer(Base):

    def test_telemetry_requires_a_stream(self):
        with self.assertRaises(ValueError):
            configure_bgp_telemetry(self.device)
        self.device.configure.assert_not_called()

    def test_telemetry_both_streams(self):
        configure_bgp_telemetry(self.device, neighbor_stream=True, prefix_stream=False)
        self.assertEqual(self.emitted(), [
            P,
            "global telemetry neighbor-stream-enabled true",
            "global telemetry prefix-stream-enabled false",
            "!",
        ])

    def test_rtr_server_name_only(self):
        configure_bgp_rtr_server(self.device, server_name="rpki-rtr")
        self.assertEqual(self.emitted(), [P, "rtr-server rpki-rtr", "!"])

    def test_rtr_server_all_options(self):
        configure_bgp_rtr_server(
            self.device, server_name="rpki-rtr", address="10.1.1.9",
            port=3323, preference=1, local_address="lo0")
        self.assertEqual(self.emitted(), [
            P,
            "rtr-server rpki-rtr",
            "rtr-server rpki-rtr address 10.1.1.9",
            "rtr-server rpki-rtr port 3323",
            "rtr-server rpki-rtr preference 1",
            "rtr-server rpki-rtr local-address lo0",
            "!",
        ])

    def test_rtr_server_is_protocol_scoped(self):
        """Sibling of `global`, not under it."""
        configure_bgp_rtr_server(self.device, server_name="rpki-rtr")
        for line in self.emitted():
            self.assertFalse(line.startswith("global "))


class TestNoSubmodeExits(Base):
    def test_all(self):
        for fn, kwargs, ctx in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                cfg = self.emitted()
                self.assertNotIn("exit", cfg)
                self.assertEqual(cfg[0], ctx)
                self.assertEqual(cfg[-1], "!")


class TestCustomInstanceRendering(Base):
    def test_all(self):
        for fn, kwargs, ctx in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="red", protocol_instance="bgp1", **kwargs)
                self.assertEqual(
                    self.emitted()[0],
                    ctx.replace("default protocol BGP default", "red protocol BGP bgp1"))


class TestFailurePropagation(Base):
    def test_all(self):
        for fn, kwargs, _ in ALL_FUNCS:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                self.device.configure.side_effect = SubCommandFailure("nope")
                with self.assertRaises(SubCommandFailure):
                    fn(self.device, **kwargs)


if __name__ == "__main__":
    unittest.main()
