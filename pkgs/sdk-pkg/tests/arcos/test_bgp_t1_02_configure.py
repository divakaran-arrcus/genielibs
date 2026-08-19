"""Unit tests for ArcOS BGP configure APIs added by missing-API batch T1-02.

Source: ``arcos_pyats_sanity/docs/config-coverage/02-bgp-policy-redist.md``.
Proposal: ``orchestrator/proposals/approved/bgp_api_t1_02_rr_scaling.md``.

Covers 11 configure/unconfigure pairs (route-reflection, dynamic peering and
AF-scoped knobs) in ``genie.libs.sdk.apis.arcos.bgp.configure``.

All 22 emitted lists were confirmed ACCEPTED by arcOS on rtr1 (2026-08-17), and
every unconfigure confirmed to remove the leaf, by commit + running-config
read-back in both directions.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.bgp.configure import (
    BGP_VPN_AFI_SAFIS,
    configure_bgp_neighbor_route_reflector_client,
    unconfigure_bgp_neighbor_route_reflector_client,
    configure_bgp_neighbor_route_server_client,
    unconfigure_bgp_neighbor_route_server_client,
    configure_bgp_neighbor_peer_as_range,
    unconfigure_bgp_neighbor_peer_as_range,
    configure_bgp_cluster_id,
    unconfigure_bgp_cluster_id,
    configure_bgp_add_paths_eligible_prefix_policy,
    unconfigure_bgp_add_paths_eligible_prefix_policy,
    configure_bgp_default_information_originate,
    unconfigure_bgp_default_information_originate,
    configure_bgp_network_rib_validation,
    unconfigure_bgp_network_rib_validation,
    configure_bgp_neighbor_aigp,
    unconfigure_bgp_neighbor_aigp,
    configure_bgp_dynamic_neighbor_prefix,
    unconfigure_bgp_dynamic_neighbor_prefix,
    configure_bgp_retain_route_target_all,
    unconfigure_bgp_retain_route_target_all,
    configure_bgp_neighbor_default_originate,
    unconfigure_bgp_neighbor_default_originate,
)

NBR = "10.1.1.2"
PCTX = "network-instance default protocol BGP default"
NCTX = f"{PCTX} neighbor {NBR}"

ALL_FUNCS = [
    (configure_bgp_neighbor_route_reflector_client, {"neighbor": NBR}, NCTX),
    (unconfigure_bgp_neighbor_route_reflector_client, {"neighbor": NBR}, NCTX),
    (configure_bgp_neighbor_route_server_client, {"neighbor": NBR}, NCTX),
    (unconfigure_bgp_neighbor_route_server_client, {"neighbor": NBR}, NCTX),
    (configure_bgp_neighbor_peer_as_range, {"neighbor": NBR, "ranges": "65000..70000"}, NCTX),
    (unconfigure_bgp_neighbor_peer_as_range, {"neighbor": NBR}, NCTX),
    (configure_bgp_cluster_id, {"cluster_id": "10.10.1.1"}, PCTX),
    (unconfigure_bgp_cluster_id, {}, PCTX),
    (configure_bgp_add_paths_eligible_prefix_policy,
     {"afi_safi": "IPV4_UNICAST", "policy": "POL"}, PCTX),
    (unconfigure_bgp_add_paths_eligible_prefix_policy, {"afi_safi": "IPV4_UNICAST"}, PCTX),
    (configure_bgp_default_information_originate, {"afi_safi": "IPV4_UNICAST"}, PCTX),
    (unconfigure_bgp_default_information_originate, {"afi_safi": "IPV4_UNICAST"}, PCTX),
    (configure_bgp_network_rib_validation,
     {"afi_safi": "IPV4_UNICAST", "prefix": "100.1.1.0/24"}, PCTX),
    (unconfigure_bgp_network_rib_validation,
     {"afi_safi": "IPV4_UNICAST", "prefix": "100.1.1.0/24"}, PCTX),
    (configure_bgp_neighbor_aigp, {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"}, NCTX),
    (unconfigure_bgp_neighbor_aigp, {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"}, NCTX),
    (configure_bgp_dynamic_neighbor_prefix, {"prefix": "220.1.0.0/16"}, PCTX),
    (unconfigure_bgp_dynamic_neighbor_prefix, {"prefix": "220.1.0.0/16"}, PCTX),
    (configure_bgp_retain_route_target_all, {"afi_safi": "L3VPN_IPV4_UNICAST"}, PCTX),
    (unconfigure_bgp_retain_route_target_all, {"afi_safi": "L3VPN_IPV4_UNICAST"}, PCTX),
    (configure_bgp_neighbor_default_originate,
     {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"}, NCTX),
    (unconfigure_bgp_neighbor_default_originate,
     {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"}, NCTX),
]


class Base(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def emitted(self):
        self.device.configure.assert_called_once()
        return self.device.configure.call_args[0][0]


class TestExactEmission(Base):
    """Exact emitted list per function — the lines lab-verified on rtr1."""

    CASES = [
        (configure_bgp_neighbor_route_reflector_client, {"neighbor": NBR},
         [NCTX, "route-reflector route-reflector-client true", "!"]),
        (unconfigure_bgp_neighbor_route_reflector_client, {"neighbor": NBR},
         [NCTX, "no route-reflector route-reflector-client", "!"]),
        (configure_bgp_neighbor_route_server_client, {"neighbor": NBR},
         [NCTX, "route-server route-server-client true", "!"]),
        (configure_bgp_neighbor_peer_as_range, {"neighbor": NBR, "ranges": "65000..70000"},
         [NCTX, "peer-as-range inline ranges 65000..70000", "!"]),
        (unconfigure_bgp_neighbor_peer_as_range, {"neighbor": NBR},
         [NCTX, "no peer-as-range", "!"]),
        (configure_bgp_cluster_id, {"cluster_id": "10.10.1.1"},
         [PCTX, "global cluster-id 10.10.1.1", "!"]),
        (unconfigure_bgp_cluster_id, {}, [PCTX, "no global cluster-id", "!"]),
        (configure_bgp_add_paths_eligible_prefix_policy,
         {"afi_safi": "IPV4_UNICAST", "policy": "POL"},
         [PCTX, "global afi-safi IPV4_UNICAST add-paths eligible-prefix-policy POL", "!"]),
        (configure_bgp_default_information_originate, {"afi_safi": "IPV4_UNICAST"},
         [PCTX, "global afi-safi IPV4_UNICAST default-information originate enabled true", "!"]),
        (configure_bgp_network_rib_validation,
         {"afi_safi": "IPV4_UNICAST", "prefix": "100.1.1.0/24"},
         [PCTX, "global afi-safi IPV4_UNICAST network 100.1.1.0/24 rib-validation true", "!"]),
        (configure_bgp_neighbor_aigp, {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"},
         [NCTX, "afi-safi IPV4_UNICAST aigp enable true", "!"]),
        (unconfigure_bgp_neighbor_aigp, {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"},
         [NCTX, "no afi-safi IPV4_UNICAST aigp enable", "!"]),
        (configure_bgp_neighbor_default_originate,
         {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"},
         [NCTX, "afi-safi IPV4_UNICAST default-originate enabled true", "!"]),
        (unconfigure_bgp_neighbor_default_originate,
         {"neighbor": NBR, "afi_safi": "IPV4_UNICAST"},
         [NCTX, "no afi-safi IPV4_UNICAST default-originate", "!"]),
    ]

    def test_cases(self):
        for fn, kwargs, expected in self.CASES:
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, **kwargs)
                self.assertEqual(self.emitted(), expected)


class TestDynamicNeighborPrefix(Base):

    def test_prefix_only(self):
        configure_bgp_dynamic_neighbor_prefix(self.device, prefix="220.1.0.0/16")
        self.assertEqual(
            self.emitted(), [PCTX, "dynamic-neighbor-prefix 220.1.0.0/16", "!"])

    def test_with_peer_group_and_limit(self):
        configure_bgp_dynamic_neighbor_prefix(
            self.device, prefix="220.1.0.0/16", peer_group="p1", neighbor_limit=32)
        self.assertEqual(self.emitted(), [
            PCTX,
            "dynamic-neighbor-prefix 220.1.0.0/16",
            "dynamic-neighbor-prefix 220.1.0.0/16 peer-group p1",
            "dynamic-neighbor-prefix 220.1.0.0/16 neighbor-limit 32",
            "!",
        ])

    def test_is_protocol_scoped_not_under_global(self):
        """Audit implied `global` scope; the device puts it at protocol level."""
        configure_bgp_dynamic_neighbor_prefix(self.device, prefix="220.1.0.0/16")
        for line in self.emitted():
            self.assertFalse(line.startswith("global "))

    def test_unconfigure(self):
        unconfigure_bgp_dynamic_neighbor_prefix(self.device, prefix="220.1.0.0/16")
        self.assertEqual(
            self.emitted(), [PCTX, "no dynamic-neighbor-prefix 220.1.0.0/16", "!"])


class TestRetainRouteTargetAll(Base):

    def test_configure_emits_boolean(self):
        """adoc shows a bare presence leaf; the build requires true/false, and
        the valueless form is rejected as 'incomplete path'."""
        configure_bgp_retain_route_target_all(
            self.device, afi_safi="L3VPN_IPV4_UNICAST")
        self.assertEqual(self.emitted(), [
            PCTX,
            "global afi-safi L3VPN_IPV4_UNICAST retain-route-target-all true",
            "!",
        ])

    def test_configure_false(self):
        configure_bgp_retain_route_target_all(
            self.device, afi_safi="L2VPN_EVPN", enabled=False)
        self.assertIn(
            "global afi-safi L2VPN_EVPN retain-route-target-all false", self.emitted())

    def test_all_vpn_afs_accepted(self):
        for af in BGP_VPN_AFI_SAFIS:
            with self.subTest(af=af):
                self.device.configure.reset_mock()
                configure_bgp_retain_route_target_all(self.device, afi_safi=af)

    def test_non_vpn_af_rejected_both_directions(self):
        """It does not exist under IPV4_UNICAST — reject before the device."""
        for fn in (configure_bgp_retain_route_target_all,
                   unconfigure_bgp_retain_route_target_all):
            for bad in ("IPV4_UNICAST", "IPV6_UNICAST", "RTFILTER", ""):
                with self.subTest(fn=fn.__name__, af=bad):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, afi_safi=bad)
                    self.device.configure.assert_not_called()

    def test_m5_non_default_instance_rejected(self):
        """adoc:855 restricts this to the `default` network-instance. The claim
        was documented but unenforced, and the custom-instance sweep asserted
        `red` renders — encoding an invalid config as expected behaviour."""
        for fn in (configure_bgp_retain_route_target_all,
                   unconfigure_bgp_retain_route_target_all):
            for ni in ("red", "vrf-a", ""):
                with self.subTest(fn=fn.__name__, ni=ni):
                    self.device.configure.reset_mock()
                    with self.assertRaises(ValueError):
                        fn(self.device, afi_safi="L3VPN_IPV4_UNICAST",
                           network_instance=ni)
                    self.device.configure.assert_not_called()

    def test_unconfigure(self):
        unconfigure_bgp_retain_route_target_all(
            self.device, afi_safi="L3VPN_IPV6_UNICAST")
        self.assertEqual(self.emitted(), [
            PCTX,
            "no global afi-safi L3VPN_IPV6_UNICAST retain-route-target-all",
            "!",
        ])


class TestDefaultOriginateExportPolicy(Base):

    def test_export_policy_string(self):
        configure_bgp_neighbor_default_originate(
            self.device, neighbor=NBR, afi_safi="IPV4_UNICAST",
            export_policy="policy1")
        self.assertIn(
            "afi-safi IPV4_UNICAST default-originate export-policy [ policy1 ]",
            self.emitted())

    def test_export_policy_list(self):
        configure_bgp_neighbor_default_originate(
            self.device, neighbor=NBR, afi_safi="IPV4_UNICAST",
            export_policy=["p1", "p2"])
        self.assertIn(
            "afi-safi IPV4_UNICAST default-originate export-policy [ p1 p2 ]",
            self.emitted())


class TestNoSubmodeExits(Base):
    """T1-04 M1 invariant: this batch enters no submode, so nothing emits 'exit'."""

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
    #: retain-route-target-all is valid only in the `default` network-instance
    #: (adoc:855), so it must NOT render a custom one — see
    #: TestRetainRouteTargetAll.test_m5_non_default_instance_rejected.
    EXEMPT = {"configure_bgp_retain_route_target_all",
              "unconfigure_bgp_retain_route_target_all"}

    def test_all(self):
        for fn, kwargs, ctx in ALL_FUNCS:
            if fn.__name__ in self.EXEMPT:
                continue
            with self.subTest(fn=fn.__name__):
                self.device.configure.reset_mock()
                fn(self.device, network_instance="red",
                   protocol_instance="bgp1", **kwargs)
                self.assertEqual(
                    self.emitted()[0], ctx.replace("default protocol BGP default",
                                                   "red protocol BGP bgp1"))


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
