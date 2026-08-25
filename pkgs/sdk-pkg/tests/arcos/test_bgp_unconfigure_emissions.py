"""Exact-emission pins for every ``unconfigure_*`` in the BGP T1-01..03 batches.

Closes review finding M1. A mutation sweep showed that inserting a bogus token
into 14 of the batch's removal paths left the whole suite green: the per-batch
files assert exact emission for the *configure* halves but, for many
unconfigures, only that ``cfg[0]``/``cfg[-1]`` are right and no ``exit``
appears. A wrong ``no <path>`` would therefore be invisible in CI *and*
on-device, because arcOS silently accepts some malformed ``no`` forms.

Every expected list below is the emission of the shipped code at the time these
were lab-verified on rtr1 (both directions, read-back confirmed), so this file
pins behaviour that was checked against a real device rather than a
hand-transcribed guess.
"""

import unittest
from unittest.mock import Mock

import genie.libs.sdk.apis.arcos.bgp.configure as bgp


class TestUnconfigureExactEmission(unittest.TestCase):
    """One exact-list assertion per removal path in the batch."""

    #: (function name, kwargs, expected emitted list)
    CASES = [
        ('unconfigure_bgp_add_paths_eligible_prefix_policy',
         {'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST add-paths eligible-prefix-policy', '!']),
        ('unconfigure_bgp_cluster_id',
         {},
         ['network-instance default protocol BGP default', 'no global cluster-id', '!']),
        ('unconfigure_bgp_compatibility_strict_common_afi_safi_check',
         {},
         ['network-instance default protocol BGP default', 'no global compatibility strict-common-afi-safi-check', '!']),
        ('unconfigure_bgp_compatibility_suppress_nexthop_attribute',
         {},
         ['network-instance default protocol BGP default', 'no global compatibility suppress-nexthop-attribute', '!']),
        ('unconfigure_bgp_default_information_originate',
         {'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST default-information originate', '!']),
        ('unconfigure_bgp_dynamic_neighbor_prefix',
         {'prefix': '220.1.0.0/16'},
         ['network-instance default protocol BGP default', 'no dynamic-neighbor-prefix 220.1.0.0/16', '!']),
        ('unconfigure_bgp_flowspec_rt_redirect_next_hop',
         {'afi_safi': 'IPV4_FLOWSPEC'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_FLOWSPEC rt-redirect', '!']),
        ('unconfigure_bgp_flowspec_sample_and_drop',
         {'afi_safi': 'IPV4_FLOWSPEC'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_FLOWSPEC sample-and-drop', '!']),
        ('unconfigure_bgp_global_export_policy',
         {'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST apply-policy export-policy', '!']),
        ('unconfigure_bgp_global_import_policy',
         {'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST apply-policy import-policy', '!']),
        ('unconfigure_bgp_graceful_shutdown',
         {},
         ['network-instance default protocol BGP default', 'no global graceful-shutdown', '!']),
        ('unconfigure_bgp_mandate_ebgp_policy',
         {},
         ['network-instance default protocol BGP default', 'no global mandate-ebgp-policy', '!']),
        ('unconfigure_bgp_neighbor_aigp',
         {'neighbor': '10.1.1.2', 'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no afi-safi IPV4_UNICAST aigp enable', '!']),
        ('unconfigure_bgp_neighbor_as_path_options',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no as-path-options', '!']),
        ('unconfigure_bgp_neighbor_auth_password',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no auth-password', '!']),
        ('unconfigure_bgp_neighbor_default_originate',
         {'neighbor': '10.1.1.2', 'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no afi-safi IPV4_UNICAST default-originate', '!']),
        ('unconfigure_bgp_neighbor_disable_fast_deactivation',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no disable-fast-deactivation', '!']),
        ('unconfigure_bgp_neighbor_dscp',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no dscp', '!']),
        ('unconfigure_bgp_neighbor_ebgp_local_as',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no ebgp-local-as', '!']),
        ('unconfigure_bgp_neighbor_ebgp_multihop',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no ebgp-multihop', '!']),
        ('unconfigure_bgp_neighbor_egress_peer_engineering',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no egress-peer-engineering', '!']),
        ('unconfigure_bgp_neighbor_enforce_first_as',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no enforce-first-as', '!']),
        ('unconfigure_bgp_neighbor_graceful_shutdown',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no graceful-shutdown', '!']),
        ('unconfigure_bgp_neighbor_inbound_soft_reconfiguration',
         {'neighbor': '10.1.1.2', 'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no afi-safi IPV4_UNICAST inbound-soft-reconfiguration', '!']),
        ('unconfigure_bgp_neighbor_next_hop',
         {'neighbor': '10.1.1.2', 'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no afi-safi IPV4_UNICAST next-hop', '!']),
        ('unconfigure_bgp_neighbor_peer_as_range',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no peer-as-range', '!']),
        ('unconfigure_bgp_neighbor_remove_private_as',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no remove-private-as', '!']),
        ('unconfigure_bgp_neighbor_route_reflector_client',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no route-reflector route-reflector-client', '!']),
        ('unconfigure_bgp_neighbor_route_server_client',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no route-server route-server-client', '!']),
        ('unconfigure_bgp_neighbor_rtfilter_send_default_route',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no afi-safi RTFILTER send-default-route', '!']),
        ('unconfigure_bgp_neighbor_transport_passive_mode',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no transport passive-mode', '!']),
        ('unconfigure_bgp_neighbor_transport_tcp_mss',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no transport tcp-mss', '!']),
        ('unconfigure_bgp_neighbor_ttl_security_hops',
         {'neighbor': '10.1.1.2'},
         ['network-instance default protocol BGP default neighbor 10.1.1.2', 'no ttl-security-hops', '!']),
        ('unconfigure_bgp_network_rib_validation',
         {'afi_safi': 'IPV4_UNICAST', 'prefix': '220.1.0.0/16'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST network 220.1.0.0/16 rib-validation', '!']),
        ('unconfigure_bgp_retain_route_target_all',
         {'afi_safi': 'L3VPN_IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi L3VPN_IPV4_UNICAST retain-route-target-all', '!']),
        ('unconfigure_bgp_rtfilter_vpn_update_delay',
         {},
         ['network-instance default protocol BGP default', 'no global afi-safi RTFILTER vpn-update-delay', '!']),
        ('unconfigure_bgp_rtr_server',
         {'server_name': 'rpki-rtr'},
         ['network-instance default protocol BGP default', 'no rtr-server rpki-rtr', '!']),
        ('unconfigure_bgp_shutdown_all_sessions',
         {},
         ['network-instance default protocol BGP default', 'no global shutdown-all-sessions', '!']),
        ('unconfigure_bgp_shutdown_protocol',
         {},
         ['network-instance default protocol BGP default', 'no global shutdown-protocol', '!']),
        ('unconfigure_bgp_silent_drop',
         {},
         ['network-instance default protocol BGP default', 'no global silent-drop', '!']),
        ('unconfigure_bgp_telemetry',
         {},
         ['network-instance default protocol BGP default', 'no global telemetry', '!']),
        ('unconfigure_bgp_update_wait_data_plane',
         {'afi_safi': 'IPV4_UNICAST'},
         ['network-instance default protocol BGP default', 'no global afi-safi IPV4_UNICAST update-wait-data-plane', '!']),
    ]

    def setUp(self):
        self.device = Mock()
        self.device.name = "test_device"

    def test_every_unconfigure_emits_its_exact_line(self):
        for name, kwargs, expected in self.CASES:
            with self.subTest(fn=name):
                self.device.configure.reset_mock()
                getattr(bgp, name)(self.device, **kwargs)
                self.device.configure.assert_called_once()
                self.assertEqual(self.device.configure.call_args[0][0], expected)

    def test_every_removal_path_is_covered(self):
        """Guard the guard: if a new unconfigure_* lands in the batch without an
        entry here, fail rather than silently leave it unpinned."""
        import re
        src = open(bgp.__file__).read()
        blk = src[src.index("batch T1-01"):]
        shipped = set(re.findall(r"\ndef (unconfigure_\w+)\(", blk))
        pinned = {n for n, _, _ in self.CASES}
        self.assertEqual(shipped - pinned, set(),
                         "unconfigure functions with no exact-emission pin")


if __name__ == "__main__":
    unittest.main()
