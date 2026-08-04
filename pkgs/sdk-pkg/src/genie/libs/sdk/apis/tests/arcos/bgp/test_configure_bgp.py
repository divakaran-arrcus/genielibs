#!/usr/bin/env python3
"""Unit tests for arcOS BGP configure/unconfigure APIs (full coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.bgp.configure builds an arcOS CLI config list
(typically starting with the `network-instance <ni> protocol BGP <pi>`
context, or a neighbor/peer-group sub-context) and calls
`device.configure(config)`. Tests mock `device.configure` and assert on a
distinctive substring of the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.bgp.configure import (
    # Global
    configure_bgp_instance,
    unconfigure_bgp_instance,
    configure_bgp_as_number,
    unconfigure_bgp_as_number,
    configure_bgp_router_id,
    unconfigure_bgp_router_id,
    configure_bgp_global_afi_safi,
    unconfigure_bgp_global_afi_safi,
    configure_bgp_maximum_paths,
    unconfigure_bgp_maximum_paths,
    configure_bgp_network,
    unconfigure_bgp_network,
    configure_bgp_aggregate_address,
    unconfigure_bgp_aggregate_address,
    configure_bgp_adj_rib_out_post,
    unconfigure_bgp_adj_rib_out_post,
    configure_bgp_label_allocation_mode,
    unconfigure_bgp_label_allocation_mode,
    configure_bgp_segment_routing,
    unconfigure_bgp_segment_routing,
    # Neighbor
    configure_bgp_neighbor,
    unconfigure_bgp_neighbor,
    configure_bgp_neighbor_description,
    unconfigure_bgp_neighbor_description,
    configure_bgp_neighbor_shutdown,
    unconfigure_bgp_neighbor_shutdown,
    configure_bgp_neighbor_bfd,
    unconfigure_bgp_neighbor_bfd,
    configure_bgp_neighbor_afi_safi,
    unconfigure_bgp_neighbor_afi_safi,
    configure_bgp_neighbor_transport,
    unconfigure_bgp_neighbor_transport,
    configure_bgp_neighbor_import_policy,
    unconfigure_bgp_neighbor_import_policy,
    configure_bgp_neighbor_export_policy,
    unconfigure_bgp_neighbor_export_policy,
    # Peer-group
    configure_bgp_peer_group,
    unconfigure_bgp_peer_group,
    configure_bgp_peer_group_bfd,
    unconfigure_bgp_peer_group_bfd,
    configure_bgp_peer_group_afi_safi,
    unconfigure_bgp_peer_group_afi_safi,
    configure_bgp_neighbor_peer_group,
    unconfigure_bgp_neighbor_peer_group,
    # Global AFI-SAFI feature
    configure_bgp_add_paths_calculate,
    unconfigure_bgp_add_paths_calculate,
    configure_bgp_null_label,
    unconfigure_bgp_null_label,
    configure_bgp_rtfilter,
    unconfigure_bgp_rtfilter,
    # Global route-selection / compatibility
    configure_bgp_ignore_next_hop_igp_metric,
    unconfigure_bgp_ignore_next_hop_igp_metric,
    configure_bgp_drop_upon_invalid_sr_policy,
    unconfigure_bgp_drop_upon_invalid_sr_policy,
    configure_bgp_compatibility_l2_attr_local,
    unconfigure_bgp_compatibility_l2_attr_local,
    # Neighbor / peer-group add-paths
    configure_bgp_neighbor_add_paths,
    unconfigure_bgp_neighbor_add_paths,
    configure_bgp_peer_group_add_paths,
    unconfigure_bgp_peer_group_add_paths,
    # Peer-group policy
    configure_bgp_peer_group_import_policy,
    unconfigure_bgp_peer_group_import_policy,
    configure_bgp_peer_group_export_policy,
    unconfigure_bgp_peer_group_export_policy,
    # VRF (RD / RT)
    configure_bgp_route_distinguisher,
    unconfigure_bgp_route_distinguisher,
    configure_bgp_route_target,
    unconfigure_bgp_route_target,
    configure_bgp_rt_afi_safi_route_target,
    unconfigure_bgp_rt_afi_safi_route_target,
    # SRv6 / L3VPN-SRv6
    configure_bgp_srv6_locator,
    unconfigure_bgp_srv6_locator,
    configure_bgp_sid_allocation_mode,
    unconfigure_bgp_sid_allocation_mode,
    configure_bgp_peer_group_extended_nexthop,
    unconfigure_bgp_peer_group_extended_nexthop,
    # Best-path selection (configure-only, no unconfigure counterpart)
    configure_bgp_multipath_as_path_relax,
    configure_bgp_med_missing_as_worst,
    configure_bgp_multipath_evpn_etree_ead_relax,
    # eRPL
    configure_bgp_erpl_server,
    unconfigure_bgp_erpl_server,
    configure_bgp_erpl_connection_wait_time,
    configure_bgp_neighbor_apply_erpl,
    unconfigure_bgp_neighbor_apply_erpl,
    # PIC
    configure_bgp_install_backup,
    unconfigure_bgp_install_backup,
    configure_bgp_advertise_best_external,
    unconfigure_bgp_advertise_best_external,
    # Neighbor timers / graceful-restart
    configure_bgp_neighbor_timers,
    unconfigure_bgp_neighbor_timers,
    configure_bgp_graceful_restart,
    unconfigure_bgp_graceful_restart,
    # Neighbor max-prefix
    configure_bgp_neighbor_max_prefix,
    unconfigure_bgp_neighbor_max_prefix,
)


import inspect
import genie.libs.sdk.apis.arcos.bgp.configure as configure_module
class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestGlobalConfigureApis(unittest.TestCase):
    """configure_bgp_instance ... configure_bgp_segment_routing"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_instance(self):
        configure_bgp_instance(self.d)
        self.assertIn("network-instance default protocol BGP default", self.d.cfg())

    def test_unconfigure_instance(self):
        unconfigure_bgp_instance(self.d)
        self.assertIn("no network-instance default protocol BGP default", self.d.cfg())

    def test_as_number(self):
        configure_bgp_as_number(self.d, 65001)
        c = self.d.cfg()
        self.assertIn("network-instance default protocol BGP default", c)
        self.assertIn("global as 65001", c)

    def test_as_number_named_instances(self):
        configure_bgp_as_number(self.d, 65002, network_instance="red", protocol_instance="bgp1")
        self.assertIn("network-instance red protocol BGP bgp1", self.d.cfg())

    def test_unconfigure_as_number(self):
        unconfigure_bgp_as_number(self.d)
        self.assertIn("no global as", self.d.cfg())

    def test_router_id(self):
        configure_bgp_router_id(self.d, "1.1.1.1")
        self.assertIn("global router-id 1.1.1.1", self.d.cfg())

    def test_unconfigure_router_id(self):
        unconfigure_bgp_router_id(self.d)
        self.assertIn("no global router-id", self.d.cfg())

    def test_global_afi_safi(self):
        configure_bgp_global_afi_safi(self.d, "IPV4_UNICAST")
        self.assertIn("global afi-safi IPV4_UNICAST", self.d.cfg())

    def test_unconfigure_global_afi_safi(self):
        unconfigure_bgp_global_afi_safi(self.d, "IPV4_UNICAST")
        self.assertIn("no global afi-safi IPV4_UNICAST", self.d.cfg())

    def test_maximum_paths(self):
        configure_bgp_maximum_paths(self.d, "IPV4_UNICAST", 4)
        self.assertIn("use-maximum-paths ibgp maximum-paths 4", self.d.cfg())

    def test_unconfigure_maximum_paths(self):
        unconfigure_bgp_maximum_paths(self.d, "IPV4_UNICAST")
        self.assertIn("no use-maximum-paths ibgp maximum-paths", self.d.cfg())

    def test_network(self):
        configure_bgp_network(self.d, "IPV4_UNICAST", "10.0.0.0/24")
        self.assertIn("network 10.0.0.0/24", self.d.cfg())

    def test_unconfigure_network(self):
        unconfigure_bgp_network(self.d, "IPV4_UNICAST", "10.0.0.0/24")
        self.assertIn("no network 10.0.0.0/24", self.d.cfg())

    def test_aggregate_address(self):
        configure_bgp_aggregate_address(self.d, "IPV4_UNICAST", "10.0.0.0/8", summary_only=True)
        c = self.d.cfg()
        self.assertIn("aggregate-address 10.0.0.0/8", c)
        self.assertIn("summary-only true", c)

    def test_unconfigure_aggregate_address(self):
        unconfigure_bgp_aggregate_address(self.d, "IPV4_UNICAST", "10.0.0.0/8")
        self.assertIn("no aggregate-address 10.0.0.0/8", self.d.cfg())

    def test_adj_rib_out_post(self):
        configure_bgp_adj_rib_out_post(self.d)
        self.assertIn("global adj-rib-out-post true", self.d.cfg())

    def test_unconfigure_adj_rib_out_post(self):
        unconfigure_bgp_adj_rib_out_post(self.d)
        self.assertIn("no global adj-rib-out-post", self.d.cfg())

    def test_label_allocation_mode(self):
        configure_bgp_label_allocation_mode(self.d, "INSTANCE_LABEL")
        self.assertIn("global label-allocation-mode INSTANCE_LABEL", self.d.cfg())

    def test_unconfigure_label_allocation_mode(self):
        unconfigure_bgp_label_allocation_mode(self.d)
        self.assertIn("no global label-allocation-mode", self.d.cfg())

    def test_segment_routing(self):
        configure_bgp_segment_routing(self.d)
        self.assertIn("global segment-routing enabled true", self.d.cfg())

    def test_unconfigure_segment_routing(self):
        unconfigure_bgp_segment_routing(self.d)
        self.assertIn("no global segment-routing enabled", self.d.cfg())


class TestNeighborConfigureApis(unittest.TestCase):
    """configure_bgp_neighbor ... configure_bgp_neighbor_export_policy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_neighbor(self):
        configure_bgp_neighbor(self.d, "10.0.0.1", 65002)
        c = self.d.cfg()
        self.assertIn("neighbor 10.0.0.1", c)
        self.assertIn("peer-as 65002", c)

    def test_unconfigure_neighbor(self):
        unconfigure_bgp_neighbor(self.d, "10.0.0.1")
        self.assertIn("no neighbor 10.0.0.1", self.d.cfg())

    def test_neighbor_description(self):
        configure_bgp_neighbor_description(self.d, "10.0.0.1", "Uplink to R2")
        self.assertIn('description "Uplink to R2"', self.d.cfg())

    def test_unconfigure_neighbor_description(self):
        unconfigure_bgp_neighbor_description(self.d, "10.0.0.1")
        self.assertIn("no description", self.d.cfg())

    def test_neighbor_shutdown(self):
        configure_bgp_neighbor_shutdown(self.d, "10.0.0.1")
        self.assertIn("shutdown true", self.d.cfg())

    def test_unconfigure_neighbor_shutdown(self):
        unconfigure_bgp_neighbor_shutdown(self.d, "10.0.0.1")
        self.assertIn("no shutdown", self.d.cfg())

    def test_neighbor_bfd(self):
        configure_bgp_neighbor_bfd(self.d, "10.0.0.1", profile="p1")
        c = self.d.cfg()
        self.assertIn("bfd enable true", c)
        self.assertIn("bfd profile p1", c)

    def test_unconfigure_neighbor_bfd(self):
        unconfigure_bgp_neighbor_bfd(self.d, "10.0.0.1")
        c = self.d.cfg()
        self.assertIn("no bfd enable", c)
        self.assertIn("no bfd profile", c)

    def test_neighbor_afi_safi(self):
        configure_bgp_neighbor_afi_safi(self.d, "10.0.0.1", "IPV4_UNICAST")
        c = self.d.cfg()
        self.assertIn("neighbor 10.0.0.1", c)
        self.assertIn("afi-safi IPV4_UNICAST", c)

    def test_unconfigure_neighbor_afi_safi(self):
        unconfigure_bgp_neighbor_afi_safi(self.d, "10.0.0.1", "IPV4_UNICAST")
        self.assertIn("no afi-safi IPV4_UNICAST", self.d.cfg())

    def test_neighbor_transport(self):
        configure_bgp_neighbor_transport(self.d, "10.0.0.1", "10.0.0.2")
        self.assertIn("transport local-address 10.0.0.2", self.d.cfg())

    def test_unconfigure_neighbor_transport(self):
        unconfigure_bgp_neighbor_transport(self.d, "10.0.0.1")
        self.assertIn("no transport local-address", self.d.cfg())

    def test_neighbor_import_policy(self):
        configure_bgp_neighbor_import_policy(self.d, "10.0.0.1", "IPV4_UNICAST", ["POL1", "POL2"])
        self.assertIn("apply-policy import-policy [ POL1 POL2 ]", self.d.cfg())

    def test_unconfigure_neighbor_import_policy(self):
        unconfigure_bgp_neighbor_import_policy(self.d, "10.0.0.1", "IPV4_UNICAST")
        self.assertIn("no apply-policy import-policy", self.d.cfg())

    def test_neighbor_export_policy(self):
        configure_bgp_neighbor_export_policy(self.d, "10.0.0.1", "IPV4_UNICAST", "POL1")
        self.assertIn("apply-policy export-policy [ POL1 ]", self.d.cfg())

    def test_unconfigure_neighbor_export_policy(self):
        unconfigure_bgp_neighbor_export_policy(self.d, "10.0.0.1", "IPV4_UNICAST")
        self.assertIn("no apply-policy export-policy", self.d.cfg())


class TestPeerGroupConfigureApis(unittest.TestCase):
    """configure_bgp_peer_group ... configure_bgp_neighbor_peer_group"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_peer_group(self):
        configure_bgp_peer_group(self.d, "SPINE", peer_as=65010)
        c = self.d.cfg()
        self.assertIn("peer-group SPINE", c)
        self.assertIn("peer-as 65010", c)

    def test_unconfigure_peer_group(self):
        unconfigure_bgp_peer_group(self.d, "SPINE")
        self.assertIn("no peer-group SPINE", self.d.cfg())

    def test_peer_group_bfd(self):
        configure_bgp_peer_group_bfd(self.d, "SPINE", profile="p2")
        c = self.d.cfg()
        self.assertIn("peer-group SPINE", c)
        self.assertIn("bfd enable true", c)
        self.assertIn("bfd profile p2", c)

    def test_unconfigure_peer_group_bfd(self):
        unconfigure_bgp_peer_group_bfd(self.d, "SPINE")
        c = self.d.cfg()
        self.assertIn("no bfd enable", c)
        self.assertIn("no bfd profile", c)

    def test_peer_group_afi_safi(self):
        configure_bgp_peer_group_afi_safi(self.d, "SPINE", "IPV4_UNICAST")
        c = self.d.cfg()
        self.assertIn("peer-group SPINE", c)
        self.assertIn("afi-safi IPV4_UNICAST", c)

    def test_unconfigure_peer_group_afi_safi(self):
        unconfigure_bgp_peer_group_afi_safi(self.d, "SPINE", "IPV4_UNICAST")
        self.assertIn("no afi-safi IPV4_UNICAST", self.d.cfg())

    def test_neighbor_peer_group(self):
        configure_bgp_neighbor_peer_group(self.d, "10.0.0.1", "SPINE")
        c = self.d.cfg()
        self.assertIn("neighbor 10.0.0.1", c)
        self.assertIn("peer-group SPINE", c)

    def test_unconfigure_neighbor_peer_group(self):
        unconfigure_bgp_neighbor_peer_group(self.d, "10.0.0.1")
        self.assertIn("no peer-group", self.d.cfg())


class TestGlobalAfiSafiFeatureApis(unittest.TestCase):
    """configure_bgp_add_paths_calculate, configure_bgp_null_label, configure_bgp_rtfilter"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_add_paths_calculate(self):
        configure_bgp_add_paths_calculate(self.d, "IPV4_UNICAST", "MULTIPATHS")
        self.assertIn("add-paths calculate MULTIPATHS", self.d.cfg())

    def test_unconfigure_add_paths_calculate(self):
        unconfigure_bgp_add_paths_calculate(self.d, "IPV4_UNICAST")
        self.assertIn("no add-paths calculate", self.d.cfg())

    def test_null_label(self):
        configure_bgp_null_label(self.d, "IPV6_LABELED_UNICAST", "EXPLICIT")
        self.assertIn("null-label EXPLICIT", self.d.cfg())

    def test_unconfigure_null_label(self):
        unconfigure_bgp_null_label(self.d, "IPV6_LABELED_UNICAST")
        self.assertIn("no null-label", self.d.cfg())

    def test_rtfilter(self):
        configure_bgp_rtfilter(self.d, "L3VPN_IPV4_UNICAST")
        self.assertIn("rtfilter enabled true", self.d.cfg())

    def test_unconfigure_rtfilter(self):
        unconfigure_bgp_rtfilter(self.d, "L3VPN_IPV4_UNICAST")
        self.assertIn("no rtfilter", self.d.cfg())


class TestGlobalRouteSelectionApis(unittest.TestCase):
    """configure_bgp_ignore_next_hop_igp_metric, drop_upon_invalid_sr_policy, compatibility_l2_attr_local"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_ignore_next_hop_igp_metric(self):
        configure_bgp_ignore_next_hop_igp_metric(self.d)
        self.assertIn("global route-selection-options ignore-next-hop-igp-metric true", self.d.cfg())

    def test_unconfigure_ignore_next_hop_igp_metric(self):
        unconfigure_bgp_ignore_next_hop_igp_metric(self.d)
        self.assertIn("global no route-selection-options ignore-next-hop-igp-metric", self.d.cfg())

    def test_drop_upon_invalid_sr_policy(self):
        configure_bgp_drop_upon_invalid_sr_policy(self.d)
        self.assertIn("global drop-upon-invalid-sr-policy true", self.d.cfg())

    def test_unconfigure_drop_upon_invalid_sr_policy(self):
        unconfigure_bgp_drop_upon_invalid_sr_policy(self.d)
        self.assertIn("global no drop-upon-invalid-sr-policy", self.d.cfg())

    def test_compatibility_l2_attr_local(self):
        configure_bgp_compatibility_l2_attr_local(self.d)
        self.assertIn("global compatibility l2-attr-local true", self.d.cfg())

    def test_unconfigure_compatibility_l2_attr_local(self):
        unconfigure_bgp_compatibility_l2_attr_local(self.d)
        self.assertIn("global no compatibility l2-attr-local", self.d.cfg())


class TestAddPathsApis(unittest.TestCase):
    """configure_bgp_neighbor_add_paths, configure_bgp_peer_group_add_paths"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_neighbor_add_paths(self):
        configure_bgp_neighbor_add_paths(
            self.d, "3.0.0.0", "IPV4_LABELED_UNICAST", send="BACKUP", receive=True
        )
        c = self.d.cfg()
        self.assertIn("add-paths send BACKUP", c)
        self.assertIn("add-paths receive true", c)

    def test_unconfigure_neighbor_add_paths(self):
        unconfigure_bgp_neighbor_add_paths(self.d, "3.0.0.0", "IPV4_LABELED_UNICAST")
        self.assertIn("no add-paths", self.d.cfg())

    def test_peer_group_add_paths(self):
        configure_bgp_peer_group_add_paths(
            self.d, "RR-Peer-Group", "L3VPN_IPV4_UNICAST", send=True, receive=False
        )
        c = self.d.cfg()
        self.assertIn("add-paths send true", c)
        self.assertIn("add-paths receive false", c)

    def test_unconfigure_peer_group_add_paths(self):
        unconfigure_bgp_peer_group_add_paths(self.d, "RR-Peer-Group", "L3VPN_IPV4_UNICAST")
        self.assertIn("no add-paths", self.d.cfg())


class TestPeerGroupPolicyApis(unittest.TestCase):
    """configure_bgp_peer_group_import_policy, configure_bgp_peer_group_export_policy"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_peer_group_import_policy(self):
        configure_bgp_peer_group_import_policy(
            self.d, "access_v4_peer_grp", "IPV4_UNICAST", ["accept_all"]
        )
        self.assertIn("apply-policy import-policy [ accept_all ]", self.d.cfg())

    def test_unconfigure_peer_group_import_policy(self):
        unconfigure_bgp_peer_group_import_policy(self.d, "access_v4_peer_grp", "IPV4_UNICAST")
        self.assertIn("no apply-policy import-policy", self.d.cfg())

    def test_peer_group_export_policy(self):
        configure_bgp_peer_group_export_policy(
            self.d, "RR-Peer-Group", "IPV4_UNICAST", ["ALLOW-ALL"]
        )
        self.assertIn("apply-policy export-policy [ ALLOW-ALL ]", self.d.cfg())

    def test_unconfigure_peer_group_export_policy(self):
        unconfigure_bgp_peer_group_export_policy(self.d, "RR-Peer-Group", "IPV4_UNICAST")
        self.assertIn("no apply-policy export-policy", self.d.cfg())


class TestBgpVrfApis(unittest.TestCase):
    """configure_bgp_route_distinguisher, configure_bgp_route_target, configure_bgp_rt_afi_safi_route_target"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_route_distinguisher(self):
        configure_bgp_route_distinguisher(
            self.d, "1.0.0.0:2001", network_instance="ECMP-L3VPN-01"
        )
        self.assertIn("global route-distinguisher 1.0.0.0:2001", self.d.cfg())

    def test_unconfigure_route_distinguisher(self):
        unconfigure_bgp_route_distinguisher(self.d, network_instance="ECMP-L3VPN-01")
        self.assertIn("no global route-distinguisher", self.d.cfg())

    def test_route_target(self):
        configure_bgp_route_target(
            self.d, "2001:2001", rt_type="both", network_instance="Leaf1-Leaf2-EPLAN-1"
        )
        self.assertIn("route-target 2001:2001 both", self.d.cfg())

    def test_unconfigure_route_target(self):
        unconfigure_bgp_route_target(
            self.d, "2001:2001", rt_type="both", network_instance="Leaf1-Leaf2-EPLAN-1"
        )
        self.assertIn("no route-target 2001:2001 both", self.d.cfg())

    def test_rt_afi_safi_route_target(self):
        configure_bgp_rt_afi_safi_route_target(
            self.d, "L3VPN_IPV4_UNICAST", "201:201", rt_type="both",
            network_instance="ECMP-L3VPN-01",
        )
        c = self.d.cfg()
        self.assertIn("rt-afi-safi L3VPN_IPV4_UNICAST", c)
        self.assertIn("route-target 201:201 both", c)

    def test_unconfigure_rt_afi_safi_route_target(self):
        unconfigure_bgp_rt_afi_safi_route_target(
            self.d, "L3VPN_IPV4_UNICAST", "201:201", rt_type="both",
            network_instance="ECMP-L3VPN-01",
        )
        self.assertIn("no route-target 201:201 both", self.d.cfg())


class TestSrv6L3vpnApis(unittest.TestCase):
    """configure_bgp_srv6_locator, configure_bgp_sid_allocation_mode, configure_bgp_peer_group_extended_nexthop"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_srv6_locator(self):
        configure_bgp_srv6_locator(self.d, "LOC1")
        self.assertIn("global srv6 locator LOC1", self.d.cfg())

    def test_unconfigure_srv6_locator(self):
        unconfigure_bgp_srv6_locator(self.d)
        self.assertIn("no global srv6 locator", self.d.cfg())

    def test_sid_allocation_mode(self):
        configure_bgp_sid_allocation_mode(self.d, "PER_NEXTHOP", network_instance="VRF1")
        self.assertIn("global sid-allocation-mode PER_NEXTHOP", self.d.cfg())

    def test_unconfigure_sid_allocation_mode(self):
        unconfigure_bgp_sid_allocation_mode(self.d, network_instance="VRF1")
        self.assertIn("no global sid-allocation-mode", self.d.cfg())

    def test_peer_group_extended_nexthop(self):
        configure_bgp_peer_group_extended_nexthop(self.d, "SPINE", "L3VPN_IPV4_UNICAST")
        c = self.d.cfg()
        self.assertIn("peer-group SPINE", c)
        self.assertIn("extended-nexthop enable true", c)

    def test_unconfigure_peer_group_extended_nexthop(self):
        unconfigure_bgp_peer_group_extended_nexthop(self.d, "SPINE", "L3VPN_IPV4_UNICAST")
        self.assertIn("no extended-nexthop", self.d.cfg())


class TestBestPathSelectionApis(unittest.TestCase):
    """configure-only knobs: no unconfigure_* counterpart exists in the source."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_multipath_as_path_relax(self):
        configure_bgp_multipath_as_path_relax(self.d)
        self.assertIn(
            "global route-selection-options multipath as-path-relax true", self.d.cfg()
        )

    def test_med_missing_as_worst(self):
        configure_bgp_med_missing_as_worst(self.d)
        self.assertIn(
            "global route-selection-options med-missing-as-worst true", self.d.cfg()
        )

    def test_multipath_evpn_etree_ead_relax(self):
        configure_bgp_multipath_evpn_etree_ead_relax(self.d)
        self.assertIn(
            "global route-selection-options multipath-evpn-etree-ead-relax true",
            self.d.cfg(),
        )


class TestErplApis(unittest.TestCase):
    """configure_bgp_erpl_server, configure_bgp_erpl_connection_wait_time, configure_bgp_neighbor_apply_erpl"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_erpl_server(self):
        configure_bgp_erpl_server(self.d, "SRV1", "10.0.0.5", 9000, preference=100)
        c = self.d.cfg()
        self.assertIn("erpl server SRV1", c)
        self.assertIn("address 10.0.0.5", c)
        self.assertIn("port 9000", c)
        self.assertIn("preference 100", c)

    def test_unconfigure_erpl_server(self):
        unconfigure_bgp_erpl_server(self.d, "SRV1")
        self.assertIn("no erpl server SRV1", self.d.cfg())

    def test_erpl_connection_wait_time(self):
        configure_bgp_erpl_connection_wait_time(self.d, 30)
        self.assertIn("erpl connection-wait-time 30", self.d.cfg())

    def test_neighbor_apply_erpl(self):
        configure_bgp_neighbor_apply_erpl(self.d, "10.0.0.1", "IPV4_UNICAST", "ERPL_POL")
        self.assertIn("apply-erpl import-policy ERPL_POL", self.d.cfg())

    def test_unconfigure_neighbor_apply_erpl(self):
        unconfigure_bgp_neighbor_apply_erpl(self.d, "10.0.0.1", "IPV4_UNICAST")
        self.assertIn("no apply-erpl import-policy", self.d.cfg())


class TestPicApis(unittest.TestCase):
    """configure_bgp_install_backup, configure_bgp_advertise_best_external"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_install_backup(self):
        configure_bgp_install_backup(self.d, "IPV4_UNICAST")
        self.assertIn("add-paths install-backup true", self.d.cfg())

    def test_unconfigure_install_backup(self):
        unconfigure_bgp_install_backup(self.d, "IPV4_UNICAST")
        self.assertIn("no add-paths install-backup", self.d.cfg())

    def test_advertise_best_external(self):
        configure_bgp_advertise_best_external(self.d, "IPV4_UNICAST")
        self.assertIn("advertise-best-external true", self.d.cfg())

    def test_unconfigure_advertise_best_external(self):
        unconfigure_bgp_advertise_best_external(self.d, "IPV4_UNICAST")
        self.assertIn("no advertise-best-external", self.d.cfg())


class TestNeighborTimersAndGracefulRestart(unittest.TestCase):
    """configure_bgp_neighbor_timers, configure_bgp_graceful_restart"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_neighbor_timers(self):
        configure_bgp_neighbor_timers(
            self.d, "10.0.0.1", keepalive_interval=10, hold_time=30,
            minimum_advertisement_interval=5,
        )
        c = self.d.cfg()
        self.assertIn("timers keepalive-interval 10 hold-time 30", c)
        self.assertIn("timers minimum-advertisement-interval 5", c)

    def test_unconfigure_neighbor_timers(self):
        unconfigure_bgp_neighbor_timers(self.d, "10.0.0.1")
        self.assertIn("no timers", self.d.cfg())

    def test_graceful_restart(self):
        configure_bgp_graceful_restart(
            self.d, enabled=True, helper_only=False, restart_time=120,
            stale_routes_time=300,
        )
        c = self.d.cfg()
        self.assertIn("global graceful-restart enabled true", c)
        self.assertIn("global graceful-restart helper-only false", c)
        self.assertIn("global graceful-restart restart-time 120", c)
        self.assertIn("global graceful-restart stale-routes-time 300", c)

    def test_unconfigure_graceful_restart(self):
        unconfigure_bgp_graceful_restart(self.d)
        self.assertIn("no global graceful-restart", self.d.cfg())


class TestNeighborMaxPrefixApis(unittest.TestCase):
    """configure_bgp_neighbor_max_prefix"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_neighbor_max_prefix(self):
        configure_bgp_neighbor_max_prefix(
            self.d, "10.0.0.1", "IPV4_UNICAST", 1000,
            warning_threshold_pct=80, prevent_teardown=True, restart_timer=300,
        )
        c = self.d.cfg()
        self.assertIn("ipv4-unicast prefix-limit max-prefixes 1000", c)
        self.assertIn("ipv4-unicast prefix-limit warning-threshold-pct 80", c)
        self.assertIn("ipv4-unicast prefix-limit prevent-teardown true", c)
        self.assertIn("ipv4-unicast prefix-limit restart-timer 300", c)

    def test_unconfigure_neighbor_max_prefix(self):
        unconfigure_bgp_neighbor_max_prefix(self.d, "10.0.0.1", "IPV4_UNICAST")
        self.assertIn("no ipv4-unicast prefix-limit", self.d.cfg())




class TestBgpConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure/unconfigure function in
    bgp/configure.py must be referenced by name somewhere in this test
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
            f"Uncovered bgp configure functions: {missing}")
if __name__ == "__main__":
    unittest.main()
