#!/usr/bin/env python3
"""Full-coverage unit tests for arcOS ISIS configure_*/unconfigure_* APIs.

Every function in genie.libs.sdk.apis.arcos.isis.configure is exercised at
least once against a mock device whose `.configure` is a Mock. Assertions
target distinctive substrings of the CLI the function actually builds (read
directly from source, not guessed).
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.isis.configure import (
    # Category 1: NET / instance
    configure_isis_net_address,
    unconfigure_isis_net_address,
    configure_isis_instance,
    unconfigure_isis_instance,
    # Category 2: interface enablement
    configure_isis_interface_ipv4,
    configure_isis_interface_ipv6,
    configure_isis_interface,
    unconfigure_isis_interface_ipv4,
    unconfigure_isis_interface_ipv6,
    unconfigure_isis_interface,
    configure_isis_interface_enabled,
    unconfigure_isis_interface_enabled,
    # Interface metric / network-type
    configure_isis_interface_metric,
    unconfigure_isis_interface_metric,
    configure_isis_interface_network_type,
    unconfigure_isis_interface_network_type,
    # Level type
    configure_isis_level_type,
    unconfigure_isis_level_type,
    # Passive interface
    configure_isis_passive_interface,
    unconfigure_isis_passive_interface,
    # Interface authentication
    configure_isis_interface_hello_authentication,
    unconfigure_isis_interface_hello_authentication,
    configure_isis_interface_auth_keychain,
    unconfigure_isis_interface_auth_keychain,
    configure_isis_interface_auth_simple_key,
    unconfigure_isis_interface_auth_simple_key,
    configure_isis_interface_auth_password,
    unconfigure_isis_interface_auth_password,
    # Level-context PDU authentication
    configure_isis_lsp_authentication,
    unconfigure_isis_lsp_authentication,
    configure_isis_csnp_authentication,
    unconfigure_isis_csnp_authentication,
    configure_isis_psnp_authentication,
    unconfigure_isis_psnp_authentication,
    # Max ECMP
    configure_isis_max_ecmp_paths,
    unconfigure_isis_max_ecmp_paths,
    # Timers
    configure_isis_spf_intervals,
    unconfigure_isis_spf_intervals,
    configure_isis_lsp_lifetime_interval,
    unconfigure_isis_lsp_lifetime_interval,
    configure_isis_lsp_refresh_interval,
    unconfigure_isis_lsp_refresh_interval,
    configure_isis_interface_hello_interval,
    unconfigure_isis_interface_hello_interval,
    configure_isis_interface_hello_multiplier,
    unconfigure_isis_interface_hello_multiplier,
    # Graceful restart
    configure_isis_graceful_restart,
    unconfigure_isis_graceful_restart,
    # Interface BFD
    configure_isis_interface_bfd,
    unconfigure_isis_interface_bfd,
    # Prefix-SID
    configure_isis_interface_ipv4_prefix_sid,
    unconfigure_isis_interface_ipv4_prefix_sid,
    configure_isis_interface_ipv6_prefix_sid,
    unconfigure_isis_interface_ipv6_prefix_sid,
    # Adjacency-SID
    configure_isis_interface_ipv4_adjacency_sid,
    unconfigure_isis_interface_ipv4_adjacency_sid,
    configure_isis_interface_ipv6_adjacency_sid,
    unconfigure_isis_interface_ipv6_adjacency_sid,
    # TI-LFA
    configure_isis_interface_ipv4_ti_lfa_sr_mpls,
    unconfigure_isis_interface_ipv4_ti_lfa_sr_mpls,
    configure_isis_interface_ipv6_ti_lfa_sr_mpls,
    unconfigure_isis_interface_ipv6_ti_lfa_sr_mpls,
    configure_isis_interface_ipv6_ti_lfa_srv6,
    unconfigure_isis_interface_ipv6_ti_lfa_srv6,
    # Segment routing
    configure_isis_segment_routing,
    unconfigure_isis_segment_routing,
    # Table connection
    configure_table_connection,
    unconfigure_table_connection,
    configure_table_connection_policy,
    unconfigure_table_connection_policy,
    # Overload bit
    configure_isis_overload_bit,
    unconfigure_isis_overload_bit,
    # LSP MTU
    configure_isis_lsp_mtu,
    unconfigure_isis_lsp_mtu,
    # Summary address
    configure_isis_summary_address_ipv4,
    unconfigure_isis_summary_address_ipv4,
    configure_isis_summary_address_ipv6,
    unconfigure_isis_summary_address_ipv6,
    # IPv6 multi-topology
    configure_isis_ipv6_multi_topology,
    unconfigure_isis_ipv6_multi_topology,
    # Level import policy
    configure_isis_level_import_policy,
    unconfigure_isis_level_import_policy,
    # Flexible algorithm
    configure_isis_flexible_algorithm,
    unconfigure_isis_flexible_algorithm,
    configure_isis_interface_flex_algo_admin_groups,
    unconfigure_isis_interface_flex_algo_admin_groups,
    configure_isis_interface_flex_algo_metric,
    unconfigure_isis_interface_flex_algo_metric,
    # Traffic engineering
    configure_isis_traffic_engineering_router_id,
    unconfigure_isis_traffic_engineering_router_id,
    configure_isis_level_traffic_engineering,
    unconfigure_isis_level_traffic_engineering,
    # Flex-algo priority / admin-groups (global)
    configure_isis_flexible_algorithm_priority,
    unconfigure_isis_flexible_algorithm_priority,
    configure_isis_flexible_algorithm_admin_groups,
    unconfigure_isis_flexible_algorithm_admin_groups,
    # Dynamic delay measurement
    configure_isis_dynamic_delay_measurement,
    unconfigure_isis_dynamic_delay_measurement,
    configure_isis_interface_flex_algo_delay_metric_dynamic,
    unconfigure_isis_interface_flex_algo_delay_metric_dynamic,
    # SRMS
    configure_isis_srms_mapping,
    unconfigure_isis_srms_mapping,
    configure_isis_srms_receive,
    unconfigure_isis_srms_receive,
    configure_isis_srms_advertise,
    unconfigure_isis_srms_advertise,
    # Auto-cost
    configure_isis_auto_cost_reference_bandwidth,
    unconfigure_isis_auto_cost_reference_bandwidth,
    # MPLS LDP sync
    configure_isis_mpls_ldp_sync,
    unconfigure_isis_mpls_ldp_sync,
    # Global hello auth
    configure_isis_global_hello_auth,
    unconfigure_isis_global_hello_auth,
    # Micro-loop avoidance
    configure_isis_micro_loop_avoidance_sr_mpls,
    unconfigure_isis_micro_loop_avoidance_sr_mpls,
    configure_isis_micro_loop_avoidance_srv6,
    unconfigure_isis_micro_loop_avoidance_srv6,
    configure_isis_micro_loop_avoidance_rib_update_delay,
    unconfigure_isis_micro_loop_avoidance_rib_update_delay,
    # LSP first-wait interval
    configure_isis_lsp_first_wait_interval,
    unconfigure_isis_lsp_first_wait_interval,
    # Interface CSNP / LSP pacing intervals
    configure_isis_interface_csnp_interval,
    unconfigure_isis_interface_csnp_interval,
    configure_isis_interface_lsp_pacing_interval,
    unconfigure_isis_interface_lsp_pacing_interval,
    # Interface per-level hello timers
    configure_isis_interface_level_hello_interval,
    unconfigure_isis_interface_level_hello_interval,
    configure_isis_interface_level_hello_multiplier,
    unconfigure_isis_interface_level_hello_multiplier,
    # Default information originate
    configure_isis_default_information_originate,
    unconfigure_isis_default_information_originate,
    # Labeled preference
    configure_isis_level_labeled_preference,
    unconfigure_isis_level_labeled_preference,
    # Attached bit
    configure_isis_attached_bit_ignore,
    unconfigure_isis_attached_bit_ignore,
    configure_isis_attached_bit_suppress,
    unconfigure_isis_attached_bit_suppress,
    # Interface per-level priority
    configure_isis_interface_level_priority,
    unconfigure_isis_interface_level_priority,
    # Level authentication (global level context)
    configure_isis_level_auth_keychain,
    unconfigure_isis_level_auth_keychain,
    configure_isis_level_auth_simple_key,
    unconfigure_isis_level_auth_simple_key,
    configure_isis_level_auth_password,
    unconfigure_isis_level_auth_password,
    # Interface per-level LAN hello authentication
    configure_isis_interface_level_hello_authentication,
    unconfigure_isis_interface_level_hello_authentication,
    configure_isis_interface_level_hello_auth_keychain,
    unconfigure_isis_interface_level_hello_auth_keychain,
    configure_isis_interface_level_hello_auth_simple_key,
    unconfigure_isis_interface_level_hello_auth_simple_key,
    configure_isis_interface_level_hello_auth_password,
    unconfigure_isis_interface_level_hello_auth_password,
    # Global address family
    configure_isis_address_family,
    unconfigure_isis_address_family,
    # SRv6
    configure_isis_srv6,
    unconfigure_isis_srv6,
    configure_isis_srv6_locator,
    unconfigure_isis_srv6_locator,
)


class _CfgDevice:
    """Mimics a pyATS device object with a mocked .configure()."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestIsisNetAndInstance(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_net_address(self):
        configure_isis_net_address(self.d, "49.0001.1921.6800.1001.00", protocol_instance="isis1")
        c = self.d.cfg()
        self.assertIn("network-instance default protocol ISIS isis1", c)
        self.assertIn("global net [ 49.0001.1921.6800.1001.00 ]", c)

    def test_unconfigure_isis_net_address(self):
        unconfigure_isis_net_address(self.d, "49.0001.1921.6800.1001.00")
        self.assertIn("no global net [ 49.0001.1921.6800.1001.00 ]", self.d.cfg())

    def test_configure_isis_instance(self):
        configure_isis_instance(self.d, protocol_instance="isis1")
        self.assertIn("network-instance default protocol ISIS isis1", self.d.cfg())

    def test_unconfigure_isis_instance(self):
        unconfigure_isis_instance(self.d, protocol_instance="isis1")
        self.assertIn("no network-instance default protocol ISIS isis1", self.d.cfg())


class TestIsisInterfaceEnablement(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_ipv4(self):
        configure_isis_interface_ipv4(self.d, "swp1", level="level_1_2")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("af IPV4 UNICAST", c)
        self.assertIn("level 1", c)
        self.assertIn("level 2", c)

    def test_configure_isis_interface_ipv6(self):
        configure_isis_interface_ipv6(self.d, "swp1", level="level_2")
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("level 2", c)

    def test_configure_isis_interface_both(self):
        configure_isis_interface(self.d, "swp1", ipv4=True, ipv6=True, level="level_1")
        # Composite wrapper: called twice (once per AF)
        self.assertEqual(self.d.configure.call_count, 2)

    def test_unconfigure_isis_interface_ipv4(self):
        unconfigure_isis_interface_ipv4(self.d, "swp1")
        self.assertIn("no af IPV4 UNICAST", self.d.cfg())

    def test_unconfigure_isis_interface_ipv6(self):
        unconfigure_isis_interface_ipv6(self.d, "swp1")
        self.assertIn("no af IPV6 UNICAST", self.d.cfg())

    def test_unconfigure_isis_interface_both(self):
        unconfigure_isis_interface(self.d, "swp1", ipv4=True, ipv6=True)
        self.assertEqual(self.d.configure.call_count, 2)

    def test_configure_isis_interface_enabled(self):
        configure_isis_interface_enabled(self.d, "swp5", enabled=False)
        self.assertIn("enabled false", self.d.cfg())

    def test_unconfigure_isis_interface_enabled(self):
        unconfigure_isis_interface_enabled(self.d, "swp5")
        self.assertIn("no enabled", self.d.cfg())


class TestIsisInterfaceMetricAndNetworkType(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_metric(self):
        configure_isis_interface_metric(self.d, "swp1", 10, "level_2")
        self.assertIn("level 2 metric 10", self.d.cfg())

    def test_unconfigure_isis_interface_metric(self):
        unconfigure_isis_interface_metric(self.d, "swp1", "level_2")
        self.assertIn("no level 2 metric", self.d.cfg())

    def test_configure_isis_interface_network_type(self):
        configure_isis_interface_network_type(self.d, "swp1", "point_to_point")
        self.assertIn("network-type POINT_TO_POINT", self.d.cfg())

    def test_unconfigure_isis_interface_network_type(self):
        unconfigure_isis_interface_network_type(self.d, "swp1")
        self.assertIn("no network-type", self.d.cfg())


class TestIsisLevelType(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_level_type(self):
        configure_isis_level_type(self.d, "level_1_2")
        c = self.d.cfg()
        self.assertIn("global level-capability LEVEL_1_2", c)
        self.assertIn("level 1", c)
        self.assertIn("level 2", c)

    def test_unconfigure_isis_level_type(self):
        unconfigure_isis_level_type(self.d)
        c = self.d.cfg()
        self.assertIn("no global level-capability", c)
        self.assertIn("enabled false", c)


class TestIsisPassiveInterface(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_passive_interface(self):
        configure_isis_passive_interface(self.d, "swp1")
        self.assertIn("passive true", self.d.cfg())

    def test_unconfigure_isis_passive_interface(self):
        unconfigure_isis_passive_interface(self.d, "swp1")
        self.assertIn("no passive", self.d.cfg())


class TestIsisInterfaceAuthentication(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_hello_authentication(self):
        configure_isis_interface_hello_authentication(self.d, "swp1", enabled=True)
        self.assertIn("authentication hello-authentication true", self.d.cfg())

    def test_unconfigure_isis_interface_hello_authentication(self):
        unconfigure_isis_interface_hello_authentication(self.d, "swp1")
        self.assertIn("no authentication hello-authentication", self.d.cfg())

    def test_configure_isis_interface_auth_keychain(self):
        configure_isis_interface_auth_keychain(self.d, "swp1", "isis_keychain1")
        c = self.d.cfg()
        self.assertIn("authentication auth-type KEYCHAIN", c)
        self.assertIn("authentication keychain isis_keychain1", c)

    def test_unconfigure_isis_interface_auth_keychain(self):
        unconfigure_isis_interface_auth_keychain(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("no authentication auth-type", c)
        self.assertIn("no authentication keychain", c)

    def test_configure_isis_interface_auth_simple_key(self):
        configure_isis_interface_auth_simple_key(self.d, "swp1", "mypassword123")
        c = self.d.cfg()
        self.assertIn("authentication auth-type SIMPLE_KEY", c)
        self.assertIn("authentication key crypto-algorithm MD5", c)
        self.assertIn("authentication key auth-password mypassword123", c)

    def test_configure_isis_interface_auth_simple_key_bad_algo(self):
        with self.assertRaises(ValueError):
            configure_isis_interface_auth_simple_key(self.d, "swp1", "pw", crypto_algorithm="SHA1")

    def test_unconfigure_isis_interface_auth_simple_key(self):
        unconfigure_isis_interface_auth_simple_key(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("no authentication auth-type", c)
        self.assertIn("no authentication key", c)

    def test_configure_isis_interface_auth_password(self):
        configure_isis_interface_auth_password(self.d, "swp1", "newpassword456")
        self.assertIn("authentication key auth-password newpassword456", self.d.cfg())

    def test_unconfigure_isis_interface_auth_password(self):
        unconfigure_isis_interface_auth_password(self.d, "swp1")
        self.assertIn("no authentication key auth-password", self.d.cfg())


class TestIsisLevelPduAuthentication(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_lsp_authentication(self):
        configure_isis_lsp_authentication(self.d, level="level_2", enabled=True)
        c = self.d.cfg()
        self.assertIn("level 2", c)
        self.assertIn("authentication lsp-authentication true", c)

    def test_unconfigure_isis_lsp_authentication(self):
        unconfigure_isis_lsp_authentication(self.d, level="level_2")
        self.assertIn("no authentication lsp-authentication", self.d.cfg())

    def test_configure_isis_csnp_authentication(self):
        configure_isis_csnp_authentication(self.d, level="level_1", enabled=False)
        c = self.d.cfg()
        self.assertIn("level 1", c)
        self.assertIn("authentication csnp-authentication false", c)

    def test_unconfigure_isis_csnp_authentication(self):
        unconfigure_isis_csnp_authentication(self.d, level="level_1")
        self.assertIn("no authentication csnp-authentication", self.d.cfg())

    def test_configure_isis_psnp_authentication(self):
        configure_isis_psnp_authentication(self.d, level="level_2", enabled=True)
        self.assertIn("authentication psnp-authentication true", self.d.cfg())

    def test_unconfigure_isis_psnp_authentication(self):
        unconfigure_isis_psnp_authentication(self.d, level="level_2")
        self.assertIn("no authentication psnp-authentication", self.d.cfg())


class TestIsisMaxEcmpPaths(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_max_ecmp_paths(self):
        configure_isis_max_ecmp_paths(self.d, 8)
        self.assertIn("global max-ecmp-paths 8", self.d.cfg())

    def test_configure_isis_max_ecmp_paths_out_of_range(self):
        with self.assertRaises(ValueError):
            configure_isis_max_ecmp_paths(self.d, 128)

    def test_unconfigure_isis_max_ecmp_paths(self):
        unconfigure_isis_max_ecmp_paths(self.d)
        self.assertIn("no global max-ecmp-paths", self.d.cfg())


class TestIsisTimers(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_spf_intervals(self):
        configure_isis_spf_intervals(self.d, first_interval=50, hold_interval=200,
                                      second_interval=5000, mla_interval=100)
        c = self.d.cfg()
        self.assertIn("global timers spf spf-first-interval 50", c)
        self.assertIn("global timers spf spf-hold-interval 200", c)
        self.assertIn("global timers spf spf-second-interval 5000", c)
        self.assertIn("global timers spf spf-mla-interval 100", c)

    def test_configure_isis_spf_intervals_none_given(self):
        with self.assertRaises(ValueError):
            configure_isis_spf_intervals(self.d)

    def test_unconfigure_isis_spf_intervals(self):
        unconfigure_isis_spf_intervals(self.d)
        c = self.d.cfg()
        self.assertIn("no global timers spf spf-first-interval", c)
        self.assertIn("no global timers spf spf-mla-interval", c)

    def test_configure_isis_lsp_lifetime_interval(self):
        configure_isis_lsp_lifetime_interval(self.d, 1200)
        self.assertIn("global timers lsp-lifetime-interval 1200", self.d.cfg())

    def test_unconfigure_isis_lsp_lifetime_interval(self):
        unconfigure_isis_lsp_lifetime_interval(self.d)
        self.assertIn("no global timers lsp-lifetime-interval", self.d.cfg())

    def test_configure_isis_lsp_refresh_interval(self):
        configure_isis_lsp_refresh_interval(self.d, 600)
        self.assertIn("global timers lsp-refresh-interval 600", self.d.cfg())

    def test_unconfigure_isis_lsp_refresh_interval(self):
        unconfigure_isis_lsp_refresh_interval(self.d)
        self.assertIn("no global timers lsp-refresh-interval", self.d.cfg())

    def test_configure_isis_interface_hello_interval(self):
        configure_isis_interface_hello_interval(self.d, "swp1", 5)
        self.assertIn("timers hello-interval 5", self.d.cfg())

    def test_unconfigure_isis_interface_hello_interval(self):
        unconfigure_isis_interface_hello_interval(self.d, "swp1")
        self.assertIn("no timers hello-interval", self.d.cfg())

    def test_configure_isis_interface_hello_multiplier(self):
        configure_isis_interface_hello_multiplier(self.d, "swp1", 3)
        self.assertIn("timers hello-multiplier 3", self.d.cfg())

    def test_unconfigure_isis_interface_hello_multiplier(self):
        unconfigure_isis_interface_hello_multiplier(self.d, "swp1")
        self.assertIn("no timers hello-multiplier", self.d.cfg())


class TestIsisGracefulRestart(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_graceful_restart(self):
        configure_isis_graceful_restart(self.d, enabled=True)
        self.assertIn("global graceful-restart enabled true", self.d.cfg())

    def test_unconfigure_isis_graceful_restart(self):
        unconfigure_isis_graceful_restart(self.d)
        self.assertIn("no global graceful-restart enabled", self.d.cfg())


class TestIsisInterfaceBfd(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_bfd(self):
        configure_isis_interface_bfd(self.d, "swp1", profile="p1", enabled=True)
        c = self.d.cfg()
        self.assertIn("bfd bfd-tlv true", c)
        self.assertIn("bfd profile p1", c)

    def test_unconfigure_isis_interface_bfd(self):
        unconfigure_isis_interface_bfd(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("no bfd bfd-tlv", c)
        self.assertIn("no bfd profile", c)


class TestIsisPrefixSid(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_ipv4_prefix_sid(self):
        configure_isis_interface_ipv4_prefix_sid(self.d, "swp1", "INDEX", 100,
                                                  label_option="EXPLICIT_NULL",
                                                  clear_n_flag=True)
        c = self.d.cfg()
        self.assertIn("af IPV4 UNICAST", c)
        self.assertIn("prefix-sid SPF", c)
        self.assertIn("sid-type INDEX", c)
        self.assertIn("value 100", c)
        self.assertIn("label-option EXPLICIT_NULL", c)
        self.assertIn("clear-n-flag true", c)

    def test_unconfigure_isis_interface_ipv4_prefix_sid(self):
        unconfigure_isis_interface_ipv4_prefix_sid(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("af IPV4 UNICAST", c)
        self.assertIn("no prefix-sid SPF", c)

    def test_configure_isis_interface_ipv6_prefix_sid(self):
        configure_isis_interface_ipv6_prefix_sid(self.d, "swp1", "INDEX", 200)
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("prefix-sid SPF", c)
        self.assertIn("value 200", c)

    def test_unconfigure_isis_interface_ipv6_prefix_sid(self):
        unconfigure_isis_interface_ipv6_prefix_sid(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("no prefix-sid SPF", c)


class TestIsisAdjacencySid(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_ipv4_adjacency_sid(self):
        configure_isis_interface_ipv4_adjacency_sid(self.d, "swp1", "INDEX", 300)
        c = self.d.cfg()
        self.assertIn("af IPV4 UNICAST", c)
        self.assertIn("adjacency-sid POINT_TO_POINT", c)
        self.assertIn("value 300", c)

    def test_unconfigure_isis_interface_ipv4_adjacency_sid(self):
        unconfigure_isis_interface_ipv4_adjacency_sid(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("no adjacency-sid POINT_TO_POINT", c)

    def test_configure_isis_interface_ipv6_adjacency_sid(self):
        configure_isis_interface_ipv6_adjacency_sid(self.d, "swp1", "INDEX", 400)
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("adjacency-sid POINT_TO_POINT", c)
        self.assertIn("value 400", c)

    def test_unconfigure_isis_interface_ipv6_adjacency_sid(self):
        unconfigure_isis_interface_ipv6_adjacency_sid(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("no adjacency-sid POINT_TO_POINT", c)


class TestIsisTiLfa(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_ipv4_ti_lfa_sr_mpls(self):
        configure_isis_interface_ipv4_ti_lfa_sr_mpls(self.d, "swp1", enabled=True)
        c = self.d.cfg()
        self.assertIn("af IPV4 UNICAST", c)
        self.assertIn("fast-reroute ti-lfa sr-mpls enabled true", c)

    def test_unconfigure_isis_interface_ipv4_ti_lfa_sr_mpls(self):
        unconfigure_isis_interface_ipv4_ti_lfa_sr_mpls(self.d, "swp1")
        self.assertIn("no fast-reroute ti-lfa sr-mpls", self.d.cfg())

    def test_configure_isis_interface_ipv6_ti_lfa_sr_mpls(self):
        configure_isis_interface_ipv6_ti_lfa_sr_mpls(self.d, "swp1", enabled=True)
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("fast-reroute ti-lfa sr-mpls enabled true", c)

    def test_unconfigure_isis_interface_ipv6_ti_lfa_sr_mpls(self):
        unconfigure_isis_interface_ipv6_ti_lfa_sr_mpls(self.d, "swp1")
        self.assertIn("no fast-reroute ti-lfa sr-mpls", self.d.cfg())

    def test_configure_isis_interface_ipv6_ti_lfa_srv6(self):
        configure_isis_interface_ipv6_ti_lfa_srv6(self.d, "swp1", enabled=True)
        c = self.d.cfg()
        self.assertIn("af IPV6 UNICAST", c)
        self.assertIn("fast-reroute ti-lfa srv6 enabled true", c)

    def test_unconfigure_isis_interface_ipv6_ti_lfa_srv6(self):
        unconfigure_isis_interface_ipv6_ti_lfa_srv6(self.d, "swp1")
        self.assertIn("no fast-reroute ti-lfa srv6", self.d.cfg())


class TestIsisSegmentRouting(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_segment_routing(self):
        configure_isis_segment_routing(self.d, enabled=True)
        self.assertIn("global segment-routing enabled true", self.d.cfg())

    def test_unconfigure_isis_segment_routing(self):
        unconfigure_isis_segment_routing(self.d)
        self.assertIn("no global segment-routing enabled", self.d.cfg())


class TestTableConnection(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_table_connection(self):
        configure_table_connection(self.d, "STATIC", "ISIS", "IPV4",
                                    import_policy=["POL1", "POL2"])
        c = self.d.cfg()
        self.assertIn("table-connection STATIC ISIS IPV4", c)
        self.assertIn("src-dst-instance default default", c)
        self.assertIn("import-policy [ POL1 POL2 ]", c)

    def test_configure_table_connection_invalid_source(self):
        with self.assertRaises(ValueError):
            configure_table_connection(self.d, "BOGUS", "ISIS", "IPV4")

    def test_unconfigure_table_connection(self):
        unconfigure_table_connection(self.d, "STATIC", "ISIS", "IPV4")
        c = self.d.cfg()
        self.assertIn("no table-connection STATIC ISIS IPV4", c)
        self.assertIn("src-dst-instance default default", c)

    def test_configure_table_connection_policy(self):
        configure_table_connection_policy(self.d, "STATIC", "ISIS", "IPV4", ["POL1"])
        c = self.d.cfg()
        self.assertIn("table-connection STATIC ISIS IPV4", c)
        self.assertIn("import-policy [ POL1 ]", c)

    def test_unconfigure_table_connection_policy(self):
        unconfigure_table_connection_policy(self.d, "STATIC", "ISIS", "IPV4")
        c = self.d.cfg()
        self.assertIn("table-connection STATIC ISIS IPV4", c)
        self.assertIn("no import-policy", c)


class TestIsisOverloadBit(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_overload_bit_set_bit(self):
        configure_isis_overload_bit(self.d, "set-bit")
        c = self.d.cfg()
        self.assertIn("global lsp-bit overload-bit set-bit true", c)

    def test_configure_isis_overload_bit_set_bit_on_boot_wait_delay(self):
        configure_isis_overload_bit(self.d, "set-bit-on-boot",
                                     reset_trigger="WAIT_DELAY", wait_delay=30)
        c = self.d.cfg()
        self.assertIn("global lsp-bit overload-bit set-bit-on-boot true", c)
        self.assertIn("global lsp-bit overload-bit reset-trigger WAIT_DELAY", c)
        self.assertIn("delay 30", c)

    def test_configure_isis_overload_bit_invalid_mode(self):
        with self.assertRaises(ValueError):
            configure_isis_overload_bit(self.d, "bogus-mode")

    def test_unconfigure_isis_overload_bit(self):
        unconfigure_isis_overload_bit(self.d)
        c = self.d.cfg()
        self.assertIn("no global lsp-bit overload-bit set-bit", c)
        self.assertIn("no global lsp-bit overload-bit reset-trigger", c)


class TestIsisLspMtu(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_lsp_mtu(self):
        configure_isis_lsp_mtu(self.d, 1492)
        self.assertIn("global transport lsp-mtu-size 1492", self.d.cfg())

    def test_unconfigure_isis_lsp_mtu(self):
        unconfigure_isis_lsp_mtu(self.d)
        self.assertIn("no global transport lsp-mtu-size", self.d.cfg())


class TestIsisSummaryAddress(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_summary_address_ipv4(self):
        configure_isis_summary_address_ipv4(self.d, "10.0.0.0/8", metric=20,
                                             level="level_2", tag=100,
                                             adv_unreachable=True,
                                             apply_policy=["POL1"],
                                             unreachable_component_tag=5)
        c = self.d.cfg()
        self.assertIn("global af IPV4 UNICAST", c)
        self.assertIn("summary-prefix 10.0.0.0/8", c)
        self.assertIn("metric 20", c)
        self.assertIn("level level_2", c)
        self.assertIn("tag 100", c)
        self.assertIn("adv-unreachable true", c)
        self.assertIn("apply-policy [ POL1 ]", c)
        self.assertIn("unreachable-component-tag 5", c)

    def test_unconfigure_isis_summary_address_ipv4(self):
        unconfigure_isis_summary_address_ipv4(self.d, "10.0.0.0/8")
        c = self.d.cfg()
        self.assertIn("global af IPV4 UNICAST", c)
        self.assertIn("no summary-prefix 10.0.0.0/8", c)

    def test_configure_isis_summary_address_ipv6(self):
        configure_isis_summary_address_ipv6(self.d, "2001:db8::/32", metric=30)
        c = self.d.cfg()
        self.assertIn("global af IPV6 UNICAST", c)
        self.assertIn("summary-prefix 2001:db8::/32", c)
        self.assertIn("metric 30", c)

    def test_unconfigure_isis_summary_address_ipv6(self):
        unconfigure_isis_summary_address_ipv6(self.d, "2001:db8::/32")
        c = self.d.cfg()
        self.assertIn("global af IPV6 UNICAST", c)
        self.assertIn("no summary-prefix 2001:db8::/32", c)


class TestIsisIpv6MultiTopology(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_ipv6_multi_topology(self):
        configure_isis_ipv6_multi_topology(self.d, enabled=True)
        c = self.d.cfg()
        self.assertIn("global af IPV6 UNICAST", c)
        self.assertIn("multi-topology enabled true", c)

    def test_unconfigure_isis_ipv6_multi_topology(self):
        unconfigure_isis_ipv6_multi_topology(self.d)
        c = self.d.cfg()
        self.assertIn("no multi-topology enabled", c)


class TestIsisLevelImportPolicy(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_level_import_policy(self):
        configure_isis_level_import_policy(self.d, "level1-to-level2", "POL1")
        c = self.d.cfg()
        self.assertIn(
            "global inter-level-propagation-policies level1-to-level2 import-policy POL1", c)

    def test_configure_isis_level_import_policy_invalid_direction(self):
        with self.assertRaises(ValueError):
            configure_isis_level_import_policy(self.d, "bogus", "POL1")

    def test_unconfigure_isis_level_import_policy(self):
        unconfigure_isis_level_import_policy(self.d, "level2-to-level1")
        c = self.d.cfg()
        self.assertIn(
            "global no inter-level-propagation-policies level2-to-level1 import-policy", c)

    def test_unconfigure_isis_level_import_policy_invalid_direction(self):
        with self.assertRaises(ValueError):
            unconfigure_isis_level_import_policy(self.d, "bogus")


class TestIsisFlexibleAlgorithm(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_flexible_algorithm(self):
        configure_isis_flexible_algorithm(self.d, 128, metric_type="TE",
                                           advertise_definition=True)
        c = self.d.cfg()
        self.assertIn("global flexible-algorithm 128", c)
        self.assertIn("metric-type TE", c)
        self.assertIn("advertise-definition enabled true", c)

    def test_unconfigure_isis_flexible_algorithm(self):
        unconfigure_isis_flexible_algorithm(self.d, 128)
        self.assertIn("no global flexible-algorithm 128", self.d.cfg())

    def test_configure_isis_interface_flex_algo_admin_groups(self):
        configure_isis_interface_flex_algo_admin_groups(self.d, "swp1", [1, 2, 3])
        self.assertIn("flexible-algorithm admin-groups [ 1 2 3 ]", self.d.cfg())

    def test_unconfigure_isis_interface_flex_algo_admin_groups(self):
        unconfigure_isis_interface_flex_algo_admin_groups(self.d, "swp1")
        self.assertIn("no flexible-algorithm admin-groups", self.d.cfg())

    def test_configure_isis_interface_flex_algo_metric(self):
        configure_isis_interface_flex_algo_metric(self.d, "swp1", 2, 128,
                                                    te_metric=100, delay_metric=50)
        c = self.d.cfg()
        self.assertIn("level 2 flexible-algorithm 128", c)
        self.assertIn("te-metric 100", c)
        self.assertIn("delay-metric 50", c)

    def test_unconfigure_isis_interface_flex_algo_metric(self):
        unconfigure_isis_interface_flex_algo_metric(self.d, "swp1", 2, 128)
        self.assertIn("no level 2 flexible-algorithm 128", self.d.cfg())

    def test_configure_isis_flexible_algorithm_priority(self):
        configure_isis_flexible_algorithm_priority(self.d, 128, 200)
        c = self.d.cfg()
        self.assertIn("global flexible-algorithm 128", c)
        self.assertIn("priority 200", c)

    def test_unconfigure_isis_flexible_algorithm_priority(self):
        unconfigure_isis_flexible_algorithm_priority(self.d, 128)
        c = self.d.cfg()
        self.assertIn("global flexible-algorithm 128", c)
        self.assertIn("no priority", c)

    def test_configure_isis_flexible_algorithm_admin_groups(self):
        configure_isis_flexible_algorithm_admin_groups(self.d, 128, "include-any", [1, 2])
        c = self.d.cfg()
        self.assertIn("global flexible-algorithm 128", c)
        self.assertIn("admin-groups include-any [ 1 2 ]", c)

    def test_unconfigure_isis_flexible_algorithm_admin_groups(self):
        unconfigure_isis_flexible_algorithm_admin_groups(self.d, 128, "include-any")
        c = self.d.cfg()
        self.assertIn("no admin-groups include-any", c)

    def test_configure_isis_interface_flex_algo_delay_metric_dynamic(self):
        configure_isis_interface_flex_algo_delay_metric_dynamic(self.d, "swp1", 2)
        self.assertIn("level 2 flexible-algorithm delay-metric DYNAMIC", self.d.cfg())

    def test_unconfigure_isis_interface_flex_algo_delay_metric_dynamic(self):
        unconfigure_isis_interface_flex_algo_delay_metric_dynamic(self.d, "swp1", 2)
        self.assertIn("no level 2 flexible-algorithm delay-metric", self.d.cfg())


class TestIsisTrafficEngineering(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_traffic_engineering_router_id(self):
        configure_isis_traffic_engineering_router_id(self.d, "10.0.0.1", af="ipv4")
        self.assertIn("global traffic-engineering ipv4-router-id 10.0.0.1", self.d.cfg())

    def test_unconfigure_isis_traffic_engineering_router_id(self):
        unconfigure_isis_traffic_engineering_router_id(self.d, af="ipv4")
        self.assertIn("no global traffic-engineering ipv4-router-id", self.d.cfg())

    def test_configure_isis_level_traffic_engineering(self):
        configure_isis_level_traffic_engineering(self.d, "1", enabled=True)
        self.assertIn("level 1 traffic-engineering enabled true", self.d.cfg())

    def test_unconfigure_isis_level_traffic_engineering(self):
        unconfigure_isis_level_traffic_engineering(self.d, "1")
        self.assertIn("no level 1 traffic-engineering enabled", self.d.cfg())


class TestIsisDynamicDelayMeasurement(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_dynamic_delay_measurement(self):
        configure_isis_dynamic_delay_measurement(self.d, probe_interval=10,
                                                  advertisement_interval=30)
        c = self.d.cfg()
        self.assertIn("global dynamic-delay-measurement probe-interval 10", c)
        self.assertIn("global dynamic-delay-measurement advertisement-interval 30", c)

    def test_configure_isis_dynamic_delay_measurement_no_params(self):
        # No params provided: function logs a warning and returns without configuring.
        configure_isis_dynamic_delay_measurement(self.d)
        self.d.configure.assert_not_called()

    def test_unconfigure_isis_dynamic_delay_measurement(self):
        unconfigure_isis_dynamic_delay_measurement(self.d)
        c = self.d.cfg()
        self.assertIn("no global dynamic-delay-measurement probe-interval", c)
        self.assertIn("no global dynamic-delay-measurement advertisement-interval", c)


class TestIsisSrms(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_srms_mapping(self):
        configure_isis_srms_mapping(self.d, "mymap1")
        self.assertIn("global segment-routing srms mapping mymap1", self.d.cfg())

    def test_unconfigure_isis_srms_mapping(self):
        unconfigure_isis_srms_mapping(self.d)
        self.assertIn("no global segment-routing srms mapping", self.d.cfg())

    def test_configure_isis_srms_receive(self):
        configure_isis_srms_receive(self.d, enabled=True)
        self.assertIn("global segment-routing srms receive-enabled true", self.d.cfg())

    def test_unconfigure_isis_srms_receive(self):
        unconfigure_isis_srms_receive(self.d)
        self.assertIn("no global segment-routing srms receive-enabled", self.d.cfg())

    def test_configure_isis_srms_advertise(self):
        configure_isis_srms_advertise(self.d, enabled=True)
        self.assertIn("global segment-routing srms advertise-enabled true", self.d.cfg())

    def test_unconfigure_isis_srms_advertise(self):
        unconfigure_isis_srms_advertise(self.d)
        self.assertIn("no global segment-routing srms advertise-enabled", self.d.cfg())


class TestIsisAutoCost(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_auto_cost_reference_bandwidth(self):
        configure_isis_auto_cost_reference_bandwidth(self.d, 100000)
        self.assertIn("global auto-cost reference-bandwidth 100000", self.d.cfg())

    def test_unconfigure_isis_auto_cost_reference_bandwidth(self):
        unconfigure_isis_auto_cost_reference_bandwidth(self.d)
        self.assertIn("no global auto-cost reference-bandwidth", self.d.cfg())


class TestIsisMplsLdpSync(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_mpls_ldp_sync(self):
        configure_isis_mpls_ldp_sync(self.d, enabled=True)
        self.assertIn("global mpls igp-ldp-sync enabled true", self.d.cfg())

    def test_unconfigure_isis_mpls_ldp_sync(self):
        unconfigure_isis_mpls_ldp_sync(self.d)
        self.assertIn("no global mpls igp-ldp-sync enabled", self.d.cfg())


class TestIsisGlobalHelloAuth(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_global_hello_auth_simple_key(self):
        configure_isis_global_hello_auth(self.d, "SIMPLE_KEY", keychain=None)
        c = self.d.cfg()
        self.assertIn("global hello-authentication auth-type SIMPLE_KEY", c)
        self.assertIn("global hello-authentication key crypto-algorithm MD5", c)

    def test_configure_isis_global_hello_auth_keychain(self):
        configure_isis_global_hello_auth(self.d, "KEYCHAIN", keychain="kc1")
        c = self.d.cfg()
        self.assertIn("global hello-authentication keychain kc1", c)
        self.assertIn("global hello-authentication auth-type KEYCHAIN", c)

    def test_unconfigure_isis_global_hello_auth(self):
        unconfigure_isis_global_hello_auth(self.d)
        c = self.d.cfg()
        self.assertIn("no global hello-authentication auth-type", c)
        self.assertIn("no global hello-authentication keychain", c)


class TestIsisMicroLoopAvoidance(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_micro_loop_avoidance_sr_mpls(self):
        configure_isis_micro_loop_avoidance_sr_mpls(self.d, af="ipv4", enabled=True)
        self.assertIn(
            "global af IPV4 UNICAST micro-loop-avoidance sr-mpls-enabled true", self.d.cfg())

    def test_unconfigure_isis_micro_loop_avoidance_sr_mpls(self):
        unconfigure_isis_micro_loop_avoidance_sr_mpls(self.d, af="ipv4")
        self.assertIn(
            "global af IPV4 UNICAST no micro-loop-avoidance sr-mpls-enabled", self.d.cfg())

    def test_configure_isis_micro_loop_avoidance_srv6(self):
        configure_isis_micro_loop_avoidance_srv6(self.d, enabled=True)
        self.assertIn("global micro-loop-avoidance srv6-enabled true", self.d.cfg())

    def test_unconfigure_isis_micro_loop_avoidance_srv6(self):
        unconfigure_isis_micro_loop_avoidance_srv6(self.d)
        self.assertIn("no global micro-loop-avoidance srv6-enabled", self.d.cfg())

    def test_configure_isis_micro_loop_avoidance_rib_update_delay(self):
        configure_isis_micro_loop_avoidance_rib_update_delay(self.d, 500)
        self.assertIn("global micro-loop-avoidance rib-update-delay 500", self.d.cfg())

    def test_unconfigure_isis_micro_loop_avoidance_rib_update_delay(self):
        unconfigure_isis_micro_loop_avoidance_rib_update_delay(self.d)
        self.assertIn("no global micro-loop-avoidance rib-update-delay", self.d.cfg())


class TestIsisLspFirstWaitInterval(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_lsp_first_wait_interval(self):
        configure_isis_lsp_first_wait_interval(self.d, 50)
        self.assertIn(
            "global timers lsp-generation lsp-first-wait-interval 50", self.d.cfg())

    def test_unconfigure_isis_lsp_first_wait_interval(self):
        unconfigure_isis_lsp_first_wait_interval(self.d)
        self.assertIn(
            "no global timers lsp-generation lsp-first-wait-interval", self.d.cfg())


class TestIsisInterfaceCsnpAndLspPacing(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_csnp_interval(self):
        configure_isis_interface_csnp_interval(self.d, "swp1", 10)
        self.assertIn("timers csnp-interval 10", self.d.cfg())

    def test_unconfigure_isis_interface_csnp_interval(self):
        unconfigure_isis_interface_csnp_interval(self.d, "swp1")
        self.assertIn("no timers csnp-interval", self.d.cfg())

    def test_configure_isis_interface_lsp_pacing_interval(self):
        configure_isis_interface_lsp_pacing_interval(self.d, "swp1", 33)
        self.assertIn("timers lsp-pacing-interval 33", self.d.cfg())

    def test_unconfigure_isis_interface_lsp_pacing_interval(self):
        unconfigure_isis_interface_lsp_pacing_interval(self.d, "swp1")
        self.assertIn("no timers lsp-pacing-interval", self.d.cfg())


class TestIsisInterfaceLevelHelloTimers(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_level_hello_interval(self):
        configure_isis_interface_level_hello_interval(self.d, "swp1", "level_2", 5)
        self.assertIn("level 2 timers hello-interval 5", self.d.cfg())

    def test_unconfigure_isis_interface_level_hello_interval(self):
        unconfigure_isis_interface_level_hello_interval(self.d, "swp1", "level_2")
        self.assertIn("no level 2 timers hello-interval", self.d.cfg())

    def test_configure_isis_interface_level_hello_multiplier(self):
        configure_isis_interface_level_hello_multiplier(self.d, "swp1", "level_1", 4)
        self.assertIn("level 1 timers hello-multiplier 4", self.d.cfg())

    def test_unconfigure_isis_interface_level_hello_multiplier(self):
        unconfigure_isis_interface_level_hello_multiplier(self.d, "swp1", "level_1")
        self.assertIn("no level 1 timers hello-multiplier", self.d.cfg())


class TestIsisDefaultInformationOriginate(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_default_information_originate(self):
        configure_isis_default_information_originate(
            self.d, "IPV4", enabled=True, always=True, export_policy="POL1")
        c = self.d.cfg()
        self.assertIn(
            "global af IPV4 UNICAST default-information originate enabled true", c)
        self.assertIn(
            "global af IPV4 UNICAST default-information originate always true", c)
        self.assertIn(
            "global af IPV4 UNICAST default-information originate export-policy POL1", c)

    def test_configure_isis_default_information_originate_invalid_afi(self):
        with self.assertRaises(ValueError):
            configure_isis_default_information_originate(self.d, "IPV5", enabled=True)

    def test_configure_isis_default_information_originate_no_params(self):
        with self.assertRaises(ValueError):
            configure_isis_default_information_originate(self.d, "IPV4")

    def test_unconfigure_isis_default_information_originate(self):
        unconfigure_isis_default_information_originate(self.d, "IPV6")
        c = self.d.cfg()
        self.assertIn(
            "global af IPV6 UNICAST no default-information originate enabled", c)
        self.assertIn(
            "global af IPV6 UNICAST no default-information originate always", c)

    def test_unconfigure_isis_default_information_originate_invalid_afi(self):
        with self.assertRaises(ValueError):
            unconfigure_isis_default_information_originate(self.d, "IPV5")


class TestIsisLabeledPreference(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_level_labeled_preference(self):
        configure_isis_level_labeled_preference(self.d, "level_2", 50)
        c = self.d.cfg()
        self.assertIn("level 2", c)
        self.assertIn("labeled-preference 50", c)

    def test_configure_isis_level_labeled_preference_out_of_range(self):
        with self.assertRaises(ValueError):
            configure_isis_level_labeled_preference(self.d, "level_2", 300)

    def test_unconfigure_isis_level_labeled_preference(self):
        unconfigure_isis_level_labeled_preference(self.d, "level_2")
        c = self.d.cfg()
        self.assertIn("level 2", c)
        self.assertIn("no labeled-preference", c)


class TestIsisAttachedBit(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_attached_bit_ignore(self):
        configure_isis_attached_bit_ignore(self.d, enabled=True)
        self.assertIn("global lsp-bit attached-bit ignore-bit true", self.d.cfg())

    def test_configure_isis_attached_bit_ignore_bad_type(self):
        with self.assertRaises(TypeError):
            configure_isis_attached_bit_ignore(self.d, enabled="yes")

    def test_unconfigure_isis_attached_bit_ignore(self):
        unconfigure_isis_attached_bit_ignore(self.d)
        self.assertIn("no global lsp-bit attached-bit ignore-bit", self.d.cfg())

    def test_configure_isis_attached_bit_suppress(self):
        configure_isis_attached_bit_suppress(self.d, enabled=True)
        self.assertIn("global lsp-bit attached-bit suppress-bit true", self.d.cfg())

    def test_unconfigure_isis_attached_bit_suppress(self):
        unconfigure_isis_attached_bit_suppress(self.d)
        self.assertIn("no global lsp-bit attached-bit suppress-bit", self.d.cfg())


class TestIsisInterfaceLevelPriority(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_level_priority(self):
        configure_isis_interface_level_priority(self.d, "swp1", "level_1", 64)
        c = self.d.cfg()
        self.assertIn("level 1", c)
        self.assertIn("priority 64", c)

    def test_configure_isis_interface_level_priority_out_of_range(self):
        with self.assertRaises(ValueError):
            configure_isis_interface_level_priority(self.d, "swp1", "level_1", 200)

    def test_unconfigure_isis_interface_level_priority(self):
        unconfigure_isis_interface_level_priority(self.d, "swp1", "level_1")
        c = self.d.cfg()
        self.assertIn("level 1", c)
        self.assertIn("no priority", c)


class TestIsisLevelAuthentication(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_level_auth_keychain(self):
        configure_isis_level_auth_keychain(self.d, "level_1", "kc1")
        c = self.d.cfg()
        self.assertIn("level 1", c)
        self.assertIn("authentication auth-type KEYCHAIN", c)
        self.assertIn("authentication keychain kc1", c)

    def test_unconfigure_isis_level_auth_keychain(self):
        unconfigure_isis_level_auth_keychain(self.d, "level_1")
        c = self.d.cfg()
        self.assertIn("no authentication keychain", c)
        self.assertIn("no authentication auth-type", c)

    def test_configure_isis_level_auth_simple_key(self):
        configure_isis_level_auth_simple_key(self.d, "level_2", "pw1")
        c = self.d.cfg()
        self.assertIn("level 2", c)
        self.assertIn("authentication auth-type SIMPLE_KEY", c)
        self.assertIn("authentication key auth-password pw1", c)

    def test_configure_isis_level_auth_simple_key_bad_algo(self):
        with self.assertRaises(ValueError):
            configure_isis_level_auth_simple_key(self.d, "level_2", "pw1",
                                                  crypto_algorithm="SHA1")

    def test_unconfigure_isis_level_auth_simple_key(self):
        unconfigure_isis_level_auth_simple_key(self.d, "level_2")
        c = self.d.cfg()
        self.assertIn("no authentication key", c)
        self.assertIn("no authentication auth-type", c)

    def test_configure_isis_level_auth_password(self):
        configure_isis_level_auth_password(self.d, "level_1", "newpw")
        c = self.d.cfg()
        self.assertIn("level 1", c)
        self.assertIn("authentication key auth-password newpw", c)

    def test_unconfigure_isis_level_auth_password(self):
        unconfigure_isis_level_auth_password(self.d, "level_1")
        self.assertIn("no authentication key auth-password", self.d.cfg())


class TestIsisInterfaceLevelHelloAuthentication(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_interface_level_hello_authentication(self):
        configure_isis_interface_level_hello_authentication(self.d, "swp1", "level_2",
                                                              enabled=True)
        c = self.d.cfg()
        self.assertIn("level 2", c)
        self.assertIn("hello-authentication hello-authentication true", c)

    def test_configure_isis_interface_level_hello_authentication_bad_type(self):
        with self.assertRaises(TypeError):
            configure_isis_interface_level_hello_authentication(
                self.d, "swp1", "level_2", enabled="yes")

    def test_unconfigure_isis_interface_level_hello_authentication(self):
        unconfigure_isis_interface_level_hello_authentication(self.d, "swp1", "level_2")
        self.assertIn("no hello-authentication hello-authentication", self.d.cfg())

    def test_configure_isis_interface_level_hello_auth_keychain(self):
        configure_isis_interface_level_hello_auth_keychain(self.d, "swp1", "level_1", "kc2")
        c = self.d.cfg()
        self.assertIn("hello-authentication auth-type KEYCHAIN", c)
        self.assertIn("hello-authentication keychain kc2", c)

    def test_unconfigure_isis_interface_level_hello_auth_keychain(self):
        unconfigure_isis_interface_level_hello_auth_keychain(self.d, "swp1", "level_1")
        c = self.d.cfg()
        self.assertIn("no hello-authentication keychain", c)
        self.assertIn("no hello-authentication auth-type", c)

    def test_configure_isis_interface_level_hello_auth_simple_key(self):
        configure_isis_interface_level_hello_auth_simple_key(
            self.d, "swp1", "level_2", "pw3")
        c = self.d.cfg()
        self.assertIn("hello-authentication auth-type SIMPLE_KEY", c)
        self.assertIn("hello-authentication key auth-password pw3", c)

    def test_configure_isis_interface_level_hello_auth_simple_key_bad_algo(self):
        with self.assertRaises(ValueError):
            configure_isis_interface_level_hello_auth_simple_key(
                self.d, "swp1", "level_2", "pw3", crypto_algorithm="SHA1")

    def test_unconfigure_isis_interface_level_hello_auth_simple_key(self):
        unconfigure_isis_interface_level_hello_auth_simple_key(self.d, "swp1", "level_2")
        c = self.d.cfg()
        self.assertIn("no hello-authentication key", c)
        self.assertIn("no hello-authentication auth-type", c)

    def test_configure_isis_interface_level_hello_auth_password(self):
        configure_isis_interface_level_hello_auth_password(
            self.d, "swp1", "level_1", "pw4")
        self.assertIn("hello-authentication key auth-password pw4", self.d.cfg())

    def test_unconfigure_isis_interface_level_hello_auth_password(self):
        unconfigure_isis_interface_level_hello_auth_password(self.d, "swp1", "level_1")
        self.assertIn("no hello-authentication key auth-password", self.d.cfg())


class TestIsisAddressFamily(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_address_family(self):
        configure_isis_address_family(self.d, "ipv4", enabled=True)
        c = self.d.cfg()
        self.assertIn("global af IPV4 UNICAST", c)
        self.assertIn("enabled true", c)

    def test_configure_isis_address_family_invalid_af(self):
        with self.assertRaises(ValueError):
            configure_isis_address_family(self.d, "ipv5")

    def test_unconfigure_isis_address_family(self):
        unconfigure_isis_address_family(self.d, "ipv6")
        self.assertIn("no global af IPV6 UNICAST", self.d.cfg())


class TestIsisSrv6(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_isis_srv6(self):
        configure_isis_srv6(self.d, enabled=True)
        self.assertIn("global srv6 enabled true", self.d.cfg())

    def test_unconfigure_isis_srv6(self):
        unconfigure_isis_srv6(self.d)
        self.assertIn("no global srv6 enabled", self.d.cfg())

    def test_configure_isis_srv6_locator(self):
        configure_isis_srv6_locator(self.d, "loc1")
        self.assertIn("global srv6 locator loc1", self.d.cfg())

    def test_unconfigure_isis_srv6_locator(self):
        unconfigure_isis_srv6_locator(self.d, "loc1")
        self.assertIn("no global srv6 locator loc1", self.d.cfg())


if __name__ == "__main__":
    unittest.main()
