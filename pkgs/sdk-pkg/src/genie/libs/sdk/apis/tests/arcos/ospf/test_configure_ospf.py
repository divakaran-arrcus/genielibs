#!/usr/bin/env python3
"""Unit tests for arcOS OSPF configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under
`network-instance <ni> protocol OSPF <pi>` (optionally nested under `area
<id>` / `interface <name>`) and calls device.configure(list). Tests mock
device.configure and assert the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.ospf import configure as ospf_configure
from genie.libs.sdk.apis.arcos.ospf.configure import (
    configure_ospf_router_id,
    unconfigure_ospf_router_id,
    configure_ospf_area,
    unconfigure_ospf_area,
    configure_ospf_interface,
    unconfigure_ospf_interface,
    unconfigure_ospf,
    configure_ospf_max_ecmp_paths,
    unconfigure_ospf_max_ecmp_paths,
    configure_ospf_auto_cost,
    unconfigure_ospf_auto_cost,
    configure_ospf_stub_default_cost,
    unconfigure_ospf_stub_default_cost,
    configure_ospf_advertise_summary_lsas,
    unconfigure_ospf_advertise_summary_lsas,
    configure_ospf_spf_throttle,
    unconfigure_ospf_spf_throttle,
    configure_ospf_interface_auth,
    configure_ospf_interface_auth_md5,
    unconfigure_ospf_interface_auth,
    configure_ospf_interface_ignore_mtu,
    unconfigure_ospf_interface_ignore_mtu,
    configure_ospf_table_connection,
    unconfigure_ospf_table_connection,
    configure_ospf_redistribute_aggregate,
    unconfigure_ospf_redistribute_aggregate,
    configure_ospf_summary_aggregate,
    unconfigure_ospf_summary_aggregate,
    configure_ospf_route_preference,
    unconfigure_ospf_route_preference,
    configure_ospf_max_lsa,
    unconfigure_ospf_max_lsa,
    configure_ospf_maintenance_mode,
    unconfigure_ospf_maintenance_mode,
    configure_ospf_maintenance_mode_trigger,
    unconfigure_ospf_maintenance_mode_trigger,
)

_CTX = 'network-instance default protocol OSPF default'


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureOspfGlobal(unittest.TestCase):
    """router-id, area, whole-feature removal."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_router_id(self):
        configure_ospf_router_id(self.d, "1.1.1.1")
        c = self.d.cfg()
        self.assertIn(_CTX, c)
        self.assertIn("global router-id 1.1.1.1", c)

    def test_router_id_removal(self):
        unconfigure_ospf_router_id(self.d)
        self.assertIn("no global router-id", self.d.cfg())

    def test_area(self):
        configure_ospf_area(self.d, "0.0.0.1", area_type="AREA_TYPE_STUB",
                             stub_default_cost=10)
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("area-type AREA_TYPE_STUB", c)
        self.assertIn("stub-default-cost 10", c)

    def test_area_default_type_no_stub_cost(self):
        configure_ospf_area(self.d, "0.0.0.0")
        c = self.d.cfg()
        self.assertIn("area-type AREA_TYPE_NORMAL", c)
        self.assertNotIn("stub-default-cost", c)

    def test_area_removal(self):
        unconfigure_ospf_area(self.d, "0.0.0.1")
        c = self.d.cfg()
        self.assertIn(f"no {_CTX} area 0.0.0.1", c)

    def test_whole_ospf_removal(self):
        unconfigure_ospf(self.d)
        c = self.d.cfg()
        self.assertIn(f"no {_CTX}", c)


class TestConfigureOspfInterface(unittest.TestCase):
    """Per-area interface knobs."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_all_knobs(self):
        configure_ospf_interface(
            self.d, "0.0.0.0", "swp1",
            network_type="POINT_TO_POINT_NETWORK",
            passive=True,
            hello_interval=10,
            dead_interval=40,
            metric=100,
            priority=5,
            retransmission_interval=5,
            transmission_delay=1,
            bfd_enabled=True,
            bfd_profile="p1",
        )
        c = self.d.cfg()
        self.assertIn("area 0.0.0.0", c)
        self.assertIn("interface swp1", c)
        self.assertIn("network-type POINT_TO_POINT_NETWORK", c)
        self.assertIn("passive true", c)
        self.assertIn("metric 100", c)
        self.assertIn("priority 5", c)
        self.assertIn("timers hello-interval 10", c)
        self.assertIn("timers dead-interval 40", c)
        self.assertIn("timers retransmission-interval 5", c)
        self.assertIn("timers transmission-delay 1", c)
        self.assertIn("bfd enabled true", c)
        self.assertIn("bfd profile p1", c)

    def test_interface_non_default_instance_context(self):
        configure_ospf_interface(
            self.d, "0.0.0.0", "swp2",
            passive=False,
            network_instance="vrf1",
            protocol_instance="inst1",
        )
        c = self.d.cfg()
        self.assertIn("network-instance vrf1 protocol OSPF inst1", c)
        self.assertIn("passive false", c)

    def test_interface_removal(self):
        unconfigure_ospf_interface(self.d, "0.0.0.0", "swp1")
        c = self.d.cfg()
        self.assertIn(f"{_CTX} area 0.0.0.0", c)
        self.assertIn("no interface swp1", c)


class TestConfigureOspfMaxEcmpPaths(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_max_ecmp_paths(self):
        configure_ospf_max_ecmp_paths(self.d, 8)
        self.assertIn("global max-ecmp-paths 8", self.d.cfg())

    def test_max_ecmp_paths_removal(self):
        unconfigure_ospf_max_ecmp_paths(self.d)
        self.assertIn("no global max-ecmp-paths", self.d.cfg())


class TestConfigureOspfAutoCost(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_auto_cost(self):
        configure_ospf_auto_cost(self.d, enabled=True, reference_bandwidth=100)
        c = self.d.cfg()
        self.assertIn("global auto-cost enabled true", c)
        self.assertIn("global auto-cost reference-bandwidth 100", c)

    def test_auto_cost_disabled_no_ref_bw(self):
        configure_ospf_auto_cost(self.d, enabled=False)
        c = self.d.cfg()
        self.assertIn("global auto-cost enabled false", c)
        self.assertNotIn("reference-bandwidth", c)

    def test_auto_cost_removal(self):
        unconfigure_ospf_auto_cost(self.d)
        self.assertIn("no global auto-cost", self.d.cfg())


class TestConfigureOspfStubDefaultCost(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_stub_default_cost(self):
        configure_ospf_stub_default_cost(self.d, "0.0.0.1", 20)
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("stub-default-cost 20", c)

    def test_stub_default_cost_removal(self):
        unconfigure_ospf_stub_default_cost(self.d, "0.0.0.1")
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("no stub-default-cost", c)


class TestConfigureOspfAdvertiseSummaryLsas(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_advertise_summary_lsas(self):
        configure_ospf_advertise_summary_lsas(self.d, "0.0.0.1", False)
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("advertise-summary-lsas false", c)

    def test_advertise_summary_lsas_removal(self):
        unconfigure_ospf_advertise_summary_lsas(self.d, "0.0.0.1")
        c = self.d.cfg()
        self.assertIn("no advertise-summary-lsas", c)


class TestConfigureOspfSpfThrottle(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_spf_throttle_all_timers(self):
        configure_ospf_spf_throttle(
            self.d, initial_delay=50, short_delay=200, long_delay=5000,
            time_to_learn=500, holddown=10000,
        )
        c = self.d.cfg()
        self.assertIn("global spf throttle timers spf-initial-delay 50", c)
        self.assertIn("global spf throttle timers spf-short-delay 200", c)
        self.assertIn("global spf throttle timers spf-long-delay 5000", c)
        self.assertIn(
            "global spf throttle timers time-to-learn-interval 500", c)
        self.assertIn(
            "global spf throttle timers holddown-interval 10000", c)

    def test_spf_throttle_no_params_noop(self):
        configure_ospf_spf_throttle(self.d)
        self.d.configure.assert_not_called()

    def test_spf_throttle_removal(self):
        unconfigure_ospf_spf_throttle(self.d)
        c = self.d.cfg()
        self.assertIn("no global spf throttle timers spf-initial-delay", c)
        self.assertIn("no global spf throttle timers spf-short-delay", c)
        self.assertIn("no global spf throttle timers spf-long-delay", c)
        self.assertIn(
            "no global spf throttle timers time-to-learn-interval", c)
        self.assertIn("no global spf throttle timers holddown-interval", c)


class TestConfigureOspfInterfaceAuth(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_auth_null(self):
        configure_ospf_interface_auth(self.d, "0.0.0.0", "swp1",
                                       "OSPF_AUTH_NULL")
        c = self.d.cfg()
        self.assertIn("area 0.0.0.0", c)
        self.assertIn("interface swp1", c)
        self.assertIn("authentication auth-type OSPF_AUTH_NULL", c)

    def test_interface_auth_md5(self):
        configure_ospf_interface_auth_md5(self.d, "0.0.0.0", "swp1",
                                           key_id=1, key_string="secret")
        c = self.d.cfg()
        self.assertIn(
            "authentication auth-type OSPF_AUTH_CRYPTO_KEY", c)
        self.assertIn(
            "authentication crypto-key algorithm OSPF_CRYPTO_ALGO_MD5", c)
        self.assertIn("authentication crypto-key key-id 1", c)
        self.assertIn("authentication crypto-key key-string secret", c)

    def test_interface_auth_removal(self):
        unconfigure_ospf_interface_auth(self.d, "0.0.0.0", "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no authentication", c)


class TestConfigureOspfInterfaceIgnoreMtu(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_ignore_mtu_enabled(self):
        configure_ospf_interface_ignore_mtu(self.d, "0.0.0.0", "swp1", True)
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("ignore-mtu true", c)

    def test_ignore_mtu_removal(self):
        unconfigure_ospf_interface_ignore_mtu(self.d, "0.0.0.0", "swp1")
        c = self.d.cfg()
        self.assertIn("no ignore-mtu", c)


class TestConfigureOspfTableConnection(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_table_connection(self):
        configure_ospf_table_connection(self.d, "STATIC", afi="IPV4",
                                         import_policy="redis_static")
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("table-connection STATIC OSPF IPV4", c)
        self.assertIn("import-policy [ redis_static ]", c)

    def test_table_connection_removal(self):
        unconfigure_ospf_table_connection(self.d, "STATIC", afi="IPV4")
        c = self.d.cfg()
        self.assertIn("no table-connection STATIC OSPF IPV4", c)


class TestConfigureOspfRedistributeAggregate(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_redistribute_aggregate(self):
        configure_ospf_redistribute_aggregate(
            self.d, "10.0.0.0/8", advertise="AGGREGATE_ADVERTISE",
            import_policy="p1",
        )
        c = self.d.cfg()
        self.assertIn("global redistribute-aggregate 10.0.0.0/8", c)
        self.assertIn("advertise AGGREGATE_ADVERTISE", c)
        self.assertIn("import-policy p1", c)

    def test_redistribute_aggregate_removal(self):
        unconfigure_ospf_redistribute_aggregate(self.d, "10.0.0.0/8")
        c = self.d.cfg()
        self.assertIn("global no redistribute-aggregate 10.0.0.0/8", c)


class TestConfigureOspfSummaryAggregate(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_summary_aggregate(self):
        configure_ospf_summary_aggregate(
            self.d, "0.0.0.1", "10.1.0.0/16",
            advertise="AGGREGATE_DONT_ADVERTISE", import_policy="p2",
        )
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("summary-aggregate 10.1.0.0/16", c)
        self.assertIn("advertise AGGREGATE_DONT_ADVERTISE", c)
        self.assertIn("import-policy p2", c)

    def test_summary_aggregate_removal(self):
        unconfigure_ospf_summary_aggregate(self.d, "0.0.0.1", "10.1.0.0/16")
        c = self.d.cfg()
        self.assertIn("area 0.0.0.1", c)
        self.assertIn("no summary-aggregate 10.1.0.0/16", c)


class TestConfigureOspfRoutePreference(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_route_preference(self):
        configure_ospf_route_preference(
            self.d, intra_area=90, inter_area=100, external=150)
        c = self.d.cfg()
        self.assertIn(
            "global route-preference intra-area 90 inter-area 100 "
            "external 150", c)

    def test_route_preference_no_args_noop(self):
        configure_ospf_route_preference(self.d)
        self.d.configure.assert_not_called()

    def test_route_preference_removal_specific(self):
        unconfigure_ospf_route_preference(self.d, intra_area=True)
        c = self.d.cfg()
        self.assertIn("global no route-preference intra-area", c)
        self.assertNotIn("inter-area", c)

    def test_route_preference_removal_default_all(self):
        unconfigure_ospf_route_preference(self.d)
        c = self.d.cfg()
        self.assertIn("global no route-preference intra-area", c)
        self.assertIn("global no route-preference inter-area", c)
        self.assertIn("global no route-preference external", c)


class TestConfigureOspfMaxLsa(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_max_lsa_all_params(self):
        configure_ospf_max_lsa(
            self.d, lsa_limit=50000, warning_threshold=80,
            warning_only=True, avoid_down_state=False,
            limit_monitor_time=60, down_recovery_time=300,
        )
        c = self.d.cfg()
        self.assertIn("global max-lsa lsa-limit 50000", c)
        self.assertIn("global max-lsa warning-threshold 80", c)
        self.assertIn("global max-lsa warning-only true", c)
        self.assertIn("global max-lsa avoid-down-state false", c)
        self.assertIn("global max-lsa limit-monitor-time 60", c)
        self.assertIn("global max-lsa down-recovery-time 300", c)

    def test_max_lsa_no_params_noop(self):
        configure_ospf_max_lsa(self.d)
        self.d.configure.assert_not_called()

    def test_max_lsa_removal(self):
        unconfigure_ospf_max_lsa(self.d)
        self.assertIn("no global max-lsa", self.d.cfg())


class TestConfigureOspfMaintenanceMode(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_maintenance_mode_all_params(self):
        configure_ospf_maintenance_mode(
            self.d, router_lsa_metric=16000,
            router_lsa_set_link_metric=True,
            router_lsa_set_stub_metric=False,
            summary_lsa_metric=16000, summary_lsa_set_metric=True,
            external_lsa_metric=16000, external_lsa_set_metric=False,
        )
        c = self.d.cfg()
        self.assertIn("global maintenance-mode router-lsa metric 16000", c)
        self.assertIn(
            "global maintenance-mode router-lsa set-link-metric true", c)
        self.assertIn(
            "global maintenance-mode router-lsa set-stub-metric false", c)
        self.assertIn("global maintenance-mode summary-lsa metric 16000", c)
        self.assertIn(
            "global maintenance-mode summary-lsa set-metric true", c)
        self.assertIn("global maintenance-mode external-lsa metric 16000", c)
        self.assertIn(
            "global maintenance-mode external-lsa set-metric false", c)

    def test_maintenance_mode_no_params_noop(self):
        configure_ospf_maintenance_mode(self.d)
        self.d.configure.assert_not_called()

    def test_maintenance_mode_removal(self):
        unconfigure_ospf_maintenance_mode(self.d)
        self.assertIn("no global maintenance-mode", self.d.cfg())

    def test_maintenance_mode_trigger(self):
        configure_ospf_maintenance_mode_trigger(
            self.d, always=True, on_startup=60)
        c = self.d.cfg()
        self.assertIn("global maintenance-mode trigger always true", c)
        self.assertIn("global maintenance-mode trigger on-startup 60", c)

    def test_maintenance_mode_trigger_no_params_noop(self):
        configure_ospf_maintenance_mode_trigger(self.d)
        self.d.configure.assert_not_called()

    def test_maintenance_mode_trigger_removal(self):
        unconfigure_ospf_maintenance_mode_trigger(self.d)
        self.assertIn("no global maintenance-mode trigger", self.d.cfg())


class TestOspfConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in ospf/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ospf_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ospf_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered OSPF configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nOSPF configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
