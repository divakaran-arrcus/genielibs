#!/usr/bin/env python3
"""Unit tests for the native ArcOS OSPFv3 Genie conf plugin (full coverage).

``genie.libs.conf.ospfv3.arcos.ospfv3.Ospfv3`` is a standalone ABC-based
native plugin (same shape as ``lag/arcos/lag.py``): ``DeviceAttributes``,
nested ``AreaAttributes``, and doubly-nested ``InterfaceAttributes`` are
each instantiated directly (no Genie/Testbed/abstraction machinery
required -- ``AttributesHelper(self, None)`` reads straight off the
instance). ``build_config(apply=False)`` returns a ``CliConfig`` whose
``.cli_config`` renders the CLI; ``build_unconfig()`` delegates to
``build_config(unconfig=True)``.

Hierarchy under test::

    network-instance <ni>
     protocol OSPF3 <pid>
      global ...
      area <area_id>
       ...
       interface <name>
        ...
"""

from unittest import TestCase
from unittest.mock import Mock

from genie.libs.conf.ospfv3.arcos.ospfv3 import Ospfv3


def _make_device():
    device = Mock()
    device.name = "rtr1"
    device.custom = {"instance_name": "default"}
    device.configure = Mock(return_value=True)
    return device


class TestOspfv3DeviceAttributesGlobal(TestCase):
    """DeviceAttributes.build_config() -- Phase 1 core global attributes."""

    def setUp(self):
        self.device = _make_device()

    def _make_da(self, **attrs):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        for key, value in attrs.items():
            setattr(da, key, value)
        return da

    def test_router_id_and_max_ecmp_paths(self):
        da = self._make_da(router_id="1.1.1.1", max_ecmp_paths=8)
        result = da.build_config(apply=False)
        output = str(result.cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("protocol OSPF3 default", output)
        self.assertIn("global router-id 1.1.1.1", output)
        self.assertIn("global max-ecmp-paths 8", output)

    def test_auto_cost(self):
        da = self._make_da(
            auto_cost_enabled=True, auto_cost_reference_bandwidth=3200
        )
        output = str(da.build_config(apply=False).cli_config)

        self.assertIn("global auto-cost enabled true", output)
        self.assertIn("global auto-cost reference-bandwidth 3200", output)

    def test_auto_cost_disabled(self):
        da = self._make_da(auto_cost_enabled=False)
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("global auto-cost enabled false", output)

    def test_log_adjacency_changes(self):
        da = self._make_da(log_adjacency_changes="LOG_ADJ_ENABLE_DETAILED")
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global log-adjacency-changes LOG_ADJ_ENABLE_DETAILED", output
        )

    def test_no_attributes_still_emits_context(self):
        """Even with zero attributes set, network-instance/protocol context
        is still opened (no attribute-gated lines emitted inside)."""
        da = self._make_da()
        output = str(da.build_config(apply=False).cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("protocol OSPF3 default", output)
        self.assertNotIn("router-id", output)

    def test_custom_pid(self):
        da = self._make_da(router_id="2.2.2.2")
        da.pid = "inst1"
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("protocol OSPF3 inst1", output)

    def test_non_default_instance_name(self):
        device = _make_device()
        device.custom = {"instance_name": "vrf1"}
        da = Ospfv3.DeviceAttributes()
        da.device = device
        da.router_id = "3.3.3.3"
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("network-instance vrf1", output)


class TestOspfv3DeviceAttributesRoutePreference(TestCase):
    """Phase 2 -- global route preference."""

    def setUp(self):
        self.device = _make_device()

    def test_route_preference_all(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.route_preference_intra_area = 90
        da.route_preference_inter_area = 100
        da.route_preference_external = 150

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("global route-preference intra-area 90", output)
        self.assertIn("global route-preference inter-area 100", output)
        self.assertIn("global route-preference external 150", output)


class TestOspfv3DeviceAttributesSpfThrottleAndLogging(TestCase):
    """Phase 3 -- SPF throttle timers + SPF logging."""

    def setUp(self):
        self.device = _make_device()

    def _make_da(self, **attrs):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        for key, value in attrs.items():
            setattr(da, key, value)
        return da

    def test_spf_throttle_timers(self):
        da = self._make_da(
            spf_initial_delay=50, spf_short_delay=200, spf_long_delay=5000,
            spf_time_to_learn=500, spf_holddown=10000,
        )
        output = str(da.build_config(apply=False).cli_config)

        self.assertIn(
            "global spf throttle timers spf-initial-delay 50", output)
        self.assertIn(
            "global spf throttle timers spf-short-delay 200", output)
        self.assertIn(
            "global spf throttle timers spf-long-delay 5000", output)
        self.assertIn(
            "global spf throttle timers time-to-learn-interval 500", output)
        self.assertIn(
            "global spf throttle timers holddown-interval 10000", output)

    def test_spf_logging(self):
        da = self._make_da(spf_log_max_logs=16, spf_log_max_triggers=8)
        output = str(da.build_config(apply=False).cli_config)

        self.assertIn("global spf logging maximum-logs 16", output)
        self.assertIn("global spf logging maximum-triggers-per-log 8", output)


class TestOspfv3DeviceAttributesLsaTimers(TestCase):
    """Phase 3 -- LSA timers (min-arrival + origination-delay)."""

    def setUp(self):
        self.device = _make_device()

    def _make_da(self, **attrs):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        for key, value in attrs.items():
            setattr(da, key, value)
        return da

    def test_lsa_min_arrival(self):
        da = self._make_da(lsa_min_arrival=1000)
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("global timers lsa min-arrival 1000", output)

    def test_lsa_origination_delay_all(self):
        da = self._make_da(
            lsa_origination_start=50, lsa_origination_hold=200,
            lsa_origination_max=5000,
        )
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global timers lsa origination-delay 50 200 5000", output)

    def test_lsa_origination_delay_start_only(self):
        da = self._make_da(lsa_origination_start=50)
        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("global timers lsa origination-delay 50", output)

    def test_lsa_origination_delay_not_emitted_without_start(self):
        """hold/max are appended only when start is set."""
        da = self._make_da(lsa_origination_hold=200, lsa_origination_max=5000)
        output = str(da.build_config(apply=False).cli_config)
        self.assertNotIn("origination-delay", output)


class TestOspfv3DeviceAttributesMaxLsa(TestCase):
    """Phase 3 -- max-LSA."""

    def setUp(self):
        self.device = _make_device()

    def test_max_lsa_all_params(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.max_lsa_limit = 50000
        da.max_lsa_warning_threshold = 80
        da.max_lsa_warning_only = True
        da.max_lsa_avoid_down_state = False
        da.max_lsa_limit_monitor_time = 60
        da.max_lsa_down_recovery_time = 300

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn("global max-lsa lsa-limit 50000", output)
        self.assertIn("global max-lsa warning-threshold 80", output)
        self.assertIn("global max-lsa warning-only true", output)
        self.assertIn("global max-lsa avoid-down-state false", output)
        self.assertIn("global max-lsa limit-monitor-time 60", output)
        self.assertIn("global max-lsa down-recovery-time 300", output)


class TestOspfv3DeviceAttributesMaintenanceMode(TestCase):
    """Phase 3 -- maintenance mode + trigger."""

    def setUp(self):
        self.device = _make_device()

    def test_maintenance_mode_trigger(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.maintenance_mode_always = True
        da.maintenance_mode_on_startup = 300

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global maintenance-mode trigger always true", output)
        self.assertIn(
            "global maintenance-mode trigger on-startup 300", output)

    def test_maintenance_mode_lsa_metrics(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.maintenance_mode_router_lsa_metric = 65535
        da.maintenance_mode_router_lsa_set_link_metric = True
        da.maintenance_mode_router_lsa_set_stub_metric = False
        da.maintenance_mode_summary_lsa_metric = 16711680
        da.maintenance_mode_summary_lsa_set_metric = True
        da.maintenance_mode_external_lsa_metric = 16711680
        da.maintenance_mode_external_lsa_set_metric = False

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global maintenance-mode router-lsa metric 65535", output)
        self.assertIn(
            "global maintenance-mode router-lsa set-link-metric true",
            output)
        self.assertIn(
            "global maintenance-mode router-lsa set-stub-metric false",
            output)
        self.assertIn(
            "global maintenance-mode summary-lsa metric 16711680", output)
        self.assertIn(
            "global maintenance-mode summary-lsa set-metric true", output)
        self.assertIn(
            "global maintenance-mode external-lsa metric 16711680", output)
        self.assertIn(
            "global maintenance-mode external-lsa set-metric false", output)


class TestOspfv3DeviceAttributesRedistributeAggregates(TestCase):
    """Phase 3 -- global redistribute-aggregate (IPv6)."""

    def setUp(self):
        self.device = _make_device()

    def test_redistribute_aggregate_with_sub_attrs(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.redistribute_aggregates = {
            "2001:db8::/32": {
                "advertise": "AGGREGATE_ADVERTISE",
                "import_policy": "p1",
            },
        }

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global redistribute-aggregate 2001:db8::/32", output)
        self.assertIn("advertise AGGREGATE_ADVERTISE", output)
        self.assertIn("import-policy p1", output)

    def test_redistribute_aggregate_bare_prefix(self):
        """A non-dict value means 'just the bare prefix, no sub-knobs'."""
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.redistribute_aggregates = {"2001:db9::/32": True}

        output = str(da.build_config(apply=False).cli_config)
        self.assertIn(
            "global redistribute-aggregate 2001:db9::/32", output)
        self.assertNotIn("advertise", output)

    def test_redistribute_aggregate_sorted_order(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.redistribute_aggregates = {
            "2001:dbb::/32": True,
            "2001:dba::/32": True,
        }

        output = str(da.build_config(apply=False).cli_config)
        self.assertLess(
            output.index("2001:dba::/32"), output.index("2001:dbb::/32")
        )


class TestOspfv3DeviceAttributesUnconfig(TestCase):
    """DeviceAttributes.build_unconfig() -- whole-feature removal."""

    def setUp(self):
        self.device = _make_device()

    def test_build_unconfig_whole_feature(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.router_id = "1.1.1.1"

        result = da.build_unconfig(apply=False)
        output = str(result.cli_config)

        self.assertIn(
            "no network-instance default protocol OSPF3 default", output
        )
        # Per-attribute lines are never emitted on the unconfig path --
        # DeviceAttributes.build_config(unconfig=True) removes the whole
        # protocol instance in one shot.
        self.assertNotIn("router-id", output)

    def test_build_config_unconfig_true_matches_build_unconfig(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device

        via_unconfig = str(da.build_unconfig(apply=False).cli_config)
        via_direct = str(
            da.build_config(apply=False, unconfig=True).cli_config
        )
        self.assertEqual(via_unconfig, via_direct)

    def test_apply_true_calls_device_configure(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.router_id = "1.1.1.1"

        result = da.build_config(apply=True)

        self.assertIsNone(result)
        self.device.configure.assert_called_once()
        args, _ = self.device.configure.call_args
        self.assertIn("global router-id 1.1.1.1", args[0])


class TestOspfv3AreaAttributes(TestCase):
    """AreaAttributes.build_config()/build_unconfig()."""

    def setUp(self):
        self.device = _make_device()

    def _make_area(self, area_id, **attrs):
        area = Ospfv3.DeviceAttributes.AreaAttributes()
        area.device = self.device
        area.area_id = area_id
        for key, value in attrs.items():
            setattr(area, key, value)
        return area

    def test_area_type_and_stub_default_cost(self):
        area = self._make_area(
            "1", area_type="AREA_TYPE_STUB", stub_default_cost=10
        )
        output = str(area.build_config(apply=False).cli_config)

        self.assertIn("area 1", output)
        self.assertIn("area-type AREA_TYPE_STUB", output)
        self.assertIn("stub-default-cost 10", output)

    def test_advertise_summary_lsas(self):
        area = self._make_area("0", advertise_summary_lsas=False)
        output = str(area.build_config(apply=False).cli_config)
        self.assertIn("advertise-summary-lsas false", output)

    def test_summary_aggregate_with_sub_attrs(self):
        area = self._make_area(
            "1",
            summary_aggregates={
                "2001:db8:1::/48": {
                    "advertise": "AGGREGATE_DONT_ADVERTISE",
                    "import_policy": "p2",
                },
            },
        )
        output = str(area.build_config(apply=False).cli_config)

        self.assertIn("area 1", output)
        self.assertIn("summary-aggregate 2001:db8:1::/48", output)
        self.assertIn("advertise AGGREGATE_DONT_ADVERTISE", output)
        self.assertIn("import-policy p2", output)

    def test_summary_aggregate_bare_prefix(self):
        area = self._make_area(
            "1", summary_aggregates={"2001:db8:2::/48": True}
        )
        output = str(area.build_config(apply=False).cli_config)
        self.assertIn("summary-aggregate 2001:db8:2::/48", output)

    def test_no_attributes_still_emits_area_context(self):
        area = self._make_area("0")
        output = str(area.build_config(apply=False).cli_config)
        self.assertIn("area 0", output)
        self.assertNotIn("area-type", output)

    def test_area_unconfig(self):
        area = self._make_area("1", advertise_summary_lsas=False)
        output = str(area.build_unconfig(apply=False).cli_config)
        self.assertIn("area 1", output)
        self.assertIn("no advertise-summary-lsas false", output)

    def test_area_with_nested_interface(self):
        intf = Ospfv3.DeviceAttributes.AreaAttributes.InterfaceAttributes()
        intf.device = self.device
        intf.interface_name = "swp1"
        intf.metric = 100

        area = self._make_area("0")
        area.interface_attr = {"swp1": intf}

        output = str(area.build_config(apply=False).cli_config)
        self.assertIn("area 0", output)
        self.assertIn("interface swp1", output)
        self.assertIn("metric 100", output)


class TestOspfv3InterfaceAttributes(TestCase):
    """InterfaceAttributes.build_config()/build_unconfig()."""

    def setUp(self):
        self.device = _make_device()

    def _make_intf(self, name, **attrs):
        intf = Ospfv3.DeviceAttributes.AreaAttributes.InterfaceAttributes()
        intf.device = self.device
        intf.interface_name = name
        for key, value in attrs.items():
            setattr(intf, key, value)
        return intf

    def test_core_knobs(self):
        intf = self._make_intf(
            "swp1", metric=100, network_type="POINT_TO_POINT_NETWORK",
            passive=True, hello_interval=10, dead_interval=40,
            retransmit_interval=5, transmission_delay=1,
        )
        output = str(intf.build_config(apply=False).cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn("metric 100", output)
        self.assertIn("network-type POINT_TO_POINT_NETWORK", output)
        self.assertIn("passive true", output)
        self.assertIn("timers hello-interval 10", output)
        self.assertIn("timers dead-interval 40", output)
        self.assertIn("timers retransmission-interval 5", output)
        self.assertIn("timers transmission-delay 1", output)

    def test_hardening_knobs(self):
        intf = self._make_intf(
            "swp2", priority=5, ignore_mtu=True,
        )
        output = str(intf.build_config(apply=False).cli_config)

        self.assertIn("interface swp2", output)
        self.assertIn("priority 5", output)
        self.assertIn("ignore-mtu true", output)

    def test_ospfv3_specific_instance_and_interface_id(self):
        intf = self._make_intf(
            "swp3", instance_id=3, interface_id_value=42,
        )
        output = str(intf.build_config(apply=False).cli_config)

        self.assertIn("interface swp3", output)
        self.assertIn("instance-id 3", output)
        self.assertIn("interface-id 42", output)

    def test_bfd_knobs(self):
        intf = self._make_intf(
            "swp4", bfd_enabled=True, bfd_profile="GLOBAL",
        )
        output = str(intf.build_config(apply=False).cli_config)

        self.assertIn("bfd enabled true", output)
        self.assertIn("bfd profile GLOBAL", output)

    def test_no_attributes_still_emits_interface_context(self):
        intf = self._make_intf("swp1")
        output = str(intf.build_config(apply=False).cli_config)
        self.assertIn("interface swp1", output)
        self.assertNotIn("metric", output)

    def test_interface_unconfig(self):
        intf = self._make_intf("swp1", metric=100, priority=5)
        output = str(intf.build_unconfig(apply=False).cli_config)

        self.assertIn("interface swp1", output)
        self.assertIn("no metric 100", output)
        self.assertIn("no priority 5", output)


class TestOspfv3FullStackIntegration(TestCase):
    """Device -> Area -> Interface nesting end to end, both directions."""

    def setUp(self):
        self.device = _make_device()

    def test_full_stack_build_config(self):
        intf = Ospfv3.DeviceAttributes.AreaAttributes.InterfaceAttributes()
        intf.device = self.device
        intf.interface_name = "swp1"
        intf.metric = 100
        intf.instance_id = 0

        area = Ospfv3.DeviceAttributes.AreaAttributes()
        area.device = self.device
        area.area_id = "0"
        area.area_type = "AREA_TYPE_NORMAL"
        area.interface_attr = {"swp1": intf}

        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.router_id = "1.1.1.1"
        da.max_ecmp_paths = 8
        da.area_attr = {"0": area}

        output = str(da.build_config(apply=False).cli_config)

        self.assertIn("network-instance default", output)
        self.assertIn("protocol OSPF3 default", output)
        self.assertIn("global router-id 1.1.1.1", output)
        self.assertIn("global max-ecmp-paths 8", output)
        self.assertIn("area 0", output)
        self.assertIn("area-type AREA_TYPE_NORMAL", output)
        self.assertIn("interface swp1", output)
        self.assertIn("metric 100", output)
        self.assertIn("instance-id 0", output)

    def test_full_stack_multiple_areas_sorted(self):
        area0 = Ospfv3.DeviceAttributes.AreaAttributes()
        area0.device = self.device
        area0.area_id = "0"

        area1 = Ospfv3.DeviceAttributes.AreaAttributes()
        area1.device = self.device
        area1.area_id = "1"
        area1.area_type = "AREA_TYPE_STUB"

        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.area_attr = {"1": area1, "0": area0}

        output = str(da.build_config(apply=False).cli_config)
        self.assertLess(output.index("area 0"), output.index("area 1"))

    def test_full_stack_build_unconfig_removes_whole_instance(self):
        da = Ospfv3.DeviceAttributes()
        da.device = self.device
        da.router_id = "1.1.1.1"
        area = Ospfv3.DeviceAttributes.AreaAttributes()
        area.device = self.device
        area.area_id = "0"
        da.area_attr = {"0": area}

        output = str(da.build_unconfig(apply=False).cli_config)
        self.assertIn(
            "no network-instance default protocol OSPF3 default", output
        )


if __name__ == "__main__":
    import unittest
    unittest.main()
