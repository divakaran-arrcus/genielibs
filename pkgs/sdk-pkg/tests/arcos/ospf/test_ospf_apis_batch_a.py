"""Unit tests for ArcOS OSPF APIs — Batch A (sanity-plan blockers)."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.ospf.configure import (
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
)
from genie.libs.sdk.apis.arcos.ospf.get import (
    get_ospf_route,
    get_ospf_lsdb_lsa_count,
)
from genie.libs.sdk.apis.arcos.ospf.verify import verify_ospf_route_present


CTX = "network-instance default protocol OSPF default"


class TestConfigureMaxEcmpPaths(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_configure(self):
        configure_ospf_max_ecmp_paths(self.device, paths=8)
        self.device.configure.assert_called_once_with(
            [CTX, "global max-ecmp-paths 8", "!"]
        )

    def test_unconfigure(self):
        unconfigure_ospf_max_ecmp_paths(self.device)
        self.device.configure.assert_called_once_with(
            [CTX, "no global max-ecmp-paths", "!"]
        )


class TestConfigureAutoCost(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_enabled_only(self):
        configure_ospf_auto_cost(self.device, enabled=True)
        self.device.configure.assert_called_once_with(
            [CTX, "global auto-cost enabled true", "!"]
        )

    def test_enabled_with_reference_bandwidth(self):
        configure_ospf_auto_cost(self.device, enabled=True, reference_bandwidth=100)
        self.device.configure.assert_called_once_with([
            CTX,
            "global auto-cost enabled true",
            "global auto-cost reference-bandwidth 100",
            "!",
        ])

    def test_disabled(self):
        configure_ospf_auto_cost(self.device, enabled=False)
        self.device.configure.assert_called_once_with(
            [CTX, "global auto-cost enabled false", "!"]
        )

    def test_unconfigure(self):
        unconfigure_ospf_auto_cost(self.device)
        self.device.configure.assert_called_once_with(
            [CTX, "no global auto-cost", "!"]
        )


class TestConfigureStubDefaultCost(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr5"

    def test_configure(self):
        configure_ospf_stub_default_cost(self.device, area_id="2", cost=50)
        self.device.configure.assert_called_once_with([
            CTX, "area 2", "stub-default-cost 50", "!",
        ])

    def test_unconfigure(self):
        unconfigure_ospf_stub_default_cost(self.device, area_id="2")
        self.device.configure.assert_called_once_with([
            CTX, "area 2", "no stub-default-cost", "!",
        ])


class TestConfigureAdvertiseSummaryLsas(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr5"

    def test_enable(self):
        configure_ospf_advertise_summary_lsas(self.device, area_id="2", enabled=True)
        self.device.configure.assert_called_once_with([
            CTX, "area 2", "advertise-summary-lsas true", "!",
        ])

    def test_disable(self):
        configure_ospf_advertise_summary_lsas(self.device, area_id="2", enabled=False)
        self.device.configure.assert_called_once_with([
            CTX, "area 2", "advertise-summary-lsas false", "!",
        ])

    def test_unconfigure(self):
        unconfigure_ospf_advertise_summary_lsas(self.device, area_id="2")
        self.device.configure.assert_called_once_with([
            CTX, "area 2", "no advertise-summary-lsas", "!",
        ])


class TestConfigureSpfThrottle(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_partial(self):
        configure_ospf_spf_throttle(
            self.device, initial_delay=100, short_delay=300
        )
        self.device.configure.assert_called_once_with([
            CTX,
            "global spf throttle timers spf-initial-delay 100",
            "global spf throttle timers spf-short-delay 300",
            "!",
        ])

    def test_all_timers(self):
        configure_ospf_spf_throttle(
            self.device,
            initial_delay=50, short_delay=200, long_delay=5000,
            time_to_learn=500, holddown=10000,
        )
        self.assertEqual(self.device.configure.call_count, 1)

    def test_no_op_when_all_none(self):
        configure_ospf_spf_throttle(self.device)
        self.device.configure.assert_not_called()

    def test_unconfigure(self):
        unconfigure_ospf_spf_throttle(self.device)
        self.assertEqual(self.device.configure.call_count, 1)
        args, _ = self.device.configure.call_args
        # 6 lines + 1 "!" = 7 entries
        self.assertEqual(len(args[0]), 7)


class TestGetOspfLsdbLsaCount(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.get.get_ospf_lsdb")
    def test_no_filter_returns_total(self, mock_lsdb):
        mock_lsdb.return_value = {
            "0": {
                "lsa-types": {
                    "ROUTER_LSA": {"lsas": {"r1": {}, "r2": {}}},
                    "SUMMARY_IP_NETWORK_LSA": {"lsas": {"s1": {}}},
                }
            }
        }
        device = Mock()
        self.assertEqual(get_ospf_lsdb_lsa_count(device, area="0"), 3)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.get_ospf_lsdb")
    def test_specific_type(self, mock_lsdb):
        mock_lsdb.return_value = {
            "0": {
                "lsa-types": {
                    "ROUTER_LSA": {"lsas": {"r1": {}, "r2": {}}},
                    "SUMMARY_IP_NETWORK_LSA": {"lsas": {"s1": {}}},
                }
            }
        }
        device = Mock()
        self.assertEqual(
            get_ospf_lsdb_lsa_count(device, area="0", lsa_type="ROUTER_LSA"), 2
        )
        self.assertEqual(
            get_ospf_lsdb_lsa_count(device, area="0", lsa_type="AS_EXTERNAL_LSA"),
            0,
        )


class TestGetOspfRoute(unittest.TestCase):
    def test_returns_none_when_parser_missing(self):
        # ShowOspfGlobalRib doesn't yet exist in the parser module — the
        # API should gracefully return None on ImportError.
        device = Mock()
        result = get_ospf_route(device, prefix="4.4.4.4/32")
        self.assertIsNone(result)


class TestVerifyOspfRoutePresent(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_route")
    def test_route_present(self, mock_get):
        mock_get.return_value = {
            "prefix": "4.4.4.4/32",
            "path-type": "intra-area",
            "metric": 20,
        }
        device = Mock()
        self.assertTrue(
            verify_ospf_route_present(
                device, prefix="4.4.4.4/32",
                path_type="intra-area", expected_metric=20,
                max_time=2, check_interval=1,
            )
        )

    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_route")
    def test_route_absent_times_out(self, mock_get):
        mock_get.return_value = None
        device = Mock()
        self.assertFalse(
            verify_ospf_route_present(
                device, prefix="9.9.9.9/32",
                max_time=2, check_interval=1,
            )
        )

    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_route")
    def test_metric_mismatch_times_out(self, mock_get):
        mock_get.return_value = {
            "prefix": "4.4.4.4/32",
            "path-type": "intra-area",
            "metric": 999,
        }
        device = Mock()
        self.assertFalse(
            verify_ospf_route_present(
                device, prefix="4.4.4.4/32",
                expected_metric=20,
                max_time=2, check_interval=1,
            )
        )


if __name__ == "__main__":
    unittest.main()
