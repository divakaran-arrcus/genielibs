"""Unit tests for ArcOS OSPF APIs — Batch B (features-plan blockers)."""

import unittest
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.ospf.configure import (
    configure_ospf_interface,
    configure_ospf_interface_auth,
    configure_ospf_interface_auth_md5,
    unconfigure_ospf_interface_auth,
    configure_ospf_interface_ignore_mtu,
    unconfigure_ospf_interface_ignore_mtu,
    configure_ospf_redistribute_aggregate,
    unconfigure_ospf_redistribute_aggregate,
    configure_ospf_summary_aggregate,
    unconfigure_ospf_summary_aggregate,
    configure_ospf_route_preference,
    configure_ospf_max_lsa,
    unconfigure_ospf_max_lsa,
    configure_ospf_maintenance_mode,
    configure_ospf_maintenance_mode_trigger,
    unconfigure_ospf_maintenance_mode,
)
from genie.libs.sdk.apis.arcos.ospf.verify import (
    verify_ospf_interface_auth_type,
    verify_ospf_route_preference,
    verify_ospf_max_lsa,
    verify_ospf_maintenance_mode_state,
)


CTX = "network-instance default protocol OSPF default"


class TestConfigureOspfInterfaceExtended(unittest.TestCase):
    """The extended configure_ospf_interface accepts metric, priority, BFD."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_metric_and_priority(self):
        configure_ospf_interface(
            self.device, area_id="1", interface="swp2",
            metric=1000, priority=10,
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("metric 1000", cfg)
        self.assertIn("priority 10", cfg)

    def test_bfd(self):
        configure_ospf_interface(
            self.device, area_id="1", interface="swp1",
            bfd_enabled=True, bfd_profile="OSPF-BFD-1",
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("bfd enabled true", cfg)
        self.assertIn("bfd profile OSPF-BFD-1", cfg)

    def test_passive_now_applied(self):
        configure_ospf_interface(
            self.device, area_id="1", interface="loopback0", passive=True,
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("passive true", cfg)

    def test_backward_compatibility(self):
        # Old call site still works
        configure_ospf_interface(
            self.device, area_id="1", interface="swp1",
            network_type="POINT_TO_POINT_NETWORK",
            hello_interval=10, dead_interval=40,
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("network-type POINT_TO_POINT_NETWORK", cfg)
        self.assertIn("timers hello-interval 10", cfg)
        self.assertIn("timers dead-interval 40", cfg)


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_null_auth(self):
        configure_ospf_interface_auth(
            self.device, area_id="1", interface="swp1",
            auth_type="OSPF_AUTH_NULL",
        )
        self.device.configure.assert_called_once_with([
            CTX, "area 1", "interface swp1",
            "authentication auth-type OSPF_AUTH_NULL", "!",
        ])

    def test_md5_auth(self):
        configure_ospf_interface_auth_md5(
            self.device, area_id="1", interface="swp1",
            key_id=5, key_string="testkey",
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("authentication auth-type OSPF_AUTH_CRYPTO_KEY", cfg)
        self.assertIn("authentication crypto-key algorithm OSPF_CRYPTO_ALGO_MD5", cfg)
        self.assertIn("authentication crypto-key key-id 5", cfg)
        self.assertIn("authentication crypto-key key-string testkey", cfg)

    def test_unconfigure(self):
        unconfigure_ospf_interface_auth(self.device, area_id="1", interface="swp1")
        self.device.configure.assert_called_once_with([
            CTX, "area 1", "interface swp1", "no authentication", "!",
        ])


class TestIgnoreMtu(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_enable(self):
        configure_ospf_interface_ignore_mtu(
            self.device, area_id="1", interface="swp1", enabled=True,
        )
        self.device.configure.assert_called_once_with([
            CTX, "area 1", "interface swp1", "ignore-mtu true", "!",
        ])

    def test_unconfigure(self):
        unconfigure_ospf_interface_ignore_mtu(
            self.device, area_id="1", interface="swp1",
        )
        self.device.configure.assert_called_once_with([
            CTX, "area 1", "interface swp1", "no ignore-mtu", "!",
        ])


class TestAggregates(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_redistribute_aggregate(self):
        configure_ospf_redistribute_aggregate(
            self.device, prefix="100.0.0.0/8",
            advertise="AGGREGATE_ADVERTISE",
        )
        self.device.configure.assert_called_once_with([
            CTX,
            "global redistribute-aggregate 100.0.0.0/8",
            "advertise AGGREGATE_ADVERTISE",
            "!",
        ])

    def test_unconfigure_redistribute_aggregate(self):
        unconfigure_ospf_redistribute_aggregate(self.device, prefix="100.0.0.0/8")
        self.device.configure.assert_called_once_with([
            CTX, "global no redistribute-aggregate 100.0.0.0/8", "!",
        ])

    def test_summary_aggregate(self):
        configure_ospf_summary_aggregate(
            self.device, area_id="1", prefix="1.10.0.0/16",
            advertise="AGGREGATE_ADVERTISE", import_policy="pol1",
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("area 1", cfg)
        self.assertIn("summary-aggregate 1.10.0.0/16", cfg)
        self.assertIn("advertise AGGREGATE_ADVERTISE", cfg)
        self.assertIn("import-policy pol1", cfg)

    def test_unconfigure_summary_aggregate(self):
        unconfigure_ospf_summary_aggregate(
            self.device, area_id="1", prefix="1.10.0.0/16",
        )
        self.device.configure.assert_called_once_with([
            CTX, "area 1", "no summary-aggregate 1.10.0.0/16", "!",
        ])


class TestRoutePreference(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_all_three(self):
        configure_ospf_route_preference(
            self.device, intra_area=100, inter_area=115, external=120,
        )
        self.device.configure.assert_called_once_with([
            CTX,
            "global route-preference intra-area 100 inter-area 115 external 120",
            "!",
        ])

    def test_partial(self):
        configure_ospf_route_preference(self.device, intra_area=100)
        self.device.configure.assert_called_once_with([
            CTX, "global route-preference intra-area 100", "!",
        ])

    def test_no_op_when_none(self):
        configure_ospf_route_preference(self.device)
        self.device.configure.assert_not_called()


class TestMaxLsa(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_basic(self):
        configure_ospf_max_lsa(self.device, lsa_limit=100, warning_threshold=75)
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("global max-lsa lsa-limit 100", cfg)
        self.assertIn("global max-lsa warning-threshold 75", cfg)

    def test_unconfigure(self):
        unconfigure_ospf_max_lsa(self.device)
        self.device.configure.assert_called_once_with([
            CTX, "no global max-lsa", "!",
        ])


class TestMaintenanceMode(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr2"

    def test_router_lsa_settings(self):
        configure_ospf_maintenance_mode(
            self.device,
            router_lsa_set_link_metric=True,
            router_lsa_set_stub_metric=True,
        )
        args, _ = self.device.configure.call_args
        cfg = args[0]
        self.assertIn("global maintenance-mode router-lsa set-link-metric true", cfg)
        self.assertIn("global maintenance-mode router-lsa set-stub-metric true", cfg)

    def test_trigger_always(self):
        configure_ospf_maintenance_mode_trigger(self.device, always=True)
        self.device.configure.assert_called_once_with([
            CTX, "global maintenance-mode trigger always true", "!",
        ])

    def test_unconfigure(self):
        unconfigure_ospf_maintenance_mode(self.device)
        self.device.configure.assert_called_once_with([
            CTX, "no global maintenance-mode", "!",
        ])


class TestVerifyAuthType(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_interface")
    def test_match(self, mock_get):
        mock_get.return_value = {
            "authentication": {"auth-type": "OSPF_AUTH_CRYPTO_KEY"}
        }
        self.assertTrue(verify_ospf_interface_auth_type(
            Mock(), interface="swp1",
            expected_auth_type="OSPF_AUTH_CRYPTO_KEY",
            max_time=2, check_interval=1,
        ))

    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_interface")
    def test_mismatch_times_out(self, mock_get):
        mock_get.return_value = {"authentication": {"auth-type": "OSPF_AUTH_NULL"}}
        self.assertFalse(verify_ospf_interface_auth_type(
            Mock(), interface="swp1",
            expected_auth_type="OSPF_AUTH_CRYPTO_KEY",
            max_time=2, check_interval=1,
        ))


class TestVerifyRoutePreference(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_global")
    def test_match(self, mock_get):
        mock_get.return_value = {
            "route-preference": {"intra-area": 100, "inter-area": 115, "external": 120}
        }
        self.assertTrue(verify_ospf_route_preference(
            Mock(), intra_area=100, inter_area=115, external=120,
            max_time=2, check_interval=1,
        ))

    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_global")
    def test_partial_match(self, mock_get):
        mock_get.return_value = {
            "route-preference": {"intra-area": 100, "inter-area": 110, "external": 110}
        }
        self.assertTrue(verify_ospf_route_preference(
            Mock(), intra_area=100,
            max_time=2, check_interval=1,
        ))


class TestVerifyMaxLsa(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_global")
    def test_match(self, mock_get):
        mock_get.return_value = {
            "max-lsa": {"lsa-limit": 100, "warning-threshold": 75, "state": "NORMAL"}
        }
        self.assertTrue(verify_ospf_max_lsa(
            Mock(), lsa_limit=100, warning_threshold=75, state="NORMAL",
            max_time=2, check_interval=1,
        ))


class TestVerifyMaintenanceModeState(unittest.TestCase):
    @patch("genie.libs.sdk.apis.arcos.ospf.verify.get_ospf_global")
    def test_active(self, mock_get):
        mock_get.return_value = {"maintenance-mode": {"state": "ACTIVE"}}
        self.assertTrue(verify_ospf_maintenance_mode_state(
            Mock(), expected_state="ACTIVE",
            max_time=2, check_interval=1,
        ))


if __name__ == "__main__":
    unittest.main()
