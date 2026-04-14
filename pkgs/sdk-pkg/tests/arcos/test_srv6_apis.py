"""Unit tests for ArcOS SRv6 / Segment Routing APIs.

Covers all SRv6 configure, get, and verify functions in
``genie.libs.sdk.apis.arcos.segment_routing``.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from unicon.core.errors import SubCommandFailure

# ---------------------------------------------------------------------------
# Configure imports
# ---------------------------------------------------------------------------
from genie.libs.sdk.apis.arcos.segment_routing.configure import (
    configure_srv6_encap_source_address,
    unconfigure_srv6_encap_source_address,
    configure_srv6_locator,
    unconfigure_srv6_locator,
    configure_srv6_locator_micro_segment,
    unconfigure_srv6_locator_micro_segment,
    configure_srv6_encap_ip_ttl_propagation,
    unconfigure_srv6_encap_ip_ttl_propagation,
    configure_srv6_encap_hop_limit,
    unconfigure_srv6_encap_hop_limit,
)

# ---------------------------------------------------------------------------
# Get imports
# ---------------------------------------------------------------------------
from genie.libs.sdk.apis.arcos.segment_routing.get import (
    get_srv6_locators,
    get_srv6_locator,
    get_srv6_locator_count,
    get_srv6_encap_source_address,
    is_srv6_locator_present,
    get_srv6_locator_prefix,
    get_srv6_locator_algorithm,
    get_srv6_locator_micro_segment_enabled,
    get_srv6_locator_node_length,
    get_srv6_locator_function_length,
)

# ---------------------------------------------------------------------------
# Verify imports
# ---------------------------------------------------------------------------
from genie.libs.sdk.apis.arcos.segment_routing.verify import (
    verify_srv6_locator_present,
    verify_srv6_locator_not_present,
    verify_srv6_encap_source_address,
    verify_srv6_locator_count,
    verify_srv6_locator_algorithm,
    verify_srv6_locator_micro_segment_enabled,
)


# ---------------------------------------------------------------------------
# Sample parser outputs (based on real device JSON)
# ---------------------------------------------------------------------------

SAMPLE_SRV6_CONFIG_PARSED = {
    "network-instances": {
        "default": {
            "srv6": {
                "config": {
                    "encapsulation": {
                        "source-address": "2400:2020:0:1191::91",
                    },
                    "locators": {
                        "base_slice0": {
                            "name": "base_slice0",
                            "locator-node-length": 24,
                            "prefix": "2400:2020:0:1191::/64",
                            "function-length": 16,
                        },
                        "base_slice131": {
                            "name": "base_slice131",
                            "locator-node-length": 24,
                            "prefix": "2400:2020:31:1191::/64",
                            "function-length": 16,
                            "algorithm": 131,
                        },
                    },
                }
            }
        }
    }
}

SAMPLE_SRV6_LOCATOR_PARSED = {
    "network-instances": {
        "default": {
            "srv6": {
                "locators": {
                    "base_slice0": {
                        "name": "base_slice0",
                        "locator-node-length": 24,
                        "prefix": "2400:2020:0:1191::/64",
                        "micro-segment-behavior-unode": False,
                        "function-length": 16,
                        "algorithm": 0,
                    },
                    "base_slice131": {
                        "name": "base_slice131",
                        "locator-node-length": 24,
                        "prefix": "2400:2020:31:1191::/64",
                        "micro-segment-behavior-unode": False,
                        "function-length": 16,
                        "algorithm": 131,
                    },
                    "usid_loc": {
                        "name": "usid_loc",
                        "locator-node-length": 16,
                        "prefix": "fc00:0:100::/48",
                        "micro-segment-behavior-unode": True,
                        "function-length": 16,
                        "algorithm": 0,
                    },
                }
            }
        }
    }
}

SAMPLE_EMPTY = {"network-instances": {}}


# ===================================================================
# Configure Tests
# ===================================================================

class TestConfigureSrv6EncapSource(unittest.TestCase):
    """Test SRv6 encapsulation source-address configure/unconfigure."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "R1"

    def test_configure_srv6_encap_source_address(self):
        configure_srv6_encap_source_address(
            self.device, "2001:db8::1"
        )
        self.device.configure.assert_called_once()
        args = self.device.configure.call_args[0][0]
        self.assertIn("network-instance default", args)
        self.assertIn("srv6 encapsulation source-address 2001:db8::1", args)
        self.assertIn("!", args)

    def test_unconfigure_srv6_encap_source_address(self):
        unconfigure_srv6_encap_source_address(self.device)
        self.device.configure.assert_called_once()
        args = self.device.configure.call_args[0][0]
        self.assertIn("no srv6 encapsulation source-address", args)


class TestConfigureSrv6Locator(unittest.TestCase):
    """Test SRv6 locator configure/unconfigure."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "R1"

    def test_configure_srv6_locator_basic(self):
        configure_srv6_locator(
            self.device, "loc1", "a::/64", 16
        )
        self.device.configure.assert_called_once()
        args = self.device.configure.call_args[0][0]
        self.assertIn("srv6 locator loc1", args)
        self.assertIn("prefix a::/64", args)
        self.assertIn("locator-node-length 16", args)
        self.assertNotIn("function-length", " ".join(args))
        self.assertNotIn("algorithm", " ".join(args))

    def test_configure_srv6_locator_full(self):
        configure_srv6_locator(
            self.device, "fa128", "fcbb:bb00:1::/48", 24,
            func_length=16, algorithm=128,
        )
        args = self.device.configure.call_args[0][0]
        self.assertIn("function-length 16", args)
        self.assertIn("algorithm 128", args)

    def test_unconfigure_srv6_locator(self):
        unconfigure_srv6_locator(self.device, "loc1")
        args = self.device.configure.call_args[0][0]
        self.assertIn("no srv6 locator loc1", args)


class TestConfigureSrv6MicroSegment(unittest.TestCase):
    """Test SRv6 locator micro-segment configure/unconfigure."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "R1"

    def test_configure_srv6_locator_micro_segment_enable(self):
        configure_srv6_locator_micro_segment(
            self.device, "usid1", enabled=True
        )
        args = self.device.configure.call_args[0][0]
        self.assertIn("micro-segment-behavior-unode true", args)

    def test_configure_srv6_locator_micro_segment_disable(self):
        configure_srv6_locator_micro_segment(
            self.device, "usid1", enabled=False
        )
        args = self.device.configure.call_args[0][0]
        self.assertIn("micro-segment-behavior-unode false", args)

    def test_unconfigure_srv6_locator_micro_segment(self):
        unconfigure_srv6_locator_micro_segment(self.device, "usid1")
        args = self.device.configure.call_args[0][0]
        self.assertIn("no micro-segment-behavior-unode", args)


class TestConfigureSrv6EncapTtlHopLimit(unittest.TestCase):
    """Test SRv6 encapsulation ip-ttl-propagation and hop-limit."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "R1"

    def test_configure_srv6_encap_ip_ttl_propagation_true(self):
        configure_srv6_encap_ip_ttl_propagation(self.device, enabled=True)
        args = self.device.configure.call_args[0][0]
        self.assertIn("srv6 encapsulation ip-ttl-propagation true", args)

    def test_configure_srv6_encap_ip_ttl_propagation_false(self):
        configure_srv6_encap_ip_ttl_propagation(self.device, enabled=False)
        args = self.device.configure.call_args[0][0]
        self.assertIn("srv6 encapsulation ip-ttl-propagation false", args)

    def test_unconfigure_srv6_encap_ip_ttl_propagation(self):
        unconfigure_srv6_encap_ip_ttl_propagation(self.device)
        args = self.device.configure.call_args[0][0]
        self.assertIn("no srv6 encapsulation ip-ttl-propagation", args)

    def test_configure_srv6_encap_hop_limit(self):
        configure_srv6_encap_hop_limit(self.device, hop_limit=15)
        args = self.device.configure.call_args[0][0]
        self.assertIn("srv6 encapsulation hop-limit 15", args)

    def test_unconfigure_srv6_encap_hop_limit(self):
        unconfigure_srv6_encap_hop_limit(self.device)
        args = self.device.configure.call_args[0][0]
        self.assertIn("no srv6 encapsulation hop-limit", args)

    def test_configure_custom_network_instance(self):
        configure_srv6_encap_hop_limit(
            self.device, hop_limit=64, network_instance="vrf1"
        )
        args = self.device.configure.call_args[0][0]
        self.assertIn("network-instance vrf1", args)


class TestConfigureFailures(unittest.TestCase):
    """Test SubCommandFailure re-raise on configure errors."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "R1"
        self.device.configure.side_effect = SubCommandFailure("mock error")

    def test_configure_failure_raises_subcommand(self):
        with self.assertRaises(SubCommandFailure):
            configure_srv6_encap_ip_ttl_propagation(self.device)

    def test_unconfigure_failure_raises_subcommand(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_srv6_encap_hop_limit(self.device)


# ===================================================================
# Get Tests
# ===================================================================

GET_MODULE = "genie.libs.sdk.apis.arcos.segment_routing.get"


class TestGetSrv6Locators(unittest.TestCase):
    """Test get_srv6_locators and related functions."""

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locators(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locators(device)
        self.assertIn("base_slice0", result)
        self.assertIn("base_slice131", result)
        self.assertIn("usid_loc", result)
        self.assertEqual(len(result), 3)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locators_empty(self, mock_parser_cls):
        from genie.metaparser.util.exceptions import SchemaEmptyParserError
        device = Mock()
        mock_parser_cls.return_value.parse.side_effect = (
            SchemaEmptyParserError
        )
        result = get_srv6_locators(device)
        self.assertEqual(result, {})

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator(device, "base_slice0")
        self.assertIsNotNone(result)
        self.assertEqual(result["prefix"], "2400:2020:0:1191::/64")

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_not_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator(device, "nonexistent")
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_count(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        self.assertEqual(get_srv6_locator_count(device), 3)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_is_srv6_locator_present_true(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        self.assertTrue(is_srv6_locator_present(device, "base_slice0"))

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_is_srv6_locator_present_false(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        self.assertFalse(is_srv6_locator_present(device, "nonexistent"))


class TestGetSrv6EncapSourceAddress(unittest.TestCase):
    """Test get_srv6_encap_source_address."""

    @patch(f"{GET_MODULE}.ShowSrv6Config")
    def test_get_srv6_encap_source_address(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_CONFIG_PARSED
        )
        result = get_srv6_encap_source_address(device)
        self.assertEqual(result, "2400:2020:0:1191::91")

    @patch(f"{GET_MODULE}.ShowSrv6Config")
    def test_get_srv6_encap_source_address_not_set(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = SAMPLE_EMPTY
        result = get_srv6_encap_source_address(device)
        self.assertIsNone(result)


class TestGetSrv6LocatorScalars(unittest.TestCase):
    """Test scalar get functions for locator fields."""

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_prefix(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_prefix(device, "base_slice0")
        self.assertEqual(result, "2400:2020:0:1191::/64")

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_algorithm(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_algorithm(device, "base_slice131")
        self.assertEqual(result, 131)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_algorithm_zero(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_algorithm(device, "base_slice0")
        self.assertEqual(result, 0)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_micro_segment_enabled_true(self, mock_cls):
        device = Mock()
        mock_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_micro_segment_enabled(device, "usid_loc")
        self.assertTrue(result)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_micro_segment_enabled_false(self, mock_cls):
        device = Mock()
        mock_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_micro_segment_enabled(
            device, "base_slice0"
        )
        self.assertFalse(result)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_micro_segment_not_found(self, mock_cls):
        device = Mock()
        mock_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_micro_segment_enabled(
            device, "nonexistent"
        )
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_node_length(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_node_length(device, "usid_loc")
        self.assertEqual(result, 16)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_function_length(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_function_length(device, "base_slice0")
        self.assertEqual(result, 16)

    @patch(f"{GET_MODULE}.ShowSrv6Locator")
    def test_get_srv6_locator_field_missing(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_SRV6_LOCATOR_PARSED
        )
        result = get_srv6_locator_prefix(device, "nonexistent")
        self.assertIsNone(result)


# ===================================================================
# Verify Tests
# ===================================================================

VERIFY_MODULE = "genie.libs.sdk.apis.arcos.segment_routing.verify"


class TestVerifySrv6LocatorPresent(unittest.TestCase):
    """Test verify_srv6_locator_present/not_present."""

    @patch(f"{VERIFY_MODULE}.is_srv6_locator_present")
    def test_verify_srv6_locator_present_success(self, mock_is):
        device = Mock()
        mock_is.return_value = True
        result = verify_srv6_locator_present(
            device, "loc1", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_srv6_locator_present")
    def test_verify_srv6_locator_present_timeout(self, mock_is):
        device = Mock()
        mock_is.return_value = False
        result = verify_srv6_locator_present(
            device, "loc1", max_time=5, check_interval=1
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.is_srv6_locator_present")
    def test_verify_srv6_locator_not_present_success(self, mock_is):
        device = Mock()
        mock_is.return_value = False
        result = verify_srv6_locator_not_present(
            device, "loc1", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_srv6_locator_present")
    def test_verify_srv6_locator_not_present_timeout(self, mock_is):
        device = Mock()
        mock_is.return_value = True
        result = verify_srv6_locator_not_present(
            device, "loc1", max_time=5, check_interval=1
        )
        self.assertFalse(result)


class TestVerifySrv6EncapSource(unittest.TestCase):
    """Test verify_srv6_encap_source_address."""

    @patch(f"{VERIFY_MODULE}.get_srv6_encap_source_address")
    def test_verify_srv6_encap_source_address_match(self, mock_get):
        device = Mock()
        mock_get.return_value = "2001:db8::1"
        result = verify_srv6_encap_source_address(
            device, "2001:db8::1", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_encap_source_address")
    def test_verify_srv6_encap_source_address_timeout(self, mock_get):
        device = Mock()
        mock_get.return_value = "2001:db8::99"
        result = verify_srv6_encap_source_address(
            device, "2001:db8::1", max_time=5, check_interval=1
        )
        self.assertFalse(result)


class TestVerifySrv6LocatorCount(unittest.TestCase):
    """Test verify_srv6_locator_count."""

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_count")
    def test_verify_srv6_locator_count_match(self, mock_get):
        device = Mock()
        mock_get.return_value = 3
        result = verify_srv6_locator_count(
            device, 3, max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_count")
    def test_verify_srv6_locator_count_timeout(self, mock_get):
        device = Mock()
        mock_get.return_value = 1
        result = verify_srv6_locator_count(
            device, 3, max_time=5, check_interval=1
        )
        self.assertFalse(result)


class TestVerifySrv6LocatorAlgorithm(unittest.TestCase):
    """Test verify_srv6_locator_algorithm."""

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_algorithm")
    def test_verify_srv6_locator_algorithm_match(self, mock_get):
        device = Mock()
        mock_get.return_value = 128
        result = verify_srv6_locator_algorithm(
            device, "fa128", 128, max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_algorithm")
    def test_verify_srv6_locator_algorithm_timeout(self, mock_get):
        device = Mock()
        mock_get.return_value = 0
        result = verify_srv6_locator_algorithm(
            device, "fa128", 128, max_time=5, check_interval=1
        )
        self.assertFalse(result)


class TestVerifySrv6LocatorMicroSegment(unittest.TestCase):
    """Test verify_srv6_locator_micro_segment_enabled."""

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_micro_segment_enabled")
    def test_verify_srv6_locator_micro_segment_match(self, mock_get):
        device = Mock()
        mock_get.return_value = True
        result = verify_srv6_locator_micro_segment_enabled(
            device, "usid1", True, max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_locator_micro_segment_enabled")
    def test_verify_srv6_locator_micro_segment_timeout(self, mock_get):
        device = Mock()
        mock_get.return_value = False
        result = verify_srv6_locator_micro_segment_enabled(
            device, "usid1", True, max_time=5, check_interval=1
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
