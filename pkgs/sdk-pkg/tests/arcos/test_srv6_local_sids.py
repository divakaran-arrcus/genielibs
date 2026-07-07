"""Unit tests for ArcOS SRv6 local-SID getter/verify APIs.

Covers get_srv6_local_sids* and verify_srv6_local_sid* in
``genie.libs.sdk.apis.arcos.segment_routing``.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

# ---------------------------------------------------------------------------
# Get imports
# ---------------------------------------------------------------------------
from genie.libs.sdk.apis.arcos.segment_routing.get import (
    get_srv6_local_sids,
    get_srv6_local_sid,
    get_srv6_local_sid_behavior,
    get_srv6_local_sids_by_locator,
)

# ---------------------------------------------------------------------------
# Verify imports
# ---------------------------------------------------------------------------
from genie.libs.sdk.apis.arcos.segment_routing.verify import (
    verify_srv6_local_sid_present,
    verify_srv6_local_sid_behavior,
)


# ---------------------------------------------------------------------------
# Sample parser output (based on ShowSrv6LocalSids schema)
# ---------------------------------------------------------------------------

SAMPLE_LOCAL_SIDS_PARSED = {
    "network_instance": {
        "default": {
            "local_sids": {
                "fcbb:bb00:1:1::/64": {
                    "behavior": "END_PSP_USD",
                    "locator_name": "base_slice0",
                    "client_name": "isis",
                },
                "fcbb:bb00:1:2::/64": {
                    "behavior": "END_X_PSP_USD",
                    "locator_name": "base_slice0",
                    "client_name": "isis",
                    "sid_paths": [
                        {
                            "next_hop_address": "fe80::1",
                            "interface": "ethernet-1/1",
                        },
                    ],
                },
                "fcbb:bb00:2:1::/64": {
                    "behavior": "END_PSP_USD",
                    "locator_name": "base_slice131",
                    "client_name": "bgp",
                },
            }
        }
    }
}

SAMPLE_EMPTY = {"network_instance": {}}

GET_MODULE = "genie.libs.sdk.apis.arcos.segment_routing.get"
VERIFY_MODULE = "genie.libs.sdk.apis.arcos.segment_routing.verify"


# ===================================================================
# Get Tests
# ===================================================================

class TestGetSrv6LocalSids(unittest.TestCase):
    """Test get_srv6_local_sids and related functions."""

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_all(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sids(device)
        self.assertEqual(len(result), 3)
        self.assertIn("fcbb:bb00:1:1::/64", result)
        self.assertIn("fcbb:bb00:1:2::/64", result)
        self.assertIn("fcbb:bb00:2:1::/64", result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_empty(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = SAMPLE_EMPTY
        result = get_srv6_local_sids(device)
        self.assertEqual(result, {})

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_schema_empty_parser_error(
        self, mock_parser_cls
    ):
        device = Mock()
        mock_parser_cls.return_value.parse.side_effect = (
            SchemaEmptyParserError
        )
        result = get_srv6_local_sids(device)
        self.assertEqual(result, {})

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sid(device, "fcbb:bb00:1:2::/64")
        self.assertIsNotNone(result)
        self.assertEqual(result["behavior"], "END_X_PSP_USD")
        self.assertEqual(result["locator_name"], "base_slice0")

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_not_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sid(device, "fcbb:bb00:99:1::/64")
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_empty_parse(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = SAMPLE_EMPTY
        result = get_srv6_local_sid(device, "fcbb:bb00:1:1::/64")
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_behavior_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sid_behavior(device, "fcbb:bb00:1:1::/64")
        self.assertEqual(result, "END_PSP_USD")

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_behavior_not_found(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sid_behavior(device, "fcbb:bb00:99:1::/64")
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sid_behavior_empty_parse(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = SAMPLE_EMPTY
        result = get_srv6_local_sid_behavior(device, "fcbb:bb00:1:1::/64")
        self.assertIsNone(result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_by_locator(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sids_by_locator(device, "base_slice0")
        self.assertEqual(len(result), 2)
        self.assertIn("fcbb:bb00:1:1::/64", result)
        self.assertIn("fcbb:bb00:1:2::/64", result)
        self.assertNotIn("fcbb:bb00:2:1::/64", result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_by_locator_other(self, mock_parser_cls):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sids_by_locator(device, "base_slice131")
        self.assertEqual(len(result), 1)
        self.assertIn("fcbb:bb00:2:1::/64", result)

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_by_locator_none_match(
        self, mock_parser_cls
    ):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = (
            SAMPLE_LOCAL_SIDS_PARSED
        )
        result = get_srv6_local_sids_by_locator(device, "nonexistent")
        self.assertEqual(result, {})

    @patch(f"{GET_MODULE}.ShowSrv6LocalSids")
    def test_get_srv6_local_sids_by_locator_empty_parse(
        self, mock_parser_cls
    ):
        device = Mock()
        mock_parser_cls.return_value.parse.return_value = SAMPLE_EMPTY
        result = get_srv6_local_sids_by_locator(device, "base_slice0")
        self.assertEqual(result, {})


# ===================================================================
# Verify Tests
# ===================================================================

class TestVerifySrv6LocalSidPresent(unittest.TestCase):
    """Test verify_srv6_local_sid_present with each filter combination."""

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_by_locator(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        result = verify_srv6_local_sid_present(
            device, locator_name="base_slice0", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_by_behavior(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        result = verify_srv6_local_sid_present(
            device, behavior="END_X_PSP_USD", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_by_sid(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        result = verify_srv6_local_sid_present(
            device, sid="fcbb:bb00:2:1::/64", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_combo_match(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        result = verify_srv6_local_sid_present(
            device,
            locator_name="base_slice0",
            behavior="END_X_PSP_USD",
            sid="fcbb:bb00:1:2::/64",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_combo_mismatch(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        # locator/behavior combination that doesn't exist together
        result = verify_srv6_local_sid_present(
            device,
            locator_name="base_slice131",
            behavior="END_X_PSP_USD",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_absent_timeout(self, mock_get):
        mock_get.return_value = SAMPLE_LOCAL_SIDS_PARSED[
            "network_instance"
        ]["default"]["local_sids"]
        device = Mock()
        result = verify_srv6_local_sid_present(
            device, sid="fcbb:bb00:99:1::/64", max_time=5, check_interval=1
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sids")
    def test_present_empty_data(self, mock_get):
        mock_get.return_value = {}
        device = Mock()
        result = verify_srv6_local_sid_present(
            device, locator_name="base_slice0", max_time=5, check_interval=1
        )
        self.assertFalse(result)


class TestVerifySrv6LocalSidBehavior(unittest.TestCase):
    """Test verify_srv6_local_sid_behavior."""

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sid_behavior")
    def test_behavior_match(self, mock_get):
        mock_get.return_value = "END_PSP_USD"
        device = Mock()
        result = verify_srv6_local_sid_behavior(
            device, "fcbb:bb00:1:1::/64", "END_PSP_USD",
            max_time=5, check_interval=1,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sid_behavior")
    def test_behavior_mismatch(self, mock_get):
        mock_get.return_value = "END_X_PSP_USD"
        device = Mock()
        result = verify_srv6_local_sid_behavior(
            device, "fcbb:bb00:1:1::/64", "END_PSP_USD",
            max_time=5, check_interval=1,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_srv6_local_sid_behavior")
    def test_behavior_sid_absent(self, mock_get):
        mock_get.return_value = None
        device = Mock()
        result = verify_srv6_local_sid_behavior(
            device, "fcbb:bb00:99:1::/64", "END_PSP_USD",
            max_time=5, check_interval=1,
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
