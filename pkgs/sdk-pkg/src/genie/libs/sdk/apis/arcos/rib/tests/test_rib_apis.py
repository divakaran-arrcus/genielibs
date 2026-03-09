"""Unit tests for ArcOS RIB get and verify APIs."""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError


# ---------------------------------------------------------------------------
# Sample parsed output fixtures
# ---------------------------------------------------------------------------

SAMPLE_RIB_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "entries": {
                "10.0.0.0/24": {
                    "prefix": "10.0.0.0/24",
                    "best-protocol": "ISIS",
                    "origins": {
                        "0": {
                            "origin-protocol": "ISIS",
                            "metric": 10,
                            "pref": 115,
                            "next-hops": {
                                "0": {
                                    "next-hop": "192.168.1.1",
                                    "interface": "ethernet-1/1",
                                }
                            },
                        }
                    },
                },
                "5.5.5.5/32": {
                    "prefix": "5.5.5.5/32",
                    "best-protocol": "BGP",
                },
            },
        }
    }
}

SAMPLE_LABEL_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "label-entries": {
                "10005": {
                    "label": 10005,
                    "label-type": "ISIS-SRGB",
                    "protocol": "ISIS",
                },
                "10006": {
                    "label": 10006,
                    "label-type": "ISIS-SRGB",
                    "protocol": "ISIS",
                },
            },
        }
    }
}

EMPTY_RIB_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "entries": {},
        }
    }
}


# ---------------------------------------------------------------------------
# Get API tests
# ---------------------------------------------------------------------------

class TestGetRib(unittest.TestCase):
    """Tests for RIB get APIs."""

    def setUp(self):
        self.device = Mock()

    # -- get_rib_entries -----------------------------------------------------

    def test_get_rib_entries_success(self):
        """get_rib_entries returns all entries for a network instance."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entries

        result = get_rib_entries(self.device)
        self.assertIn("10.0.0.0/24", result)
        self.assertIn("5.5.5.5/32", result)
        self.assertEqual(len(result), 2)

    def test_get_rib_entries_empty(self):
        """get_rib_entries returns empty dict when parser raises."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entries

        result = get_rib_entries(self.device)
        self.assertEqual(result, {})

    # -- get_rib_entry -------------------------------------------------------

    def test_get_rib_entry_found(self):
        """get_rib_entry returns a single prefix entry."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entry

        result = get_rib_entry(self.device, prefix="10.0.0.0/24")
        self.assertIsNotNone(result)
        self.assertEqual(result["prefix"], "10.0.0.0/24")
        self.assertEqual(result["best-protocol"], "ISIS")

    def test_get_rib_entry_not_found(self):
        """get_rib_entry returns None for missing prefix."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entry

        result = get_rib_entry(self.device, prefix="99.99.99.99/32")
        self.assertIsNone(result)

    # -- get_route_best_protocol ---------------------------------------------

    def test_get_route_best_protocol_found(self):
        """get_route_best_protocol returns protocol for a known prefix."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_route_best_protocol

        result = get_route_best_protocol(self.device, prefix="10.0.0.0/24")
        self.assertEqual(result, "ISIS")

    def test_get_route_best_protocol_not_found(self):
        """get_route_best_protocol returns None for missing prefix."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_route_best_protocol

        result = get_route_best_protocol(self.device, prefix="99.99.99.99/32")
        self.assertIsNone(result)

    # -- is_route_in_rib -----------------------------------------------------

    def test_is_route_in_rib_true(self):
        """is_route_in_rib returns True when prefix exists."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import is_route_in_rib

        result = is_route_in_rib(self.device, prefix="10.0.0.0/24")
        self.assertTrue(result)

    def test_is_route_in_rib_false(self):
        """is_route_in_rib returns False when prefix is missing."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import is_route_in_rib

        result = is_route_in_rib(self.device, prefix="99.99.99.99/32")
        self.assertFalse(result)

    def test_is_route_in_rib_parser_error(self):
        """is_route_in_rib returns False on parser error."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.rib.get import is_route_in_rib

        result = is_route_in_rib(self.device, prefix="10.0.0.0/24")
        self.assertFalse(result)

    # -- get_rib_entry_count -------------------------------------------------

    def test_get_rib_entry_count(self):
        """get_rib_entry_count returns number of entries."""
        self.device.parse.return_value = SAMPLE_RIB_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entry_count

        result = get_rib_entry_count(self.device)
        self.assertEqual(result, 2)

    def test_get_rib_entry_count_empty(self):
        """get_rib_entry_count returns 0 on empty parser output."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_entry_count

        result = get_rib_entry_count(self.device)
        self.assertEqual(result, 0)

    # -- get_rib_label_entries -----------------------------------------------

    def test_get_rib_label_entries_success(self):
        """get_rib_label_entries returns all label entries."""
        self.device.parse.return_value = SAMPLE_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entries

        result = get_rib_label_entries(self.device)
        self.assertIn("10005", result)
        self.assertIn("10006", result)

    def test_get_rib_label_entries_empty(self):
        """get_rib_label_entries returns empty dict on parser error."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entries

        result = get_rib_label_entries(self.device)
        self.assertEqual(result, {})

    # -- get_rib_label_entry -------------------------------------------------

    def test_get_rib_label_entry_found(self):
        """get_rib_label_entry returns a single label entry."""
        self.device.parse.return_value = SAMPLE_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entry

        result = get_rib_label_entry(self.device, label="10005")
        self.assertIsNotNone(result)
        self.assertEqual(result["label"], 10005)
        self.assertEqual(result["protocol"], "ISIS")

    def test_get_rib_label_entry_not_found(self):
        """get_rib_label_entry returns None for missing label."""
        self.device.parse.return_value = SAMPLE_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entry

        result = get_rib_label_entry(self.device, label="99999")
        self.assertIsNone(result)

    # -- get_rib_label_entry_count -------------------------------------------

    def test_get_rib_label_entry_count(self):
        """get_rib_label_entry_count returns number of label entries."""
        self.device.parse.return_value = SAMPLE_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entry_count

        result = get_rib_label_entry_count(self.device)
        self.assertEqual(result, 2)

    def test_get_rib_label_entry_count_empty(self):
        """get_rib_label_entry_count returns 0 on empty parser output."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.rib.get import get_rib_label_entry_count

        result = get_rib_label_entry_count(self.device)
        self.assertEqual(result, 0)


# ---------------------------------------------------------------------------
# Verify API tests
# ---------------------------------------------------------------------------

class TestVerifyRib(unittest.TestCase):
    """Tests for RIB verify APIs."""

    def setUp(self):
        self.device = Mock()

    # -- verify_route_in_rib -------------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_in_rib_success(self, mock_is):
        """verify_route_in_rib returns True when route exists."""
        mock_is.return_value = True

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_in_rib

        result = verify_route_in_rib(
            self.device,
            prefix="10.0.0.0/24",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_in_rib_timeout(self, mock_is):
        """verify_route_in_rib returns False when route not found within timeout."""
        mock_is.return_value = False

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_in_rib

        result = verify_route_in_rib(
            self.device,
            prefix="99.99.99.99/32",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_route_not_in_rib ---------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_not_in_rib_success(self, mock_is):
        """verify_route_not_in_rib returns True when route is absent."""
        mock_is.return_value = False

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_not_in_rib

        result = verify_route_not_in_rib(
            self.device,
            prefix="99.99.99.99/32",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_not_in_rib_timeout(self, mock_is):
        """verify_route_not_in_rib returns False when route still exists."""
        mock_is.return_value = True

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_not_in_rib

        result = verify_route_not_in_rib(
            self.device,
            prefix="10.0.0.0/24",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_route_protocol -----------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_match(self, mock_get):
        """verify_route_protocol returns True when protocol matches."""
        mock_get.return_value = "ISIS"

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_protocol

        result = verify_route_protocol(
            self.device,
            prefix="10.0.0.0/24",
            expected="ISIS",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_mismatch(self, mock_get):
        """verify_route_protocol returns False when protocol differs."""
        mock_get.return_value = "BGP"

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_protocol

        result = verify_route_protocol(
            self.device,
            prefix="10.0.0.0/24",
            expected="ISIS",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_not_found(self, mock_get):
        """verify_route_protocol returns False when prefix missing."""
        mock_get.return_value = None

        from genie.libs.sdk.apis.arcos.rib.verify import verify_route_protocol

        result = verify_route_protocol(
            self.device,
            prefix="99.99.99.99/32",
            expected="ISIS",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_label_in_rib -------------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_label_entry")
    def test_verify_label_in_rib_success(self, mock_get):
        """verify_label_in_rib returns True when label exists."""
        mock_get.return_value = {"label": 10005, "protocol": "ISIS"}

        from genie.libs.sdk.apis.arcos.rib.verify import verify_label_in_rib

        result = verify_label_in_rib(
            self.device,
            label=10005,
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_label_entry")
    def test_verify_label_in_rib_timeout(self, mock_get):
        """verify_label_in_rib returns False when label missing."""
        mock_get.return_value = None

        from genie.libs.sdk.apis.arcos.rib.verify import verify_label_in_rib

        result = verify_label_in_rib(
            self.device,
            label=99999,
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
