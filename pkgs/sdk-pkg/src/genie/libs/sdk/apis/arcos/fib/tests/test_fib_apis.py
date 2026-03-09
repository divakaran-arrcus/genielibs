"""Unit tests for ArcOS FIB get and verify APIs."""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError


# ---------------------------------------------------------------------------
# Sample parsed output fixtures
# ---------------------------------------------------------------------------

SAMPLE_FIB_PREFIX_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "prefix-entries": {
                "10.0.0.0/24": {
                    "prefix": "10.0.0.0/24",
                    "next-hop-id": 643,
                    "publish-type": "PUBLISH_ADD",
                    "publish-id": 1,
                },
                "5.5.5.5/32": {
                    "prefix": "5.5.5.5/32",
                    "next-hop-id": 650,
                    "publish-type": "PUBLISH_ADD",
                    "publish-id": 2,
                },
            },
        }
    }
}

SAMPLE_FIB_NEXTHOP_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "nexthop-entries": {
                "643": {
                    "index": 643,
                    "eos0-nexthop-index": 643,
                    "level": 1,
                    "flags": "",
                    "paths": {
                        "0": {
                            "path-id": 0,
                            "path-type": "DIRECT",
                            "nh-type": "IPV4",
                            "next-hop": "192.168.1.1",
                            "interface": "ethernet-1/1",
                        }
                    },
                },
                "650": {
                    "index": 650,
                    "level": 1,
                    "flags": "",
                    "paths": {},
                },
            },
        }
    }
}

SAMPLE_FIB_LABEL_PARSED = {
    "network-instance": {
        "default": {
            "address-family": "IPV4",
            "label-entries": {
                "10005": {
                    "local-label": 10005,
                    "vpn-table-id": 1,
                    "next-hop-id": 643,
                    "control-word": False,
                    "flow-label": False,
                },
                "10006": {
                    "local-label": 10006,
                    "vpn-table-id": 1,
                    "next-hop-id": 650,
                    "control-word": False,
                    "flow-label": False,
                },
            },
        }
    }
}


# ---------------------------------------------------------------------------
# Get API tests
# ---------------------------------------------------------------------------

class TestGetFib(unittest.TestCase):
    """Tests for FIB get APIs."""

    def setUp(self):
        self.device = Mock()

    # -- get_fib_prefix_entries -----------------------------------------------

    def test_get_fib_prefix_entries_success(self):
        """get_fib_prefix_entries returns all prefix entries for a network instance."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entries

        result = get_fib_prefix_entries(self.device)
        self.assertIn("10.0.0.0/24", result)
        self.assertIn("5.5.5.5/32", result)
        self.assertEqual(len(result), 2)

    def test_get_fib_prefix_entries_empty(self):
        """get_fib_prefix_entries returns empty dict when parser raises."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entries

        result = get_fib_prefix_entries(self.device)
        self.assertEqual(result, {})

    # -- get_fib_prefix_entry -------------------------------------------------

    def test_get_fib_prefix_entry_found(self):
        """get_fib_prefix_entry returns a single prefix entry."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entry

        result = get_fib_prefix_entry(self.device, prefix="10.0.0.0/24")
        self.assertIsNotNone(result)
        self.assertEqual(result["prefix"], "10.0.0.0/24")
        self.assertEqual(result["next-hop-id"], 643)

    def test_get_fib_prefix_entry_not_found(self):
        """get_fib_prefix_entry returns None for missing prefix."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entry

        result = get_fib_prefix_entry(self.device, prefix="99.99.99.99/32")
        self.assertIsNone(result)

    # -- get_fib_prefix_entry_count -------------------------------------------

    def test_get_fib_prefix_entry_count(self):
        """get_fib_prefix_entry_count returns number of prefix entries."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entry_count

        result = get_fib_prefix_entry_count(self.device)
        self.assertEqual(result, 2)

    def test_get_fib_prefix_entry_count_empty(self):
        """get_fib_prefix_entry_count returns 0 on empty parser output."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_prefix_entry_count

        result = get_fib_prefix_entry_count(self.device)
        self.assertEqual(result, 0)

    # -- is_prefix_in_fib ----------------------------------------------------

    def test_is_prefix_in_fib_true(self):
        """is_prefix_in_fib returns True when prefix exists."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import is_prefix_in_fib

        result = is_prefix_in_fib(self.device, prefix="10.0.0.0/24")
        self.assertTrue(result)

    def test_is_prefix_in_fib_false(self):
        """is_prefix_in_fib returns False when prefix is missing."""
        self.device.parse.return_value = SAMPLE_FIB_PREFIX_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import is_prefix_in_fib

        result = is_prefix_in_fib(self.device, prefix="99.99.99.99/32")
        self.assertFalse(result)

    def test_is_prefix_in_fib_parser_error(self):
        """is_prefix_in_fib returns False on parser error."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import is_prefix_in_fib

        result = is_prefix_in_fib(self.device, prefix="10.0.0.0/24")
        self.assertFalse(result)

    # -- get_fib_nexthop_entries ----------------------------------------------

    def test_get_fib_nexthop_entries_success(self):
        """get_fib_nexthop_entries returns all nexthop entries."""
        self.device.parse.return_value = SAMPLE_FIB_NEXTHOP_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entries

        result = get_fib_nexthop_entries(self.device)
        self.assertIn("643", result)
        self.assertIn("650", result)
        self.assertEqual(len(result), 2)

    def test_get_fib_nexthop_entries_empty(self):
        """get_fib_nexthop_entries returns empty dict when parser raises."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entries

        result = get_fib_nexthop_entries(self.device)
        self.assertEqual(result, {})

    # -- get_fib_nexthop_entry ------------------------------------------------

    def test_get_fib_nexthop_entry_found(self):
        """get_fib_nexthop_entry returns a single nexthop entry."""
        self.device.parse.return_value = SAMPLE_FIB_NEXTHOP_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entry

        result = get_fib_nexthop_entry(self.device, index=643)
        self.assertIsNotNone(result)
        self.assertEqual(result["index"], 643)

    def test_get_fib_nexthop_entry_not_found(self):
        """get_fib_nexthop_entry returns None for missing nexthop."""
        self.device.parse.return_value = SAMPLE_FIB_NEXTHOP_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entry

        result = get_fib_nexthop_entry(self.device, index=99999)
        self.assertIsNone(result)

    # -- get_fib_nexthop_entry_count ------------------------------------------

    def test_get_fib_nexthop_entry_count(self):
        """get_fib_nexthop_entry_count returns number of nexthop entries."""
        self.device.parse.return_value = SAMPLE_FIB_NEXTHOP_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entry_count

        result = get_fib_nexthop_entry_count(self.device)
        self.assertEqual(result, 2)

    def test_get_fib_nexthop_entry_count_empty(self):
        """get_fib_nexthop_entry_count returns 0 on empty parser output."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_nexthop_entry_count

        result = get_fib_nexthop_entry_count(self.device)
        self.assertEqual(result, 0)

    # -- get_fib_label_entries ------------------------------------------------

    def test_get_fib_label_entries_success(self):
        """get_fib_label_entries returns all label entries."""
        self.device.parse.return_value = SAMPLE_FIB_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entries

        result = get_fib_label_entries(self.device)
        self.assertIn("10005", result)
        self.assertIn("10006", result)

    def test_get_fib_label_entries_empty(self):
        """get_fib_label_entries returns empty dict on parser error."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entries

        result = get_fib_label_entries(self.device)
        self.assertEqual(result, {})

    # -- get_fib_label_entry --------------------------------------------------

    def test_get_fib_label_entry_found(self):
        """get_fib_label_entry returns a single label entry."""
        self.device.parse.return_value = SAMPLE_FIB_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entry

        result = get_fib_label_entry(self.device, label="10005")
        self.assertIsNotNone(result)
        self.assertEqual(result["local-label"], 10005)

    def test_get_fib_label_entry_not_found(self):
        """get_fib_label_entry returns None for missing label."""
        self.device.parse.return_value = SAMPLE_FIB_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entry

        result = get_fib_label_entry(self.device, label="99999")
        self.assertIsNone(result)

    # -- get_fib_label_entry_count --------------------------------------------

    def test_get_fib_label_entry_count(self):
        """get_fib_label_entry_count returns number of label entries."""
        self.device.parse.return_value = SAMPLE_FIB_LABEL_PARSED

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entry_count

        result = get_fib_label_entry_count(self.device)
        self.assertEqual(result, 2)

    def test_get_fib_label_entry_count_empty(self):
        """get_fib_label_entry_count returns 0 on empty parser output."""
        self.device.parse.side_effect = SchemaEmptyParserError("No output")

        from genie.libs.sdk.apis.arcos.fib.get import get_fib_label_entry_count

        result = get_fib_label_entry_count(self.device)
        self.assertEqual(result, 0)


# ---------------------------------------------------------------------------
# Verify API tests
# ---------------------------------------------------------------------------

class TestVerifyFib(unittest.TestCase):
    """Tests for FIB verify APIs."""

    def setUp(self):
        self.device = Mock()

    # -- verify_prefix_in_fib ------------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.fib.verify.is_prefix_in_fib")
    def test_verify_prefix_in_fib_success(self, mock_is):
        """verify_prefix_in_fib returns True when prefix exists."""
        mock_is.return_value = True

        from genie.libs.sdk.apis.arcos.fib.verify import verify_prefix_in_fib

        result = verify_prefix_in_fib(
            self.device,
            prefix="10.0.0.0/24",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.fib.verify.is_prefix_in_fib")
    def test_verify_prefix_in_fib_timeout(self, mock_is):
        """verify_prefix_in_fib returns False when prefix not found within timeout."""
        mock_is.return_value = False

        from genie.libs.sdk.apis.arcos.fib.verify import verify_prefix_in_fib

        result = verify_prefix_in_fib(
            self.device,
            prefix="99.99.99.99/32",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_prefix_not_in_fib --------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.fib.verify.is_prefix_in_fib")
    def test_verify_prefix_not_in_fib_success(self, mock_is):
        """verify_prefix_not_in_fib returns True when prefix is absent."""
        mock_is.return_value = False

        from genie.libs.sdk.apis.arcos.fib.verify import verify_prefix_not_in_fib

        result = verify_prefix_not_in_fib(
            self.device,
            prefix="99.99.99.99/32",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.fib.verify.is_prefix_in_fib")
    def test_verify_prefix_not_in_fib_timeout(self, mock_is):
        """verify_prefix_not_in_fib returns False when prefix still present."""
        mock_is.return_value = True

        from genie.libs.sdk.apis.arcos.fib.verify import verify_prefix_not_in_fib

        result = verify_prefix_not_in_fib(
            self.device,
            prefix="10.0.0.0/24",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_nexthop_in_fib -----------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.fib.verify.get_fib_nexthop_entry")
    def test_verify_nexthop_in_fib_success(self, mock_get):
        """verify_nexthop_in_fib returns True when nexthop exists."""
        mock_get.return_value = {"index": 643, "level": 1}

        from genie.libs.sdk.apis.arcos.fib.verify import verify_nexthop_in_fib

        result = verify_nexthop_in_fib(
            self.device,
            index="643",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.fib.verify.get_fib_nexthop_entry")
    def test_verify_nexthop_in_fib_timeout(self, mock_get):
        """verify_nexthop_in_fib returns False when nexthop missing."""
        mock_get.return_value = None

        from genie.libs.sdk.apis.arcos.fib.verify import verify_nexthop_in_fib

        result = verify_nexthop_in_fib(
            self.device,
            index="99999",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)

    # -- verify_label_in_fib -------------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.fib.verify.get_fib_label_entry")
    def test_verify_label_in_fib_success(self, mock_get):
        """verify_label_in_fib returns True when label exists."""
        mock_get.return_value = {"local-label": 10005, "next-hop-id": 643}

        from genie.libs.sdk.apis.arcos.fib.verify import verify_label_in_fib

        result = verify_label_in_fib(
            self.device,
            label="10005",
            max_time=5,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.fib.verify.get_fib_label_entry")
    def test_verify_label_in_fib_timeout(self, mock_get):
        """verify_label_in_fib returns False when label missing."""
        mock_get.return_value = None

        from genie.libs.sdk.apis.arcos.fib.verify import verify_label_in_fib

        result = verify_label_in_fib(
            self.device,
            label="99999",
            max_time=5,
            check_interval=1,
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
