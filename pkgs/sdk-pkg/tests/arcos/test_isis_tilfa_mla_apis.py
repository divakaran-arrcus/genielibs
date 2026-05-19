"""Unit tests for ArcOS ISIS TI-LFA / MLA APIs.

Covers the 5 functions added 2026-05-13 to support TI-LFA and MLA test
scripts:

  Get APIs (in ``genie.libs.sdk.apis.arcos.isis.get``):
    - get_isis_fast_reroute
    - get_isis_protection_trackers

  Verify APIs (in ``genie.libs.sdk.apis.arcos.isis.verify``):
    - verify_isis_route_has_backup
    - verify_isis_no_backup_for_prefix
    - verify_isis_no_mla_for_prefix
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_fast_reroute,
    get_isis_protection_trackers,
)
from genie.libs.sdk.apis.arcos.isis.verify import (
    verify_isis_route_has_backup,
    verify_isis_no_backup_for_prefix,
    verify_isis_no_mla_for_prefix,
)


# ---------------------------------------------------------------------------
# Sample parser outputs (shape matches the ShowIsisFastReroute /
# ShowIsisProtectionTracker / ShowIsisRoute parsers).
# ---------------------------------------------------------------------------

FAST_REROUTE_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "fast-reroute": {
                        "IPV4-UNICAST": {
                            "afi-name": "IPV4",
                            "safi-name": "UNICAST",
                            "prefixes": {
                                "6.6.6.6/32": {
                                    "prefix": "6.6.6.6/32",
                                    "levels": {
                                        2: {
                                            "level-number": 2,
                                            "reroute-type": "TI_LFA",
                                            "protection-types": [
                                                "NODE_PROTECTION",
                                                "LINK_PROTECTION",
                                            ],
                                            "flags": ["PQ_IS_ADJACENT"],
                                            "pq-node-system-id": "rtr4.00",
                                            "nexthop-interface": "swp2",
                                            "nexthop-address": "10.14.2.4",
                                            "origin-system-id": "rtr6.00",
                                            "metric": 50,
                                        }
                                    },
                                }
                            },
                        }
                    }
                }
            }
        }
    }
}


FAST_REROUTE_MLA_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "fast-reroute": {
                        "IPV4-UNICAST": {
                            "prefixes": {
                                "6.6.6.6/32": {
                                    "prefix": "6.6.6.6/32",
                                    "levels": {
                                        2: {
                                            "level-number": 2,
                                            "reroute-type": "MICRO_LOOP_AVOIDANCE",
                                            "metric": 60,
                                        }
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


PROTECTION_TRACKER_SINGLE = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "protection-trackers": {
                            "protection-tracker": {
                                "268435460": {
                                    "id": "268435460",
                                    "reference-count": 3,
                                    "interface": "swp1",
                                    "system-id": "rtr2.00",
                                    "last-updated-time": "2026-05-12T14:50:20+00:00",
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


PROTECTION_TRACKER_MULTI = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "protection-trackers": {
                            "protection-tracker": {
                                "268435459": {
                                    "id": "268435459",
                                    "reference-count": 1,
                                    "interface": "swp1",
                                    "system-id": "rtr6.00",
                                    "last-updated-time": "2026-05-12T18:00:00+00:00",
                                },
                                "268435460": {
                                    "id": "268435460",
                                    "reference-count": 1,
                                    "interface": "swp2",
                                    "system-id": "rtr2.00",
                                    "last-updated-time": "2026-05-12T18:00:01+00:00",
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}


ROUTE_WITH_BACKUP = {
    "prefix": "6.6.6.6/32",
    "metric": 40,
    "next_hops": {
        "1": {
            "interface": "swp1",
            "address": "10.12.1.2",
        },
        "2": {
            "interface": "swp2",
            "address": "10.14.2.4",
            "backup": True,
            "pushed-mpls-label-stack": [16005, 16006],
        },
    },
}


ROUTE_NO_BACKUP = {
    "prefix": "5.5.5.5/32",
    "metric": 30,
    "next_hops": {
        "1": {"interface": "swp1", "address": "10.12.1.2"},
        "2": {"interface": "swp2", "address": "10.14.2.4"},
    },
}


# ===========================================================================
# get_isis_fast_reroute
# ===========================================================================
class TestGetIsisFastReroute(unittest.TestCase):
    """Test get_isis_fast_reroute."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisFastReroute")
    def test_with_prefix_returns_prefix_keyed_dict(self, mock_parser_cls):
        parser = Mock()
        parser.parse.return_value = FAST_REROUTE_PARSED
        mock_parser_cls.return_value = parser

        result = get_isis_fast_reroute(self.device, prefix="6.6.6.6/32")

        self.assertIn("6.6.6.6/32", result)
        levels = result["6.6.6.6/32"]["levels"]
        self.assertEqual(levels[2]["reroute-type"], "TI_LFA")
        self.assertEqual(levels[2]["pq-node-system-id"], "rtr4.00")

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisFastReroute")
    def test_without_prefix_returns_all(self, mock_parser_cls):
        parser = Mock()
        parser.parse.return_value = FAST_REROUTE_PARSED
        mock_parser_cls.return_value = parser

        result = get_isis_fast_reroute(self.device)

        self.assertEqual(len(result), 1)
        self.assertIn("6.6.6.6/32", result)

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisFastReroute")
    def test_empty_parser_returns_empty_dict(self, mock_parser_cls):
        parser = Mock()
        parser.parse.side_effect = SchemaEmptyParserError({})
        mock_parser_cls.return_value = parser

        result = get_isis_fast_reroute(self.device, prefix="9.9.9.9/32")
        self.assertEqual(result, {})

    def test_invalid_address_family_raises(self):
        with self.assertRaises(ValueError):
            get_isis_fast_reroute(self.device, address_family="ipv7")


# ===========================================================================
# get_isis_protection_trackers
# ===========================================================================
class TestGetIsisProtectionTrackers(unittest.TestCase):
    """Test get_isis_protection_trackers."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisProtectionTracker")
    def test_single_tracker(self, mock_parser_cls):
        parser = Mock()
        parser.parse.return_value = PROTECTION_TRACKER_SINGLE
        mock_parser_cls.return_value = parser

        result = get_isis_protection_trackers(self.device)

        self.assertEqual(len(result), 1)
        self.assertIn("268435460", result)
        entry = result["268435460"]
        self.assertEqual(entry["interface"], "swp1")
        self.assertEqual(entry["system-id"], "rtr2.00")
        self.assertEqual(entry["reference-count"], 3)

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisProtectionTracker")
    def test_multi_tracker(self, mock_parser_cls):
        parser = Mock()
        parser.parse.return_value = PROTECTION_TRACKER_MULTI
        mock_parser_cls.return_value = parser

        result = get_isis_protection_trackers(self.device)

        self.assertEqual(len(result), 2)
        self.assertIn("268435459", result)
        self.assertIn("268435460", result)
        self.assertEqual(result["268435459"]["interface"], "swp1")
        self.assertEqual(result["268435460"]["interface"], "swp2")

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisProtectionTracker")
    def test_empty_parser_returns_empty_dict(self, mock_parser_cls):
        parser = Mock()
        parser.parse.side_effect = SchemaEmptyParserError({})
        mock_parser_cls.return_value = parser

        result = get_isis_protection_trackers(self.device)
        self.assertEqual(result, {})


# ===========================================================================
# verify_isis_route_has_backup
# ===========================================================================
class TestVerifyIsisRouteHasBackup(unittest.TestCase):
    """Test verify_isis_route_has_backup."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_success(self, mock_get_route):
        mock_get_route.return_value = ROUTE_WITH_BACKUP

        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32", max_time=5, check_interval=1
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_with_egress_constraint_match(self, mock_get_route):
        mock_get_route.return_value = ROUTE_WITH_BACKUP

        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32",
            expected_backup_egress="swp2",
            max_time=5, check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_with_label_stack_len_match(self, mock_get_route):
        mock_get_route.return_value = ROUTE_WITH_BACKUP

        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32",
            expected_label_stack_len=2,
            max_time=5, check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_timeout_when_no_backup(self, mock_get_route):
        mock_get_route.return_value = ROUTE_NO_BACKUP

        result = verify_isis_route_has_backup(
            self.device, "5.5.5.5/32", max_time=2, check_interval=1
        )
        self.assertFalse(result)


# ===========================================================================
# verify_isis_no_backup_for_prefix
# ===========================================================================
class TestVerifyIsisNoBackupForPrefix(unittest.TestCase):
    """Test verify_isis_no_backup_for_prefix."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_success_when_no_backup(self, mock_get_route):
        mock_get_route.return_value = ROUTE_NO_BACKUP

        result = verify_isis_no_backup_for_prefix(
            self.device, "5.5.5.5/32", max_time=2, check_interval=1
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_route")
    def test_fails_when_backup_appears(self, mock_get_route):
        mock_get_route.return_value = ROUTE_WITH_BACKUP

        result = verify_isis_no_backup_for_prefix(
            self.device, "6.6.6.6/32", max_time=2, check_interval=1
        )
        self.assertFalse(result)


# ===========================================================================
# verify_isis_no_mla_for_prefix
# ===========================================================================
class TestVerifyIsisNoMlaForPrefix(unittest.TestCase):
    """Test verify_isis_no_mla_for_prefix."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_fast_reroute")
    def test_success_when_no_frr_entries(self, mock_get_frr):
        mock_get_frr.return_value = {}

        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32", max_time=2, check_interval=1
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_fast_reroute")
    def test_success_with_tilfa_only(self, mock_get_frr):
        # FRR exists but reroute-type is TI_LFA — should still pass (no MLA)
        mock_get_frr.return_value = FAST_REROUTE_PARSED["network-instance"][
            "default"
        ]["isis"]["default"]["fast-reroute"]["IPV4-UNICAST"]["prefixes"]

        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32", max_time=2, check_interval=1
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_fast_reroute")
    def test_fails_when_mla_active(self, mock_get_frr):
        mock_get_frr.return_value = FAST_REROUTE_MLA_PARSED["network-instance"][
            "default"
        ]["isis"]["default"]["fast-reroute"]["IPV4-UNICAST"]["prefixes"]

        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32", max_time=2, check_interval=1
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
