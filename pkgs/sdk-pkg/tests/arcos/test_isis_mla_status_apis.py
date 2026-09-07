"""Unit tests for ArcOS ISIS MLA status APIs and RIB backup-nexthop APIs.

Covers:

  ISIS get APIs (in ``genie.libs.sdk.apis.arcos.isis.get``):
    - get_isis_micro_loop_avoidance
    - get_isis_mla_status_timestamp

  ISIS verify APIs (in ``genie.libs.sdk.apis.arcos.isis.verify``):
    - verify_isis_mla_fired

  RIB get/verify APIs (in ``genie.libs.sdk.apis.arcos.rib.get`` /
  ``genie.libs.sdk.apis.arcos.rib.verify``):
    - get_rib_backup_nexthops
    - verify_rib_has_backup
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_micro_loop_avoidance,
    get_isis_mla_status_timestamp,
)
from genie.libs.sdk.apis.arcos.isis.verify import verify_isis_mla_fired
from genie.libs.sdk.apis.arcos.rib.get import get_rib_backup_nexthops
from genie.libs.sdk.apis.arcos.rib.verify import verify_rib_has_backup


# ---------------------------------------------------------------------------
# Sample parser / getter output fixtures
# ---------------------------------------------------------------------------

# ShowIsisMicroLoopAvoidance parser output. Post the composite-key redesign,
# 'status' rows are keyed by "<algo>-<level>-<topology-id>".
MLA_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "micro-loop-avoidance": {
                            "srv6-enabled": False,
                            "rib-update-delay": 8000,
                            "status": {
                                "0-2-ISIS_MT_ID0_STANDARD": {
                                    "algo": 0,
                                    "level": 2,
                                    "topology-id": "ISIS_MT_ID0_STANDARD",
                                    "mla-state": "ACTIVE",
                                    "last-event": "LINK-DOWN",
                                    "near-node": "rtr1",
                                    "far-node": "rtr2",
                                    "spf-start-timestamp": "2026-07-10T04:12:07.1+00:00",
                                }
                            },
                        }
                    }
                }
            }
        }
    }
}

# Flattened form as returned by get_isis_micro_loop_avoidance (this is what
# verify_isis_mla_fired / get_isis_mla_status_timestamp consume).
MLA_ROW_FULL = {
    "algo": 0,
    "level": 2,
    "topology-id": "ISIS_MT_ID0_STANDARD",
    "mla-state": "ACTIVE",
    "last-event": "LINK-DOWN",
    "near-node": "rtr1",
    "far-node": "rtr2",
    "spf-start-timestamp": "2026-07-10T04:12:07.1+00:00",
}

MLA_FLATTENED = {
    "srv6-enabled": False,
    "rib-update-delay": 8000,
    "status": {"0-2-ISIS_MT_ID0_STANDARD": MLA_ROW_FULL},
}


# ---------------------------------------------------------------------------
# get_isis_micro_loop_avoidance
# ---------------------------------------------------------------------------
class TestGetIsisMicroLoopAvoidance(unittest.TestCase):
    """Test get_isis_micro_loop_avoidance."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisMicroLoopAvoidance")
    def test_happy_path_returns_flattened_dict(self, mock_parser_cls):
        parser = Mock()
        parser.parse.return_value = MLA_PARSED
        mock_parser_cls.return_value = parser

        result = get_isis_micro_loop_avoidance(self.device)

        self.assertEqual(result.get("srv6-enabled"), False)
        self.assertEqual(result.get("rib-update-delay"), 8000)
        self.assertIn("status", result)
        row = result["status"]["0-2-ISIS_MT_ID0_STANDARD"]
        self.assertEqual(row["algo"], 0)
        self.assertEqual(row["level"], 2)
        self.assertEqual(row["topology-id"], "ISIS_MT_ID0_STANDARD")
        self.assertEqual(row["mla-state"], "ACTIVE")
        self.assertEqual(row["last-event"], "LINK-DOWN")
        self.assertEqual(row["near-node"], "rtr1")
        self.assertEqual(row["far-node"], "rtr2")

    @patch("genie.libs.parser.arcos.show_isis.ShowIsisMicroLoopAvoidance")
    def test_empty_parser_returns_empty_dict(self, mock_parser_cls):
        parser = Mock()
        parser.parse.side_effect = SchemaEmptyParserError({})
        mock_parser_cls.return_value = parser

        result = get_isis_micro_loop_avoidance(self.device)
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# get_isis_mla_status_timestamp
# ---------------------------------------------------------------------------
class TestGetIsisMlaStatusTimestamp(unittest.TestCase):
    """Test get_isis_mla_status_timestamp."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.isis.get.get_isis_micro_loop_avoidance")
    def test_returns_baseline_timestamp_for_algo(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = get_isis_mla_status_timestamp(self.device, algo=0)
        self.assertEqual(result, "2026-07-10T04:12:07.1+00:00")

    @patch("genie.libs.sdk.apis.arcos.isis.get.get_isis_micro_loop_avoidance")
    def test_returns_empty_string_when_algo_absent(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = get_isis_mla_status_timestamp(self.device, algo=128)
        self.assertEqual(result, "")

    @patch("genie.libs.sdk.apis.arcos.isis.get.get_isis_micro_loop_avoidance")
    def test_returns_empty_string_when_no_status_rows(self, mock_get_mla):
        mock_get_mla.return_value = {"srv6-enabled": False, "rib-update-delay": 8000}

        result = get_isis_mla_status_timestamp(self.device, algo=0)
        self.assertEqual(result, "")


# ---------------------------------------------------------------------------
# verify_isis_mla_fired
# ---------------------------------------------------------------------------
class TestVerifyIsisMlaFired(unittest.TestCase):
    """Test verify_isis_mla_fired."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_matches_on_algo_state_event_near_far(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = verify_isis_mla_fired(
            self.device,
            expected_event="LINK-DOWN",
            algo=0,
            near_node="rtr1",
            far_node="rtr2",
            max_time=2,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_since_timestamp_row_newer_than_baseline_matches(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = verify_isis_mla_fired(
            self.device,
            algo=0,
            since_timestamp="2026-07-10T04:00:00.0+00:00",
            max_time=1,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_since_timestamp_row_equal_to_baseline_does_not_match(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = verify_isis_mla_fired(
            self.device,
            algo=0,
            since_timestamp="2026-07-10T04:12:07.1+00:00",
            max_time=1,
            check_interval=1,
        )
        self.assertFalse(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_since_timestamp_row_older_than_baseline_does_not_match(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = verify_isis_mla_fired(
            self.device,
            algo=0,
            since_timestamp="2026-07-10T05:00:00.0+00:00",
            max_time=1,
            check_interval=1,
        )
        self.assertFalse(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_matching_row_with_no_timestamp_and_since_timestamp_is_accepted(
        self, mock_get_mla
    ):
        # Recently-fixed behavior: a matching row missing spf-start-timestamp
        # entirely must be ACCEPTED (returns True), not rejected, when
        # since_timestamp is set — freshness cannot be disproven, so the
        # match is taken as the fire we just triggered.
        row_no_ts = dict(MLA_ROW_FULL)
        del row_no_ts["spf-start-timestamp"]
        mock_get_mla.return_value = {
            "srv6-enabled": False,
            "rib-update-delay": 8000,
            "status": {"0-2-ISIS_MT_ID0_STANDARD": row_no_ts},
        }

        result = verify_isis_mla_fired(
            self.device,
            algo=0,
            since_timestamp="2026-07-10T04:00:00.0+00:00",
            max_time=1,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_algo_as_int_matches_row_with_int_algo(self, mock_get_mla):
        row_algo_128 = dict(MLA_ROW_FULL)
        row_algo_128["algo"] = 128
        mock_get_mla.return_value = {
            "status": {"128-2-ISIS_MT_ID0_STANDARD": row_algo_128}
        }

        result = verify_isis_mla_fired(
            self.device,
            algo=128,
            max_time=2,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.isis.verify.get_isis_micro_loop_avoidance")
    def test_no_matching_row_returns_false(self, mock_get_mla):
        mock_get_mla.return_value = MLA_FLATTENED

        result = verify_isis_mla_fired(
            self.device,
            algo=99,
            max_time=1,
            check_interval=1,
        )
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# get_rib_backup_nexthops
# ---------------------------------------------------------------------------
class TestGetRibBackupNexthops(unittest.TestCase):
    """Test get_rib_backup_nexthops."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_comma_separated_flags_match(self, mock_get_entry):
        mock_get_entry.return_value = {
            "prefix": "6.6.6.6/32",
            "origins": {
                "0": {
                    "next-hops": {
                        "0": {"interface": "swp1", "flags": "ATTACH"},
                        "1": {"interface": "swp2", "flags": "ATTACH,BACKUP"},
                    }
                }
            },
        }

        result = get_rib_backup_nexthops(self.device, "6.6.6.6/32")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["interface"], "swp2")

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_space_separated_flags_match(self, mock_get_entry):
        mock_get_entry.return_value = {
            "prefix": "6.6.6.6/32",
            "origins": {
                "0": {
                    "next-hops": {
                        "0": {"interface": "swp1", "flags": "ATTACH"},
                        "1": {"interface": "swp2", "flags": "ATTACH BACKUP"},
                    }
                }
            },
        }

        result = get_rib_backup_nexthops(self.device, "6.6.6.6/32")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["interface"], "swp2")

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_no_backup_flag_returns_empty_list(self, mock_get_entry):
        mock_get_entry.return_value = {
            "prefix": "5.5.5.5/32",
            "origins": {
                "0": {
                    "next-hops": {
                        "0": {"interface": "swp1", "flags": "ATTACH"},
                    }
                }
            },
        }

        result = get_rib_backup_nexthops(self.device, "5.5.5.5/32")
        self.assertEqual(result, [])

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_missing_entry_returns_empty_list(self, mock_get_entry):
        mock_get_entry.return_value = None

        result = get_rib_backup_nexthops(self.device, "9.9.9.9/32")
        self.assertEqual(result, [])

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_empty_entry_returns_empty_list(self, mock_get_entry):
        mock_get_entry.return_value = {}

        result = get_rib_backup_nexthops(self.device, "9.9.9.9/32")
        self.assertEqual(result, [])

    @patch("genie.libs.sdk.apis.arcos.rib.get.get_rib_entry")
    def test_ipv6_address_family_passed_through(self, mock_get_entry):
        mock_get_entry.return_value = {
            "prefix": "2001:db8::6/128",
            "origins": {
                "0": {
                    "next-hops": {
                        "0": {"interface": "swp2", "flags": "ATTACH,BACKUP"},
                    }
                }
            },
        }

        result = get_rib_backup_nexthops(self.device, "2001:db8::6/128", af="IPV6")

        mock_get_entry.assert_called_once_with(
            self.device, prefix="2001:db8::6/128", af="IPV6", ni="default"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["interface"], "swp2")


# ---------------------------------------------------------------------------
# verify_rib_has_backup
# ---------------------------------------------------------------------------
class TestVerifyRibHasBackup(unittest.TestCase):
    """Test verify_rib_has_backup."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_true_when_backup_on_expected_egress(self, mock_get_backups):
        mock_get_backups.return_value = [
            {"interface": "swp2", "flags": "ATTACH,BACKUP"}
        ]

        result = verify_rib_has_backup(
            self.device,
            "6.6.6.6/32",
            expected_backup_egress="swp2",
            max_time=2,
            check_interval=1,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_false_when_egress_differs(self, mock_get_backups):
        mock_get_backups.return_value = [
            {"interface": "swp2", "flags": "ATTACH,BACKUP"}
        ]

        result = verify_rib_has_backup(
            self.device,
            "6.6.6.6/32",
            expected_backup_egress="swp3",
            max_time=1,
            check_interval=1,
        )
        self.assertFalse(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_false_when_no_backup(self, mock_get_backups):
        mock_get_backups.return_value = []

        result = verify_rib_has_backup(
            self.device,
            "5.5.5.5/32",
            max_time=1,
            check_interval=1,
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# mla-state EMPTY — a FIFTH terminal state, added by ANPN-33133
# (arrcus_sw 797f74e4c0, "isis: cancel MLA when the computation produces no
# enforcement", on origin/RT2 2026-09-05).
#
# Before that fix, isis_mla_activate() armed the rib-update-delay at
# ctx-create time, on the PREDICTION that MLA would be needed. If the
# computation then enforced nothing, the delay stayed armed for its whole
# window and TI-LFA was deferred that long for an MLA that programmed no
# path. The fix decides from the OUTCOME: a counter of programmed MLA SID
# stacks, and isis_mla_cancel_if_no_paths_installed() tears the session down
# early, stamping EMPTY -- deliberately NOT CANCELED, which means "torn down
# by a conflicting topology change" and would misreport the cause.
#
# So the enum is five-way:
#   NONE      no session ever started (no compatible trigger)
#   ACTIVE    session running, rib-update-delay pending
#   EXPIRED   ran its full delay window and completed
#   CANCELED  torn down by a CONFLICTING topology change
#   EMPTY     activated, then programmed ZERO MLA SID stacks -> torn down
#
# EMPTY is terminal and means MLA DID fire. For a single-link shut on a small
# topology it is the COMMON outcome, not the exception: on the fixture below --
# the verbatim status dump from a failing CI run -- three of four (algo,
# topology) tuples ended EMPTY off one trigger.
# ---------------------------------------------------------------------------

# Verbatim from a failing nightly: `shut rtr1:swp1`, rib-update-delay 8000ms.
# algo 128 / MT_ID2 reached EXPIRED; the other three enforced nothing.
# Note algo 128 / MT_ID2's spf-start is ~8.19s LATER than the rest: for
# EXPIRED the timestamp is the POST-CONVERGENCE SPF, not the activating one,
# so timestamps must not be compared across states as a single clock.
MLA_STATUS_EMPTY_MAJORITY = {
    "srv6-enabled": True,
    "rib-update-delay": 8000,
    "status": {
        "0-2-ISIS_MT_ID0_STANDARD": {
            "algo": 0, "level": 2, "topology-id": "ISIS_MT_ID0_STANDARD",
            "mla-state": "EMPTY", "last-event": "LINK-DOWN",
            "near-node": "rtr1", "far-node": "rtr2",
            "spf-start-timestamp": "2026-09-07T13:44:38.867824+00:00"},
        "0-2-ISIS_MT_ID2_IPV6_UNICAST": {
            "algo": 0, "level": 2, "topology-id": "ISIS_MT_ID2_IPV6_UNICAST",
            "mla-state": "EMPTY", "last-event": "LINK-DOWN",
            "near-node": "rtr1", "far-node": "rtr2",
            "spf-start-timestamp": "2026-09-07T13:44:38.85857+00:00"},
        "128-2-ISIS_MT_ID0_STANDARD": {
            "algo": 128, "level": 2, "topology-id": "ISIS_MT_ID0_STANDARD",
            "mla-state": "EMPTY", "last-event": "LINK-DOWN",
            "near-node": "rtr1", "far-node": "rtr2",
            "spf-start-timestamp": "2026-09-07T13:44:38.870133+00:00"},
        "128-2-ISIS_MT_ID2_IPV6_UNICAST": {
            "algo": 128, "level": 2, "topology-id": "ISIS_MT_ID2_IPV6_UNICAST",
            "mla-state": "EXPIRED", "last-event": "LINK-DOWN",
            "near-node": "rtr1", "far-node": "rtr2",
            "spf-start-timestamp": "2026-09-07T13:44:47.062709+00:00"},
        "129-2-ISIS_MT_ID0_STANDARD": {
            "algo": 129, "level": 2, "topology-id": "ISIS_MT_ID0_STANDARD",
            "mla-state": "NONE"},
        "130-2-ISIS_MT_ID0_STANDARD": {
            "algo": 130, "level": 2, "topology-id": "ISIS_MT_ID0_STANDARD",
            "mla-state": "NONE"},
    },
}

_MLA_GET = ("genie.libs.sdk.apis.arcos.isis.verify."
            "get_isis_micro_loop_avoidance")
FAST_MLA = {"max_time": 0.05, "check_interval": 0.01}


class TestMlaEmptyIsAFire(unittest.TestCase):
    """EMPTY means MLA activated and then enforced nothing. It fired."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_algo0_empty_counts_as_fired(self):
        """The exact CI failure: algo 0 ends EMPTY, test reported no-fire."""
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertTrue(verify_isis_mla_fired(
                self.device, expected_event="LINK-DOWN", algo=0,
                near_node="rtr1", **FAST_MLA))

    def test_algo128_expired_still_counts(self):
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertTrue(verify_isis_mla_fired(
                self.device, expected_event="LINK-DOWN", algo=128,
                near_node="rtr1", **FAST_MLA))

    def test_never_started_is_still_not_a_fire(self):
        """NONE must NOT become a pass -- that is the real no-fire signal."""
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertFalse(verify_isis_mla_fired(
                self.device, expected_event="LINK-DOWN", algo=129,
                **FAST_MLA))

    def test_wrong_event_still_rejected(self):
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertFalse(verify_isis_mla_fired(
                self.device, expected_event="LINK-UP", algo=0, **FAST_MLA))

    def test_freshness_filter_still_applies_to_empty(self):
        """A stale EMPTY row must not satisfy a new trigger."""
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertFalse(verify_isis_mla_fired(
                self.device, expected_event="LINK-DOWN", algo=0,
                since_timestamp="2026-09-07T13:45:00+00:00", **FAST_MLA))

    def test_explicitly_narrowed_states_are_honoured(self):
        """A caller that really wants only a completed hold can still ask."""
        with patch(_MLA_GET, return_value=MLA_STATUS_EMPTY_MAJORITY):
            self.assertFalse(verify_isis_mla_fired(
                self.device, algo=0, expected_states=("EXPIRED",),
                **FAST_MLA))
