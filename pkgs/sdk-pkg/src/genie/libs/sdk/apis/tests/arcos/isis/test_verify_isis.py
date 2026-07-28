#!/usr/bin/env python3
"""Unit tests for arcOS ISIS verify APIs (full coverage).

Verify helpers wrap the get helpers in a Timeout retry loop and return bool.
Positive cases return True on the first iteration (fast); negative cases use
max_time=0 so the loop exits immediately instead of polling.

Census-backfill additions (below the original 3-function class) follow the
pattern established by the arcos/rib verify tests: rather than driving the
underlying get/is_ helper through a ``_DummyDevice`` + real ``Timeout`` loop,
each verify_* function's underlying helper (imported by name into
``isis/verify.py``'s own module namespace) is patched directly at
``genie.libs.sdk.apis.arcos.isis.verify.<helper>``. This matters because
``Timeout(max_time=0, ...).iterate()`` returns False immediately -- the loop
body (and the helper call inside it) never runs at all -- so a naive
"positive=default max_time, negative=max_time=0" split would silently skip
real coverage of the negative path. Instead:

  * "found-first-try" cases patch the helper to return the passing value
    immediately, with a small non-zero max_time -- the loop body runs exactly
    once and returns True on the first check.
  * "exhausts-timeout" cases patch the helper to always return the failing
    value, with max_time=0.05 / check_interval=0.02 (real time, but tiny) --
    this reliably drives several loop iterations, exercising timeout.sleep()
    and the loop-continues path before falling through to the final return.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
import genie.libs.sdk.apis.arcos.isis.verify as verify_module
from genie.libs.sdk.apis.arcos.isis.verify import (
    verify_isis_system_id,
    verify_isis_adjacency_present,
    verify_isis_adjacency_not_present,
    verify_isis_adjacency_state,
    verify_isis_route_present,
    verify_isis_flex_algo_route_present,
    verify_isis_flex_algo_route_not_present,
    verify_isis_flex_algo_definition_present,
    verify_isis_flex_algo_definition_not_present,
    verify_isis_flex_algo_fast_reroute_present,
    verify_isis_flex_algo_fast_reroute_not_present,
    verify_isis_route_has_backup,
    verify_isis_no_backup_for_prefix,
    verify_isis_no_mla_for_prefix,
    verify_isis_mla_fired,
)


_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "net": ["49.0000.0000.0000.0005.00"],
                        "system-id": "0000.0000.0005",
                    },
                    "interface": {
                        "swp1": {
                            "level": {
                                2: {"adjacency": {"rtr2": {"state": "UP"}}}
                            }
                        },
                    },
                }
            }
        }
    }
}


class _DummyDevice:
    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestVerifyIsis(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)
        self.empty = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_system_id_present(self):
        self.assertTrue(verify_isis_system_id(self.device))

    def test_system_id_absent_fast_fail(self):
        self.assertFalse(verify_isis_system_id(self.empty, max_time=0))

    def test_adjacency_present(self):
        self.assertTrue(verify_isis_adjacency_present(self.device, adjacency="rtr2"))

    def test_adjacency_present_false_fast_fail(self):
        self.assertFalse(
            verify_isis_adjacency_present(self.device, adjacency="rtrX", max_time=0)
        )

    def test_adjacency_not_present_true(self):
        self.assertTrue(
            verify_isis_adjacency_not_present(self.device, adjacency="rtrX")
        )

    def test_adjacency_not_present_false_fast_fail(self):
        # rtr2 IS present, so "not present" is False (fast-fail via max_time=0).
        self.assertFalse(
            verify_isis_adjacency_not_present(self.device, adjacency="rtr2", max_time=0)
        )


# ---------------------------------------------------------------------------
# Census-backfill additions.
# ---------------------------------------------------------------------------

VERIFY_MODULE = "genie.libs.sdk.apis.arcos.isis.verify"

# Small, real, non-zero timings so the Timeout loop body actually executes
# (Timeout(max_time=0, ...) never enters the loop at all).
FOUND_MAX_TIME = 1
FOUND_INTERVAL = 0.5
EXHAUST_MAX_TIME = 0.05
EXHAUST_INTERVAL = 0.02


class _Device:
    """Verify APIs only forward ``device`` to the (mocked) get/is_ helper."""


class TestVerifyIsisAdjacencyState(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.get_isis_adjacency_state")
    def test_found_first_try(self, mock_get):
        mock_get.return_value = "UP"
        result = verify_isis_adjacency_state(
            self.device, adjacency="rtr2", expected_state="up",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_adjacency_state")
    def test_mismatch_exhausts_timeout(self, mock_get):
        mock_get.return_value = "DOWN"
        result = verify_isis_adjacency_state(
            self.device, adjacency="rtr2", expected_state="UP",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_adjacency_state")
    def test_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_adjacency_state(
            self.device, adjacency="rtr2", expected_state="UP",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisRoutePresent(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.get_isis_routes")
    def test_found_first_try(self, mock_get):
        mock_get.return_value = {"5.5.5.5/32": {}}
        result = verify_isis_route_present(
            self.device, "5.5.5.5/32",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_routes")
    def test_missing_exhausts_timeout(self, mock_get):
        mock_get.return_value = {}
        result = verify_isis_route_present(
            self.device, "9.9.9.9/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_routes")
    def test_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_route_present(
            self.device, "5.5.5.5/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisFlexAlgoRoutePresent(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_present_found_first_try(self, mock_is):
        mock_is.return_value = True
        result = verify_isis_flex_algo_route_present(
            self.device, "10.0.0.0/24",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = False
        result = verify_isis_flex_algo_route_present(
            self.device, "9.9.9.9/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_present_exception_path(self, mock_is):
        mock_is.side_effect = Exception("boom")
        result = verify_isis_flex_algo_route_present(
            self.device, "10.0.0.0/24",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_not_present_found_first_try(self, mock_is):
        mock_is.return_value = False
        result = verify_isis_flex_algo_route_not_present(
            self.device, "9.9.9.9/32",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_not_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = True
        result = verify_isis_flex_algo_route_not_present(
            self.device, "10.0.0.0/24",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_route_present")
    def test_not_present_exception_path(self, mock_is):
        # Exception -> present=True (assumed) -> "not present" never satisfied.
        mock_is.side_effect = Exception("boom")
        result = verify_isis_flex_algo_route_not_present(
            self.device, "10.0.0.0/24",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisFlexAlgoDefinitionPresent(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_present_found_first_try(self, mock_get):
        mock_get.return_value = {"128": {"id": 128}}
        result = verify_isis_flex_algo_definition_present(
            self.device, 128,
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_present_exhausts_timeout(self, mock_get):
        mock_get.return_value = {}
        result = verify_isis_flex_algo_definition_present(
            self.device, 200,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_present_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_flex_algo_definition_present(
            self.device, 128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_not_present_found_first_try(self, mock_get):
        mock_get.return_value = {}
        result = verify_isis_flex_algo_definition_not_present(
            self.device, 200,
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_not_present_exhausts_timeout(self, mock_get):
        mock_get.return_value = {"128": {"id": 128}}
        result = verify_isis_flex_algo_definition_not_present(
            self.device, 128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_flex_algo_definitions")
    def test_not_present_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_flex_algo_definition_not_present(
            self.device, 128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisFlexAlgoFastReroutePresent(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_present_found_first_try(self, mock_is):
        mock_is.return_value = True
        result = verify_isis_flex_algo_fast_reroute_present(
            self.device, "3.3.3.3/32", algo=128,
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = False
        result = verify_isis_flex_algo_fast_reroute_present(
            self.device, "9.9.9.9/32", algo=128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_present_exception_path(self, mock_is):
        mock_is.side_effect = Exception("boom")
        result = verify_isis_flex_algo_fast_reroute_present(
            self.device, "3.3.3.3/32", algo=128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_not_present_found_first_try(self, mock_is):
        mock_is.return_value = False
        result = verify_isis_flex_algo_fast_reroute_not_present(
            self.device, "9.9.9.9/32", algo=128,
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_not_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = True
        result = verify_isis_flex_algo_fast_reroute_not_present(
            self.device, "3.3.3.3/32", algo=128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch(f"{VERIFY_MODULE}.is_isis_flex_algo_fast_reroute_present")
    def test_not_present_exception_path(self, mock_is):
        mock_is.side_effect = Exception("boom")
        result = verify_isis_flex_algo_fast_reroute_not_present(
            self.device, "3.3.3.3/32", algo=128,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisRouteHasBackup(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @staticmethod
    def _route_with_backup(interface="swp2", label_stack=None):
        nh = {"interface": interface, "backup": True}
        if label_stack is not None:
            nh["label_stack"] = label_stack
        return {
            "prefix": "6.6.6.6/32",
            "levels": {
                "2": {
                    "next-hops": [
                        {"interface": "swp1"},
                        nh,
                    ]
                }
            },
        }

    @staticmethod
    def _route_without_backup():
        return {
            "prefix": "6.6.6.6/32",
            "levels": {"2": {"next-hops": [{"interface": "swp1"}]}},
        }

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_found_first_try(self, mock_get):
        mock_get.return_value = self._route_with_backup()
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_egress_match_found_first_try(self, mock_get):
        mock_get.return_value = self._route_with_backup(interface="swp2")
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32", expected_backup_egress="swp2",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_egress_mismatch_exhausts_timeout(self, mock_get):
        mock_get.return_value = self._route_with_backup(interface="swp2")
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32", expected_backup_egress="swp9",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_label_stack_match_found_first_try(self, mock_get):
        mock_get.return_value = self._route_with_backup(label_stack=[16005])
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32", expected_label_stack_len=1,
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_label_stack_mismatch_exhausts_timeout(self, mock_get):
        mock_get.return_value = self._route_with_backup(label_stack=[16005])
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32", expected_label_stack_len=2,
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_no_backup_exhausts_timeout(self, mock_get):
        mock_get.return_value = self._route_without_backup()
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_has_backup_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_route_has_backup(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


class TestVerifyIsisNoBackupForPrefix(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_no_backup_observed_true(self, mock_get):
        mock_get.return_value = TestVerifyIsisRouteHasBackup._route_without_backup()
        result = verify_isis_no_backup_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertTrue(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_backup_observed_false_immediately(self, mock_get):
        mock_get.return_value = TestVerifyIsisRouteHasBackup._route_with_backup()
        result = verify_isis_no_backup_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_isis_route")
    def test_exception_path_treated_as_no_backup(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_no_backup_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertTrue(result)


class TestVerifyIsisNoMlaForPrefix(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @patch(f"{VERIFY_MODULE}.get_isis_fast_reroute")
    def test_no_mla_observed_true(self, mock_get):
        mock_get.return_value = {
            "6.6.6.6/32": {
                "levels": {"2": {"reroute-type": "TI_LFA"}}
            }
        }
        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertTrue(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{VERIFY_MODULE}.get_isis_fast_reroute")
    def test_mla_observed_false_immediately(self, mock_get):
        mock_get.return_value = {
            "6.6.6.6/32": {
                "levels": {"2": {"reroute-type": "MICRO_LOOP_AVOIDANCE"}}
            }
        }
        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
        )
        self.assertFalse(result)

    @patch(f"{VERIFY_MODULE}.get_isis_fast_reroute")
    def test_no_entry_for_prefix_true(self, mock_get):
        mock_get.return_value = {}
        result = verify_isis_no_mla_for_prefix(
            self.device, "9.9.9.9/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertTrue(result)

    @patch(f"{VERIFY_MODULE}.get_isis_fast_reroute")
    def test_exception_path_treated_as_no_mla(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_isis_no_mla_for_prefix(
            self.device, "6.6.6.6/32",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertTrue(result)


class TestVerifyIsisMlaFired(unittest.TestCase):
    def setUp(self):
        self.device = _Device()

    @staticmethod
    def _mla(rows):
        return {"status": rows}

    def test_matched_row_found_first_try(self):
        rows = {
            "0-0-MT-0": {
                "algo": 0,
                "mla-state": "ACTIVE",
                "last-event": "LINK-DOWN",
                "near-node": "rtr1",
                "far-node": "rtr2",
                "spf-start-timestamp": "2026-01-01T00:00:01Z",
            }
        }
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, expected_event="LINK-DOWN", algo=0,
                near_node="rtr1", far_node="rtr2",
                max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
            )
        self.assertTrue(result)

    def test_no_matching_algo_exhausts_timeout(self):
        rows = {
            "128-0-MT-0": {
                "algo": 128,
                "mla-state": "ACTIVE",
                "last-event": "LINK-DOWN",
            }
        }
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, algo=0,
                max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
            )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    def test_wrong_state_exhausts_timeout(self):
        rows = {"0-0-MT-0": {"algo": 0, "mla-state": "INACTIVE"}}
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, algo=0,
                max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
            )
        self.assertFalse(result)

    def test_stale_row_filtered_by_since_timestamp(self):
        # Row timestamp is not strictly newer than the baseline -> skipped.
        rows = {
            "0-0-MT-0": {
                "algo": 0,
                "mla-state": "ACTIVE",
                "last-event": "LINK-DOWN",
                "spf-start-timestamp": "2026-01-01T00:00:00Z",
            }
        }
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, algo=0,
                since_timestamp="2026-01-01T00:00:00Z",
                max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
            )
        self.assertFalse(result)

    def test_fresh_row_accepted_with_since_timestamp(self):
        rows = {
            "0-0-MT-0": {
                "algo": 0,
                "mla-state": "ACTIVE",
                "last-event": "LINK-DOWN",
                "spf-start-timestamp": "2026-01-01T00:00:05Z",
            }
        }
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, algo=0,
                since_timestamp="2026-01-01T00:00:00Z",
                max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
            )
        self.assertTrue(result)

    def test_row_missing_timestamp_accepted_with_since_timestamp(self):
        rows = {
            "0-0-MT-0": {
                "algo": 0,
                "mla-state": "ACTIVE",
                "last-event": "LINK-DOWN",
            }
        }
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.return_value = self._mla(rows)
            result = verify_isis_mla_fired(
                self.device, algo=0,
                since_timestamp="2026-01-01T00:00:00Z",
                max_time=FOUND_MAX_TIME, check_interval=FOUND_INTERVAL,
            )
        self.assertTrue(result)

    def test_exception_path(self):
        with patch(f"{VERIFY_MODULE}.get_isis_micro_loop_avoidance") as mock_get:
            mock_get.side_effect = Exception("boom")
            result = verify_isis_mla_fired(
                self.device, algo=0,
                max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
            )
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Machine coverage check.
# ---------------------------------------------------------------------------


class TestVerifyIsisCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    isis/verify.py must be referenced by name somewhere in this test file's
    source. Order-safe under both pytest and `python -m unittest`
    (alphabetical class order), since it scans source text instead of
    relying on side effects from other test classes having already run.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        public_fns = {
            name
            for name in dir(verify_module)
            if name.startswith("verify_")
            and callable(getattr(verify_module, name))
            and getattr(getattr(verify_module, name), "__module__", None)
            == verify_module.__name__
        }
        missing = [n for n in public_fns if n not in source]
        self.assertEqual(
            missing,
            [],
            f"Untested public verify_ functions in isis/verify.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
