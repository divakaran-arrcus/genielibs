#!/usr/bin/env python3
"""Unit tests for arcOS RIB verify APIs (full coverage).

Verify helpers poll a get/is helper (imported by name into
``rib/verify.py``'s module namespace) inside a ``genie.utils.timeout.Timeout``
loop. Empirically, ``Timeout(max_time=0, ...).iterate()`` returns ``False``
immediately — the loop body never runs at all — so a naive "positive uses
default max_time, negative uses max_time=0" split (as used for e.g. the
Interface verify tests) would silently skip the loop body, the
``timeout.sleep()`` call, and the "keep polling" line on the negative path.

To get real branch/line coverage here:
  * "found-first-try" cases patch the underlying helper to return the
    passing value immediately, with a small non-zero ``max_time`` — the loop
    body runs exactly once and returns True on the first check.
  * "exhaust-timeout" cases patch the underlying helper to always return the
    failing value, with ``max_time=0.05`` / ``check_interval=0.02`` — real
    time, but tiny; this reliably drives 3-4 loop iterations (confirmed via
    manual Timeout probing), exercising ``timeout.sleep()`` and the
    loop-continues path before falling through to ``return False``.
"""

import importlib
import io
import sys
import unittest
from unittest.mock import patch

import coverage

from genie.libs.sdk.apis.arcos.rib import verify as rib_verify

VERIFY_MODULE = "genie.libs.sdk.apis.arcos.rib.verify"

# Small, real, non-zero timings so the Timeout loop body actually executes
# (Timeout(max_time=0, ...) never enters the loop at all).
FOUND_MAX_TIME = 1
FOUND_INTERVAL = 0.5
EXHAUST_MAX_TIME = 0.05
EXHAUST_INTERVAL = 0.02


class _DummyDevice:
    """Verify APIs only forward ``device`` to the (mocked) get helper."""


class TestVerifyRib(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    # -- verify_route_in_rib ----------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_in_rib_found_first_try(self, mock_is):
        mock_is.return_value = True
        result = rib_verify.verify_route_in_rib(
            self.device,
            "5.5.5.5/32",
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)
        mock_is.assert_called()

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_in_rib_exhausts_timeout(self, mock_is):
        mock_is.return_value = False
        result = rib_verify.verify_route_in_rib(
            self.device,
            "9.9.9.9/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_in_rib_exception_path(self, mock_is):
        # is_route_in_rib raising is caught internally and treated as
        # "not present" for this iteration.
        mock_is.side_effect = Exception("boom")
        result = rib_verify.verify_route_in_rib(
            self.device,
            "5.5.5.5/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    # -- verify_route_not_in_rib -------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_not_in_rib_found_first_try(self, mock_is):
        mock_is.return_value = False
        result = rib_verify.verify_route_not_in_rib(
            self.device,
            "9.9.9.9/32",
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_not_in_rib_exhausts_timeout(self, mock_is):
        mock_is.return_value = True
        result = rib_verify.verify_route_not_in_rib(
            self.device,
            "5.5.5.5/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.is_route_in_rib")
    def test_verify_route_not_in_rib_exception_path(self, mock_is):
        mock_is.side_effect = Exception("boom")
        result = rib_verify.verify_route_not_in_rib(
            self.device,
            "5.5.5.5/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        # Exception -> present=True -> "not present" never satisfied.
        self.assertFalse(result)

    # -- verify_route_protocol ----------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_found_first_try(self, mock_get):
        mock_get.return_value = "isis"
        result = rib_verify.verify_route_protocol(
            self.device,
            "5.5.5.5/32",
            expected="ISIS",
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_mismatch_exhausts_timeout(self, mock_get):
        mock_get.return_value = "BGP"
        result = rib_verify.verify_route_protocol(
            self.device,
            "5.5.5.5/32",
            expected="ISIS",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_none_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = rib_verify.verify_route_protocol(
            self.device,
            "9.9.9.9/32",
            expected="ISIS",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_route_best_protocol")
    def test_verify_route_protocol_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = rib_verify.verify_route_protocol(
            self.device,
            "5.5.5.5/32",
            expected="ISIS",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    # -- verify_label_in_rib -------------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_label_entry")
    def test_verify_label_in_rib_found_first_try(self, mock_get):
        mock_get.return_value = {"label": 10005, "protocol": "ISIS"}
        result = rib_verify.verify_label_in_rib(
            self.device,
            10005,
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_label_entry")
    def test_verify_label_in_rib_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = rib_verify.verify_label_in_rib(
            self.device,
            99999,
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_label_entry")
    def test_verify_label_in_rib_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = rib_verify.verify_label_in_rib(
            self.device,
            10005,
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)

    # -- verify_rib_has_backup ----------------------------------------------

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_verify_rib_has_backup_found_first_try(self, mock_get):
        mock_get.return_value = [
            {"interface": "swp2", "flags": "ATTACH,BACKUP,SR"}
        ]
        result = rib_verify.verify_rib_has_backup(
            self.device,
            "5.5.5.5/32",
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_verify_rib_has_backup_egress_match_found_first_try(self, mock_get):
        mock_get.return_value = [
            {"interface": "swp2", "flags": "ATTACH,BACKUP,SR"}
        ]
        result = rib_verify.verify_rib_has_backup(
            self.device,
            "5.5.5.5/32",
            expected_backup_egress="swp2",
            max_time=FOUND_MAX_TIME,
            check_interval=FOUND_INTERVAL,
        )
        self.assertTrue(result)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_verify_rib_has_backup_egress_mismatch_exhausts_timeout(
        self, mock_get
    ):
        mock_get.return_value = [
            {"interface": "swp2", "flags": "ATTACH,BACKUP,SR"}
        ]
        result = rib_verify.verify_rib_has_backup(
            self.device,
            "5.5.5.5/32",
            expected_backup_egress="swp9",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_verify_rib_has_backup_no_backups_exhausts_timeout(self, mock_get):
        mock_get.return_value = []
        result = rib_verify.verify_rib_has_backup(
            self.device,
            "9.9.9.9/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch("genie.libs.sdk.apis.arcos.rib.verify.get_rib_backup_nexthops")
    def test_verify_rib_has_backup_exception_path(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = rib_verify.verify_rib_has_backup(
            self.device,
            "5.5.5.5/32",
            max_time=EXHAUST_MAX_TIME,
            check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Embedded machine coverage check
# ---------------------------------------------------------------------------

_COVERAGE_TEST_CLASSES = (TestVerifyRib,)


class TestVerifyRibFullCoverage(unittest.TestCase):
    def test_full_coverage(self):
        global rib_verify

        sys.modules.pop(VERIFY_MODULE, None)
        cov = coverage.Coverage(source=[VERIFY_MODULE])
        cov.start()
        try:
            rib_verify = importlib.import_module(VERIFY_MODULE)

            loader = unittest.defaultTestLoader
            suite = unittest.TestSuite()
            for cls in _COVERAGE_TEST_CLASSES:
                suite.addTests(loader.loadTestsFromTestCase(cls))

            result = unittest.TextTestRunner(
                verbosity=0, stream=io.StringIO()
            ).run(suite)
        finally:
            cov.stop()
            cov.save()

        self.assertTrue(
            result.wasSuccessful(),
            "rib/verify.py functional test suite failed during coverage re-run",
        )

        report_buf = io.StringIO()
        total = cov.report(show_missing=True, file=report_buf)
        self.assertGreaterEqual(
            total,
            100.0,
            f"rib/verify.py line coverage only {total:.1f}%\n{report_buf.getvalue()}",
        )


if __name__ == "__main__":
    unittest.main()
