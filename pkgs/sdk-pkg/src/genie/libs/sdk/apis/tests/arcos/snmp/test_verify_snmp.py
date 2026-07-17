#!/usr/bin/env python3
"""Unit tests for arcOS SNMP verify APIs (full coverage).

Verify helpers wrap genie.libs.sdk.apis.arcos.snmp.get.is_snmp_server_enabled
in a genie.utils.timeout.Timeout loop. That get helper is imported directly
into the verify module's namespace, so tests patch it there.

IMPORTANT: genie.utils.timeout.Timeout(max_time=0) never enters the poll
loop body at all (confirmed empirically: Timeout(0, N).iterate() is False
on the very first call), so max_time=0 only exercises the "return False
without ever calling the underlying helper" branch. To actually exercise
the loop body (the try/except around is_snmp_server_enabled and the
timeout.sleep() retry path) tests use a small non-zero max_time/check_interval
(e.g. 0.05/0.02) so a handful of iterations execute quickly.

A machine coverage check (test_zzz_all_functions_covered) asserts every
public verify_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import patch

import genie.libs.sdk.apis.arcos.snmp.verify as verify_module
from genie.libs.sdk.apis.arcos.snmp.verify import (
    verify_snmp_server_enabled,
    verify_snmp_server_disabled,
)

MOD = "genie.libs.sdk.apis.arcos.snmp.verify"

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


verify_snmp_server_enabled = _track(
    "verify_snmp_server_enabled", verify_snmp_server_enabled
)
verify_snmp_server_disabled = _track(
    "verify_snmp_server_disabled", verify_snmp_server_disabled
)


class TestVerifySnmpServerEnabled(unittest.TestCase):
    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_found_first_try(self, mock_enabled):
        """First poll hits immediately."""
        mock_enabled.return_value = True
        self.assertTrue(
            verify_snmp_server_enabled(None, max_time=1, check_interval=1)
        )
        mock_enabled.assert_called()

    def test_max_time_zero_never_polls(self):
        """Timeout(0, N) never enters the loop body -> returns False without
        ever calling is_snmp_server_enabled."""
        with patch(f"{MOD}.is_snmp_server_enabled") as mock_enabled:
            self.assertFalse(verify_snmp_server_enabled(None, max_time=0))
            mock_enabled.assert_not_called()

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_exhausts_timeout_returns_false(self, mock_enabled):
        """Underlying check never succeeds; small max_time/check_interval
        lets the loop run a few real iterations before giving up."""
        mock_enabled.return_value = False
        self.assertFalse(
            verify_snmp_server_enabled(None, max_time=0.05, check_interval=0.02)
        )
        self.assertGreaterEqual(mock_enabled.call_count, 1)

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_retries_then_succeeds(self, mock_enabled):
        """First poll(s) miss, loop sleeps and retries, later poll hits."""
        mock_enabled.side_effect = [False, False, True]
        self.assertTrue(
            verify_snmp_server_enabled(None, max_time=1, check_interval=0)
        )

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_exception_treated_as_not_enabled(self, mock_enabled):
        """Exception from is_snmp_server_enabled is caught/logged and the
        loop keeps polling until it exhausts the timeout."""
        mock_enabled.side_effect = Exception("boom")
        self.assertFalse(
            verify_snmp_server_enabled(None, max_time=0.05, check_interval=0.02)
        )


class TestVerifySnmpServerDisabled(unittest.TestCase):
    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_found_first_try(self, mock_enabled):
        """First poll hits immediately (server already disabled)."""
        mock_enabled.return_value = False
        self.assertTrue(
            verify_snmp_server_disabled(None, max_time=1, check_interval=1)
        )
        mock_enabled.assert_called()

    def test_max_time_zero_never_polls(self):
        with patch(f"{MOD}.is_snmp_server_enabled") as mock_enabled:
            self.assertFalse(verify_snmp_server_disabled(None, max_time=0))
            mock_enabled.assert_not_called()

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_exhausts_timeout_returns_false(self, mock_enabled):
        """Server stays enabled; small max_time/check_interval lets the
        loop run a few real iterations before giving up."""
        mock_enabled.return_value = True
        self.assertFalse(
            verify_snmp_server_disabled(None, max_time=0.05, check_interval=0.02)
        )
        self.assertGreaterEqual(mock_enabled.call_count, 1)

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_retries_then_succeeds(self, mock_enabled):
        """First poll(s) still enabled, loop sleeps and retries, later poll clear."""
        mock_enabled.side_effect = [True, True, False]
        self.assertTrue(
            verify_snmp_server_disabled(None, max_time=1, check_interval=0)
        )

    @patch(f"{MOD}.is_snmp_server_enabled")
    def test_exception_treated_as_enabled(self, mock_enabled):
        """Exception from is_snmp_server_enabled is caught/logged and the
        loop keeps polling until it exhausts the timeout."""
        mock_enabled.side_effect = Exception("boom")
        self.assertFalse(
            verify_snmp_server_disabled(None, max_time=0.05, check_interval=0.02)
        )


class TestVerifySnmpCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in verify.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(verify_module, inspect.isfunction)
            if obj.__module__ == verify_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in snmp/verify.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
