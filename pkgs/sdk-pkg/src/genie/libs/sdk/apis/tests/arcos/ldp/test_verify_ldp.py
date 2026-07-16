#!/usr/bin/env python3
"""Unit tests for arcOS LDP verify APIs (full coverage).

Both verify helpers wrap a get_* helper in a genie.utils.timeout.Timeout
poll loop. Timeout(max_time=0) never enters the loop body (iterate()
returns False immediately), so bare max_time=0 negatives would never
exercise the polling logic. Instead we patch the underlying get helper on
the verify module's namespace and drive the loop with a small non-zero
max_time/check_interval, covering both the found-on-first-try and the
exhaust-timeout paths, plus the defensive exception branch.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.ldp.verify import (
    verify_ldp_session_operational,
    verify_ldp_session_not_present,
)

MOD = "genie.libs.sdk.apis.arcos.ldp.verify"


class TestVerifyLdpSessionOperational(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.get_ldp_session_state")
    def test_operational_found_first_try(self, mock_get):
        mock_get.return_value = "Operational"
        result = verify_ldp_session_operational(
            self.device, "1.1.1.1", max_time=1, check_interval=0.5)
        self.assertTrue(result)
        mock_get.assert_called()

    @patch(f"{MOD}.get_ldp_session_state")
    def test_operational_wrong_state_exhausts_timeout(self, mock_get):
        mock_get.return_value = "Initialized"
        result = verify_ldp_session_operational(
            self.device, "1.1.1.1", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)

    @patch(f"{MOD}.get_ldp_session_state")
    def test_operational_none_state_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_ldp_session_operational(
            self.device, "9.9.9.9", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)

    @patch(f"{MOD}.get_ldp_session_state")
    def test_operational_exception_is_caught_and_exhausts(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_ldp_session_operational(
            self.device, "1.1.1.1", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)


class TestVerifyLdpSessionNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.get_ldp_sessions")
    def test_not_present_found_first_try(self, mock_get):
        mock_get.return_value = {}
        result = verify_ldp_session_not_present(
            self.device, "1.1.1.1", max_time=1, check_interval=0.5)
        self.assertTrue(result)
        mock_get.assert_called()

    @patch(f"{MOD}.get_ldp_sessions")
    def test_not_present_still_present_exhausts_timeout(self, mock_get):
        mock_get.return_value = {"1.1.1.1": {"session-state": "Operational"}}
        result = verify_ldp_session_not_present(
            self.device, "1.1.1.1", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)

    @patch(f"{MOD}.get_ldp_sessions")
    def test_not_present_exception_assumes_present_and_exhausts(
            self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_ldp_session_not_present(
            self.device, "1.1.1.1", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)

    @patch(f"{MOD}.get_ldp_sessions")
    def test_not_present_other_peer_present_is_still_absent(self, mock_get):
        # peer_address not a key in the sessions dict -> considered absent
        mock_get.return_value = {"2.2.2.2": {"session-state": "Operational"}}
        result = verify_ldp_session_not_present(
            self.device, "1.1.1.1", max_time=1, check_interval=0.5)
        self.assertTrue(result)


class TestLdpVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    ldp/verify.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.ldp import verify as ldp_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ldp_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ldp_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered LDP verify functions: {missing}")

        print(f"\nLDP verify coverage: {len(names)} total, 0 missing")


if __name__ == "__main__":
    unittest.main()
