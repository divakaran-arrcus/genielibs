#!/usr/bin/env python3
"""Unit tests for arcOS FIB verify APIs (full coverage).

All four verify helpers wrap a get_*/is_* helper in a
``genie.utils.timeout.Timeout`` poll loop. ``Timeout(max_time=0)`` never
enters the loop body (``iterate()`` returns False immediately), so a bare
``max_time=0`` negative would never actually exercise the polling logic or
the defensive exception branch. Instead we patch the underlying
get/is helper on the verify module's namespace and drive the loop with a
small non-zero ``max_time``/``check_interval`` (0.05/0.02), covering both
the found-on-first-try and the exhaust-timeout paths, plus the defensive
``except Exception`` branch in each verify function.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.fib.verify import (
    verify_prefix_in_fib,
    verify_prefix_not_in_fib,
    verify_nexthop_in_fib,
    verify_label_in_fib,
)

MOD = "genie.libs.sdk.apis.arcos.fib.verify"


class TestVerifyPrefixInFib(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_found_first_try(self, mock_is):
        mock_is.return_value = True
        result = verify_prefix_in_fib(
            self.device, prefix="10.0.0.0/24", max_time=1, check_interval=0.5)
        self.assertTrue(result)
        mock_is.assert_called()

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_never_found_exhausts_timeout(self, mock_is):
        mock_is.return_value = False
        result = verify_prefix_in_fib(
            self.device, prefix="99.99.99.99/32", max_time=0.05,
            check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 1)

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_exception_is_caught_and_exhausts(self, mock_is):
        mock_is.side_effect = Exception("boom")
        result = verify_prefix_in_fib(
            self.device, prefix="10.0.0.0/24", max_time=0.05,
            check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 1)


class TestVerifyPrefixNotInFib(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_absent_first_try(self, mock_is):
        mock_is.return_value = False
        result = verify_prefix_not_in_fib(
            self.device, prefix="99.99.99.99/32", max_time=1,
            check_interval=0.5)
        self.assertTrue(result)
        mock_is.assert_called()

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_still_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = True
        result = verify_prefix_not_in_fib(
            self.device, prefix="10.0.0.0/24", max_time=0.05,
            check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 1)

    @patch(f"{MOD}.is_prefix_in_fib")
    def test_exception_assumes_present_and_exhausts(self, mock_is):
        # verify_prefix_not_in_fib treats an exception as "present" (safe
        # default), so it must exhaust the timeout and return False.
        mock_is.side_effect = Exception("boom")
        result = verify_prefix_not_in_fib(
            self.device, prefix="10.0.0.0/24", max_time=0.05,
            check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_is.call_count, 1)


class TestVerifyNexthopInFib(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.get_fib_nexthop_entry")
    def test_found_first_try(self, mock_get):
        mock_get.return_value = {"index": 643, "level": 1}
        result = verify_nexthop_in_fib(
            self.device, index="643", max_time=1, check_interval=0.5)
        self.assertTrue(result)
        mock_get.assert_called()

    @patch(f"{MOD}.get_fib_nexthop_entry")
    def test_missing_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_nexthop_in_fib(
            self.device, index="99999", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)

    @patch(f"{MOD}.get_fib_nexthop_entry")
    def test_exception_is_caught_and_exhausts(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_nexthop_in_fib(
            self.device, index="643", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)


class TestVerifyLabelInFib(unittest.TestCase):
    def setUp(self):
        self.device = object()

    @patch(f"{MOD}.get_fib_label_entry")
    def test_found_first_try(self, mock_get):
        mock_get.return_value = {"local-label": 10005, "next-hop-id": 643}
        result = verify_label_in_fib(
            self.device, label="10005", max_time=1, check_interval=0.5)
        self.assertTrue(result)
        mock_get.assert_called()

    @patch(f"{MOD}.get_fib_label_entry")
    def test_missing_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_label_in_fib(
            self.device, label="99999", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)

    @patch(f"{MOD}.get_fib_label_entry")
    def test_exception_is_caught_and_exhausts(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_label_in_fib(
            self.device, label="10005", max_time=0.05, check_interval=0.02)
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 1)


# ---------------------------------------------------------------------------
# Machine-checked coverage
# ---------------------------------------------------------------------------


class TestFibVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    fib/verify.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.fib import verify as fib_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(fib_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == fib_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered FIB verify functions: {missing}")

        print(f"\nFIB verify coverage: {len(names)} total, 0 missing")


if __name__ == "__main__":
    unittest.main()
