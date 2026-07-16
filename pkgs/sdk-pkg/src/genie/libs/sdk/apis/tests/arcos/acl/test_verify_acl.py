#!/usr/bin/env python3
"""Unit tests for arcOS ACL verify APIs (full coverage).

verify.py wraps ``is_acl_set_present`` (imported into the verify module's
own namespace) in a ``genie.utils.timeout.Timeout`` poll loop. Two pitfalls
to avoid here:

* ``Timeout(max_time=0, ...)`` never enters the poll loop at all (confirmed
  empirically against the compiled Timeout implementation), so a "fast
  fail" test built on max_time=0 never actually calls the body of the loop
  -- it just returns the pre-loop default. That silently skips the
  present/not-present + exception-handling branches inside the loop.
* Using a real non-zero max_time works but burns wall-clock time sleeping
  between polls.

To get deterministic, fast, and *real* coverage of the loop body (both the
happy path and the exception-handling branch), this file patches
``is_acl_set_present`` directly on the verify module's namespace (so no
real device/parser is needed) and patches ``Timeout`` on the verify
module's namespace with a fake that iterates a fixed small number of times
with no real sleep. Positive-path tests don't need the fake Timeout since
they return True on the very first iteration.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.acl.verify import (
    verify_acl_set_present,
    verify_acl_set_not_present,
)

MOD = "genie.libs.sdk.apis.arcos.acl.verify"


class _FakeTimeout:
    """Timeout stand-in: no real sleep, iterates a fixed number of times."""

    _ITERATIONS = 2

    def __init__(self, max_time, check_interval):
        self._left = self._ITERATIONS

    def iterate(self):
        if self._left > 0:
            self._left -= 1
            return True
        return False

    def sleep(self):
        pass


class TestVerifyAclSetPresent(unittest.TestCase):
    """verify_acl_set_present"""

    @patch(f"{MOD}.is_acl_set_present", return_value=True)
    def test_present_true_first_iteration(self, mock_present):
        self.assertTrue(
            verify_acl_set_present(object(), "v4-acl", "ACL_IPV4"))
        mock_present.assert_called_once()

    @patch(f"{MOD}.Timeout", _FakeTimeout)
    @patch(f"{MOD}.is_acl_set_present", return_value=False)
    def test_present_false_after_polling(self, mock_present):
        """ACL never shows up -- loop polls _ITERATIONS times then times
        out, exercising the loop body's False branch and the final
        `return False`."""
        self.assertFalse(
            verify_acl_set_present(object(), "v4-acl", "ACL_IPV4"))
        self.assertEqual(mock_present.call_count, _FakeTimeout._ITERATIONS)

    @patch(f"{MOD}.Timeout", _FakeTimeout)
    @patch(f"{MOD}.is_acl_set_present", side_effect=RuntimeError("device unreachable"))
    def test_present_exception_handled_as_absent(self, mock_present):
        """is_acl_set_present raising is caught, treated as not-present,
        and polling continues until the fake timeout expires."""
        self.assertFalse(
            verify_acl_set_present(object(), "v4-acl", "ACL_IPV4"))
        self.assertEqual(mock_present.call_count, _FakeTimeout._ITERATIONS)


class TestVerifyAclSetNotPresent(unittest.TestCase):
    """verify_acl_set_not_present"""

    @patch(f"{MOD}.is_acl_set_present", return_value=False)
    def test_absent_true_first_iteration(self, mock_present):
        self.assertTrue(
            verify_acl_set_not_present(object(), "v4-acl", "ACL_IPV4"))
        mock_present.assert_called_once()

    @patch(f"{MOD}.Timeout", _FakeTimeout)
    @patch(f"{MOD}.is_acl_set_present", return_value=True)
    def test_absent_false_after_polling(self, mock_present):
        """ACL stubbornly stays present -- loop polls until the fake
        timeout expires and returns False."""
        self.assertFalse(
            verify_acl_set_not_present(object(), "v4-acl", "ACL_IPV4"))
        self.assertEqual(mock_present.call_count, _FakeTimeout._ITERATIONS)

    @patch(f"{MOD}.Timeout", _FakeTimeout)
    @patch(f"{MOD}.is_acl_set_present", side_effect=RuntimeError("device unreachable"))
    def test_absent_exception_handled_as_present(self, mock_present):
        """is_acl_set_present raising is caught, conservatively treated as
        present (i.e. NOT confirmed absent), and polling continues until
        the fake timeout expires."""
        self.assertFalse(
            verify_acl_set_not_present(object(), "v4-acl", "ACL_IPV4"))
        self.assertEqual(mock_present.call_count, _FakeTimeout._ITERATIONS)


class TestAclVerifyFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    acl/verify.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.acl import verify as acl_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(acl_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == acl_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered ACL verify functions: {missing}")

        print(f"\nACL verify coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
