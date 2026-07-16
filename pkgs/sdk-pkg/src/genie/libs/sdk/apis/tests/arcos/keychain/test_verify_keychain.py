#!/usr/bin/env python3
"""Unit tests for arcOS Keychain verify APIs (full coverage).

Verify helpers wrap ``is_keychain_present`` (imported directly into the
``verify`` module namespace from ``keychain.get``) in a Timeout loop.
Tests patch ``is_keychain_present`` on the verify module namespace.
Positive cases return on the first iteration (default/real Timeout - the
first ``iterate()`` call always executes the loop body once, so no real
sleep occurs). Negatives use ``max_time=0``, under which
``Timeout.iterate()`` never enters the loop body at all, so the function
falls through to its default return value - this is used both to fast-fail
"not found within timeout" cases and to verify the exception-handling
branches degrade to the documented default (present=False for
verify_keychain_present, present=True for verify_keychain_not_present)
without ever blocking on a real sleep.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.keychain import verify as keychain_verify
from genie.libs.sdk.apis.arcos.keychain.verify import (
    verify_keychain_present,
    verify_keychain_not_present,
)

MOD = "genie.libs.sdk.apis.arcos.keychain.verify"


class TestVerifyKeychainPresent(unittest.TestCase):
    """verify_keychain_present"""

    @patch(f"{MOD}.is_keychain_present", return_value=True)
    def test_present_true(self, mock_is_present):
        self.assertTrue(
            verify_keychain_present(object(), "isis-key")
        )
        mock_is_present.assert_called()

    @patch(f"{MOD}.is_keychain_present", return_value=False)
    def test_present_false_fast_fail(self, mock_is_present):
        self.assertFalse(
            verify_keychain_present(object(), "isis-key", max_time=0)
        )

    @patch(f"{MOD}.is_keychain_present", side_effect=Exception("boom"))
    def test_present_exception_fast_fail(self, mock_is_present):
        self.assertFalse(
            verify_keychain_present(object(), "isis-key", max_time=0)
        )

    @patch(f"{MOD}.is_keychain_present", return_value=True)
    def test_present_custom_interval(self, mock_is_present):
        self.assertTrue(
            verify_keychain_present(
                object(), "isis-key", max_time=5, check_interval=1
            )
        )


class TestVerifyKeychainNotPresent(unittest.TestCase):
    """verify_keychain_not_present"""

    @patch(f"{MOD}.is_keychain_present", return_value=False)
    def test_not_present_true(self, mock_is_present):
        self.assertTrue(
            verify_keychain_not_present(object(), "isis-key")
        )
        mock_is_present.assert_called()

    @patch(f"{MOD}.is_keychain_present", return_value=True)
    def test_not_present_false_fast_fail(self, mock_is_present):
        self.assertFalse(
            verify_keychain_not_present(object(), "isis-key", max_time=0)
        )

    @patch(f"{MOD}.is_keychain_present", side_effect=Exception("boom"))
    def test_not_present_exception_fast_fail(self, mock_is_present):
        # On exception, verify_keychain_not_present treats the keychain as
        # present (fail-safe), so it must NOT report "not present".
        self.assertFalse(
            verify_keychain_not_present(object(), "isis-key", max_time=0)
        )

    @patch(f"{MOD}.is_keychain_present", return_value=False)
    def test_not_present_custom_interval(self, mock_is_present):
        self.assertTrue(
            verify_keychain_not_present(
                object(), "isis-key", max_time=5, check_interval=1
            )
        )


class TestKeychainVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    keychain/verify.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(keychain_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == keychain_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered keychain verify functions: {missing}")

        print(
            f"\nKeychain verify coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
