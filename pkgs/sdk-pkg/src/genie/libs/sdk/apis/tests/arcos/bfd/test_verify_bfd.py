#!/usr/bin/env python3
"""Unit tests for arcOS BFD verify APIs (full coverage).

Verify helpers wrap the bfd.get helpers (imported directly into the verify
module namespace) in a Timeout loop; positive cases return True on the
first iteration, negatives use max_time=0 to fast-fail.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.bfd import verify as bfd_verify
from genie.libs.sdk.apis.arcos.bfd.verify import (
    verify_bfd_session_state,
    verify_bfd_session_up,
    verify_bfd_session_down,
    verify_bfd_profile_present,
    verify_bfd_session_present,
)

MOD = "genie.libs.sdk.apis.arcos.bfd.verify"


class TestVerifyBfdSessionState(unittest.TestCase):
    """verify_bfd_session_state / verify_bfd_session_up / verify_bfd_session_down"""

    @patch(f"{MOD}.get_bfd_session_state", return_value="UP")
    def test_session_state_match(self, mock_get):
        self.assertTrue(
            verify_bfd_session_state(
                object(), "fast-profile", "20", expected_state="UP"
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value="DOWN")
    def test_session_state_mismatch_fast_fail(self, mock_get):
        self.assertFalse(
            verify_bfd_session_state(
                object(), "fast-profile", "20", expected_state="UP",
                max_time=0,
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value=None)
    def test_session_state_none_fast_fail(self, mock_get):
        self.assertFalse(
            verify_bfd_session_state(
                object(), "fast-profile", "20", expected_state="UP",
                max_time=0,
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", side_effect=Exception("boom"))
    def test_session_state_exception_fast_fail(self, mock_get):
        self.assertFalse(
            verify_bfd_session_state(
                object(), "fast-profile", "20", expected_state="UP",
                max_time=0,
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value="up")
    def test_session_state_case_insensitive(self, mock_get):
        self.assertTrue(
            verify_bfd_session_state(
                object(), "fast-profile", "20", expected_state="UP"
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value="UP")
    def test_session_up(self, mock_get):
        self.assertTrue(
            verify_bfd_session_up(object(), "fast-profile", "20")
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value="UP")
    def test_session_down_fast_fail(self, mock_get):
        self.assertFalse(
            verify_bfd_session_down(
                object(), "fast-profile", "20", max_time=0
            )
        )

    @patch(f"{MOD}.get_bfd_session_state", return_value="DOWN")
    def test_session_down(self, mock_get):
        self.assertTrue(
            verify_bfd_session_down(object(), "fast-profile", "20")
        )


class TestVerifyBfdProfilePresent(unittest.TestCase):
    """verify_bfd_profile_present"""

    @patch(f"{MOD}.is_bfd_profile_present", return_value=True)
    def test_profile_present(self, mock_is):
        self.assertTrue(
            verify_bfd_profile_present(object(), "fast-profile")
        )

    @patch(f"{MOD}.is_bfd_profile_present", return_value=False)
    def test_profile_not_present_fast_fail(self, mock_is):
        self.assertFalse(
            verify_bfd_profile_present(
                object(), "no-such-profile", max_time=0
            )
        )

    @patch(f"{MOD}.is_bfd_profile_present", side_effect=Exception("boom"))
    def test_profile_present_exception_fast_fail(self, mock_is):
        self.assertFalse(
            verify_bfd_profile_present(
                object(), "fast-profile", max_time=0
            )
        )


class TestVerifyBfdSessionPresent(unittest.TestCase):
    """verify_bfd_session_present"""

    @patch(f"{MOD}.is_bfd_session_present", return_value=True)
    def test_session_present(self, mock_is):
        self.assertTrue(
            verify_bfd_session_present(object(), "fast-profile", "20")
        )

    @patch(f"{MOD}.is_bfd_session_present", return_value=False)
    def test_session_not_present_fast_fail(self, mock_is):
        self.assertFalse(
            verify_bfd_session_present(
                object(), "fast-profile", "99", max_time=0
            )
        )

    @patch(f"{MOD}.is_bfd_session_present", side_effect=Exception("boom"))
    def test_session_present_exception_fast_fail(self, mock_is):
        self.assertFalse(
            verify_bfd_session_present(
                object(), "fast-profile", "20", max_time=0
            )
        )


class TestBfdVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    bfd/verify.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(bfd_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == bfd_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered BFD verify functions: {missing}")

        print(
            f"\nBFD verify coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
