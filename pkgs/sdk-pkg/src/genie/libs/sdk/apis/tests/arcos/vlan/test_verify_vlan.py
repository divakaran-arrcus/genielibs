#!/usr/bin/env python3
"""Unit tests for arcOS VLAN verify APIs (full coverage).

Verify helpers wrap genie.libs.sdk.apis.arcos.vlan.get.is_vlan_present /
get_vlan_members in a Timeout loop. Since those get helpers are imported
directly into the verify module's namespace, tests patch them there.
Positive cases return on the first iteration; negatives use max_time=0
to fast-fail. A machine coverage check (test_zzz_all_functions_covered)
asserts every public verify_* function in the module was exercised.
"""

import inspect
import unittest
from unittest.mock import patch

import genie.libs.sdk.apis.arcos.vlan.verify as verify_module
from genie.libs.sdk.apis.arcos.vlan.verify import (
    verify_vlan_present,
    verify_vlan_not_present,
    verify_vlan_member_present,
)

MOD = "genie.libs.sdk.apis.arcos.vlan.verify"

_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


verify_vlan_present = _track("verify_vlan_present", verify_vlan_present)
verify_vlan_not_present = _track("verify_vlan_not_present", verify_vlan_not_present)
verify_vlan_member_present = _track(
    "verify_vlan_member_present", verify_vlan_member_present
)


class TestVerifyVlanPresent(unittest.TestCase):
    @patch(f"{MOD}.is_vlan_present")
    def test_present_true(self, mock_present):
        mock_present.return_value = True
        self.assertTrue(verify_vlan_present(None, 100, max_time=1, check_interval=1))

    @patch(f"{MOD}.is_vlan_present")
    def test_present_false_fast_fail(self, mock_present):
        mock_present.return_value = False
        self.assertFalse(verify_vlan_present(None, 100, max_time=0))

    @patch(f"{MOD}.is_vlan_present")
    def test_present_raises_treated_as_absent(self, mock_present):
        mock_present.side_effect = Exception("boom")
        self.assertFalse(verify_vlan_present(None, 100, max_time=0))

    @patch(f"{MOD}.is_vlan_present")
    def test_present_retries_then_succeeds(self, mock_present):
        """First poll misses, loop sleeps and retries, second poll hits."""
        mock_present.side_effect = [False, True]
        self.assertTrue(
            verify_vlan_present(None, 100, max_time=2, check_interval=0)
        )


class TestVerifyVlanNotPresent(unittest.TestCase):
    @patch(f"{MOD}.is_vlan_present")
    def test_not_present_true(self, mock_present):
        mock_present.return_value = False
        self.assertTrue(
            verify_vlan_not_present(None, 100, max_time=1, check_interval=1)
        )

    @patch(f"{MOD}.is_vlan_present")
    def test_not_present_false_fast_fail(self, mock_present):
        mock_present.return_value = True
        self.assertFalse(verify_vlan_not_present(None, 100, max_time=0))

    @patch(f"{MOD}.is_vlan_present")
    def test_not_present_raises_treated_as_present(self, mock_present):
        mock_present.side_effect = Exception("boom")
        self.assertFalse(verify_vlan_not_present(None, 100, max_time=0))

    @patch(f"{MOD}.is_vlan_present")
    def test_not_present_retries_then_succeeds(self, mock_present):
        """First poll still present, loop sleeps and retries, second poll clear."""
        mock_present.side_effect = [True, False]
        self.assertTrue(
            verify_vlan_not_present(None, 100, max_time=2, check_interval=0)
        )


class TestVerifyVlanMemberPresent(unittest.TestCase):
    @patch(f"{MOD}.get_vlan_members")
    def test_member_present_true(self, mock_members):
        mock_members.return_value = ["swp1", "swp2"]
        self.assertTrue(
            verify_vlan_member_present(
                None, 100, "swp1", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.get_vlan_members")
    def test_member_present_false_fast_fail(self, mock_members):
        mock_members.return_value = ["swp2"]
        self.assertFalse(
            verify_vlan_member_present(None, 100, "swp1", max_time=0)
        )

    @patch(f"{MOD}.get_vlan_members")
    def test_member_present_raises_treated_as_absent(self, mock_members):
        mock_members.side_effect = Exception("boom")
        self.assertFalse(
            verify_vlan_member_present(None, 100, "swp1", max_time=0)
        )

    @patch(f"{MOD}.get_vlan_members")
    def test_member_present_retries_then_succeeds(self, mock_members):
        """First poll misses, loop sleeps and retries, second poll hits."""
        mock_members.side_effect = [["swp2"], ["swp1", "swp2"]]
        self.assertTrue(
            verify_vlan_member_present(
                None, 100, "swp1", max_time=2, check_interval=0
            )
        )


class TestVerifyVlanCoverage(unittest.TestCase):
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
            f"Untested public functions in vlan/verify.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
