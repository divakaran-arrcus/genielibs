#!/usr/bin/env python3
"""Unit tests for arcOS VRRP verify APIs (full coverage).

Each verify_* helper wraps a get/is helper (imported directly into the
verify module's namespace) in a Timeout loop. Positive cases return True on
the first iteration. Negative cases patch the underlying helper on the verify
module namespace and use a small non-zero max_time/check_interval (e.g.
0.05/0.02) so the loop body -- including the try/except around the
underlying call -- actually runs before the timeout is exhausted; a bare
max_time=0 never enters the loop at all and would only exercise the final
`return False`.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.vrrp.verify import (
    verify_vrrp_group_present,
    verify_vrrp_group_not_present,
    verify_vrrp_group_master,
)

MOD = "genie.libs.sdk.apis.arcos.vrrp.verify"


import inspect
import genie.libs.sdk.apis.arcos.vrrp.verify as verify_module
class TestVerifyVrrpGroupPresent(unittest.TestCase):
    @patch(f"{MOD}.is_vrrp_group_present")
    def test_present_true_immediate(self, mock_present):
        mock_present.return_value = True
        self.assertTrue(
            verify_vrrp_group_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
            )
        )

    @patch(f"{MOD}.is_vrrp_group_present")
    def test_present_false_exhausts_timeout(self, mock_present):
        mock_present.return_value = False
        self.assertFalse(
            verify_vrrp_group_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_present.assert_called()

    @patch(f"{MOD}.is_vrrp_group_present")
    def test_present_exception_handled_then_times_out(self, mock_present):
        """is_vrrp_group_present raising is caught and treated as absent."""
        mock_present.side_effect = Exception("boom")
        self.assertFalse(
            verify_vrrp_group_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )


class TestVerifyVrrpGroupNotPresent(unittest.TestCase):
    @patch(f"{MOD}.is_vrrp_group_present")
    def test_not_present_true_immediate(self, mock_present):
        mock_present.return_value = False
        self.assertTrue(
            verify_vrrp_group_not_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
            )
        )

    @patch(f"{MOD}.is_vrrp_group_present")
    def test_not_present_false_exhausts_timeout(self, mock_present):
        """Group still present -- loop exhausts, returns False."""
        mock_present.return_value = True
        self.assertFalse(
            verify_vrrp_group_not_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_present.assert_called()

    @patch(f"{MOD}.is_vrrp_group_present")
    def test_not_present_exception_treated_as_present(self, mock_present):
        """Exception sets present=True -- loop continues then exhausts."""
        mock_present.side_effect = Exception("boom")
        self.assertFalse(
            verify_vrrp_group_not_present(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )


class TestVerifyVrrpGroupMaster(unittest.TestCase):
    @patch(f"{MOD}.get_vrrp_group_mode")
    def test_master_true_immediate(self, mock_mode):
        mock_mode.return_value = "MASTER"
        self.assertTrue(
            verify_vrrp_group_master(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
            )
        )

    @patch(f"{MOD}.get_vrrp_group_mode")
    def test_master_false_backup_exhausts_timeout(self, mock_mode):
        mock_mode.return_value = "BACKUP"
        self.assertFalse(
            verify_vrrp_group_master(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_mode.assert_called()

    @patch(f"{MOD}.get_vrrp_group_mode")
    def test_master_exception_handled_then_times_out(self, mock_mode):
        """get_vrrp_group_mode raising is caught, mode falls back to None."""
        mock_mode.side_effect = Exception("boom")
        self.assertFalse(
            verify_vrrp_group_master(
                None, "swp10", 0, "ipv4", "172.16.1.1", 10,
                max_time=0.05, check_interval=0.02,
            )
        )




class TestVrrpVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify function in
    vrrp/verify.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(verify_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == verify_module.__name__
            and (name.startswith("verify_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered vrrp verify functions: {missing}")
if __name__ == "__main__":
    unittest.main()
