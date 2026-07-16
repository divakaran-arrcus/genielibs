#!/usr/bin/env python3
"""Unit tests for arcOS LAG (LACP/Bond) verify APIs (full coverage).

Verify helpers wrap the get helpers (``genie.libs.sdk.apis.arcos.lag.get``)
in a Timeout loop; positive cases return on the first iteration, negatives
use max_time=0 to fast-fail without sleeping.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.lag.verify import (
    verify_lag_member_in_sync,
    verify_lag_member_collecting_distributing,
    verify_lag_bond_present,
)

MOD = "genie.libs.sdk.apis.arcos.lag.verify"


class _DummyDevice:
    name = "rtr1"


class TestVerifyLagMemberInSync(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_lag_member_sync_state")
    def test_in_sync_true(self, mock_get):
        mock_get.return_value = "IN_SYNC"
        self.assertTrue(
            verify_lag_member_in_sync(self.device, "bond10", "swp10")
        )

    @patch(f"{MOD}.get_lag_member_sync_state")
    def test_in_sync_false_fast_fail(self, mock_get):
        mock_get.return_value = "OUT_SYNC"
        self.assertFalse(
            verify_lag_member_in_sync(
                self.device, "bond10", "swp10", max_time=0
            )
        )

    @patch(f"{MOD}.get_lag_member_sync_state")
    def test_in_sync_exception_fast_fail(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        self.assertFalse(
            verify_lag_member_in_sync(
                self.device, "bond10", "swp10", max_time=0
            )
        )


class TestVerifyLagMemberCollectingDistributing(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_lag_members")
    def test_collecting_distributing_true(self, mock_get):
        mock_get.return_value = {
            "swp10": {"collecting": True, "distributing": True}
        }
        self.assertTrue(
            verify_lag_member_collecting_distributing(
                self.device, "bond10", "swp10"
            )
        )

    @patch(f"{MOD}.get_lag_members")
    def test_collecting_distributing_false_fast_fail(self, mock_get):
        mock_get.return_value = {
            "swp10": {"collecting": True, "distributing": False}
        }
        self.assertFalse(
            verify_lag_member_collecting_distributing(
                self.device, "bond10", "swp10", max_time=0
            )
        )

    @patch(f"{MOD}.get_lag_members")
    def test_collecting_distributing_missing_member_fast_fail(
        self, mock_get
    ):
        mock_get.return_value = {}
        self.assertFalse(
            verify_lag_member_collecting_distributing(
                self.device, "bond10", "swp99", max_time=0
            )
        )

    @patch(f"{MOD}.get_lag_members")
    def test_collecting_distributing_exception_fast_fail(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        self.assertFalse(
            verify_lag_member_collecting_distributing(
                self.device, "bond10", "swp10", max_time=0
            )
        )


class TestVerifyLagBondPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_lag_bond")
    def test_bond_present_true(self, mock_get):
        mock_get.return_value = {"name": "bond10"}
        self.assertTrue(
            verify_lag_bond_present(self.device, "bond10")
        )

    @patch(f"{MOD}.get_lag_bond")
    def test_bond_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_lag_bond_present(self.device, "bond10", max_time=0)
        )

    @patch(f"{MOD}.get_lag_bond")
    def test_bond_present_exception_fast_fail(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        self.assertFalse(
            verify_lag_bond_present(self.device, "bond10", max_time=0)
        )


if __name__ == "__main__":
    unittest.main()
