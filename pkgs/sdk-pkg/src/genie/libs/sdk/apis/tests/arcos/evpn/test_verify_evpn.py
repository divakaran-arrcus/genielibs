#!/usr/bin/env python3
"""Unit tests for arcOS EVPN verify APIs (full coverage).

Both verify_* helpers wrap a get_evpn_* helper (imported directly into the
verify module namespace) in a ``genie.utils.timeout.Timeout`` loop.
``Timeout(max_time=0, ...)`` never enters the poll loop at all (``iterate()``
returns False on the very first call), so a naive ``max_time=0`` negative
test never actually exercises the loop body (mismatch branch, exception
branch, sleep()). To get real branch coverage this file patches the
underlying get_evpn_* helper on the verify module's namespace and drives
the *real* Timeout with a small non-zero max_time/check_interval
(0.05s / 0.02s) so the loop runs a few real iterations before exhausting.
Found-first-try cases use the (large) default max_time since they return
True on the first iteration and never sleep.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.evpn import verify as evpn_verify
from genie.libs.sdk.apis.arcos.evpn.verify import (
    verify_evpn_anycast_gateway_mac,
    verify_evpn_df_election_time,
)

MOD = "genie.libs.sdk.apis.arcos.evpn.verify"


class TestVerifyEvpnAnycastGatewayMac(unittest.TestCase):
    """verify_evpn_anycast_gateway_mac"""

    @patch(f"{MOD}.get_evpn_anycast_gateway_mac", return_value="AA:BB:CC:01:02:03")
    def test_match_case_insensitive_first_try(self, mock_get):
        self.assertTrue(
            verify_evpn_anycast_gateway_mac(
                object(), "aa:bb:cc:01:02:03"
            )
        )
        mock_get.assert_called_once()

    @patch(f"{MOD}.get_evpn_anycast_gateway_mac", return_value="ff:ff:ff:ff:ff:ff")
    def test_mismatch_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_anycast_gateway_mac(
                object(), "aa:bb:cc:01:02:03",
                max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_anycast_gateway_mac", return_value=None)
    def test_none_value_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_anycast_gateway_mac(
                object(), "aa:bb:cc:01:02:03",
                max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_anycast_gateway_mac", side_effect=Exception("boom"))
    def test_exception_is_caught_and_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_anycast_gateway_mac(
                object(), "aa:bb:cc:01:02:03",
                max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_anycast_gateway_mac", return_value="ff:ff:ff:ff:ff:ff")
    def test_max_time_zero_never_enters_loop(self, mock_get):
        self.assertFalse(
            verify_evpn_anycast_gateway_mac(
                object(), "aa:bb:cc:01:02:03", max_time=0,
            )
        )
        mock_get.assert_not_called()


class TestVerifyEvpnDfElectionTime(unittest.TestCase):
    """verify_evpn_df_election_time"""

    @patch(f"{MOD}.get_evpn_df_election_time", return_value=15)
    def test_match_int_first_try(self, mock_get):
        self.assertTrue(
            verify_evpn_df_election_time(object(), 15)
        )
        mock_get.assert_called_once()

    @patch(f"{MOD}.get_evpn_df_election_time", return_value="15")
    def test_match_string_int_coercion_first_try(self, mock_get):
        self.assertTrue(
            verify_evpn_df_election_time(object(), 15)
        )

    @patch(f"{MOD}.get_evpn_df_election_time", return_value=99)
    def test_mismatch_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_df_election_time(
                object(), 15, max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_df_election_time", return_value=None)
    def test_none_value_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_df_election_time(
                object(), 15, max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_df_election_time", return_value="not-a-number")
    def test_non_numeric_value_exhausts_timeout(self, mock_get):
        """Exercises the ValueError/TypeError `pass` branch on int() cast."""
        self.assertFalse(
            verify_evpn_df_election_time(
                object(), 15, max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_df_election_time", side_effect=Exception("boom"))
    def test_exception_is_caught_and_exhausts_timeout(self, mock_get):
        self.assertFalse(
            verify_evpn_df_election_time(
                object(), 15, max_time=0.05, check_interval=0.02,
            )
        )
        self.assertGreater(mock_get.call_count, 1)

    @patch(f"{MOD}.get_evpn_df_election_time", return_value=99)
    def test_max_time_zero_never_enters_loop(self, mock_get):
        self.assertFalse(
            verify_evpn_df_election_time(object(), 15, max_time=0)
        )
        mock_get.assert_not_called()


class TestEvpnVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    evpn/verify.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(evpn_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == evpn_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered EVPN verify functions: {missing}")

        print(
            f"\nEVPN verify coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
