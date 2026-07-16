#!/usr/bin/env python3
"""Unit tests for arcOS SR-Policy verify APIs (full coverage).

Verify helpers wrap the get helpers (imported into this module's namespace)
in a genie.utils.timeout.Timeout loop. Timeout(max_time=0) never enters the
poll loop, so exhaust-timeout cases here use a small non-zero max_time/
check_interval (0.05/0.02) to force the loop body to actually execute while
keeping the test fast. Positive cases return True on the very first
iteration (mock returns the expected state right away).
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.sr_policy.verify import (
    verify_sr_policy_oper_up,
    verify_sr_policy_oper_down,
    verify_sr_policy_segment_list_present,
)

_VERIFY_MOD = "genie.libs.sdk.apis.arcos.sr_policy.verify"


class TestVerifySrPolicyOperUp(unittest.TestCase):
    """verify_sr_policy_oper_up"""

    def test_oper_up_found_first_try(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state", return_value="UP"
        ):
            self.assertTrue(
                verify_sr_policy_oper_up(object(), "2.2.2.2", 100)
            )

    def test_oper_up_exhausts_timeout(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state", return_value="DOWN"
        ):
            self.assertFalse(
                verify_sr_policy_oper_up(
                    object(), "2.2.2.2", 100,
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_oper_up_handles_get_exception(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state",
            side_effect=RuntimeError("boom"),
        ):
            self.assertFalse(
                verify_sr_policy_oper_up(
                    object(), "2.2.2.2", 100,
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifySrPolicyOperDown(unittest.TestCase):
    """verify_sr_policy_oper_down"""

    def test_oper_down_found_first_try(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state", return_value="DOWN"
        ):
            self.assertTrue(
                verify_sr_policy_oper_down(object(), "2.2.2.2", 100)
            )

    def test_oper_down_exhausts_timeout(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state", return_value="UP"
        ):
            self.assertFalse(
                verify_sr_policy_oper_down(
                    object(), "2.2.2.2", 100,
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_oper_down_handles_get_exception(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_db_oper_state",
            side_effect=RuntimeError("boom"),
        ):
            self.assertFalse(
                verify_sr_policy_oper_down(
                    object(), "2.2.2.2", 100,
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifySrPolicySegmentListPresent(unittest.TestCase):
    """verify_sr_policy_segment_list_present"""

    def test_segment_list_present_found_first_try(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_segment_list",
            return_value={"name": "sl1"},
        ):
            self.assertTrue(
                verify_sr_policy_segment_list_present(object(), "sl1")
            )

    def test_segment_list_present_exhausts_timeout(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_segment_list", return_value=None
        ):
            self.assertFalse(
                verify_sr_policy_segment_list_present(
                    object(), "sl9",
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_segment_list_present_handles_get_exception(self):
        with patch(
            f"{_VERIFY_MOD}.get_sr_policy_segment_list",
            side_effect=RuntimeError("boom"),
        ):
            self.assertFalse(
                verify_sr_policy_segment_list_present(
                    object(), "sl1",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestSrPolicyVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    sr_policy/verify.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect
        from genie.libs.sdk.apis.arcos.sr_policy import verify as sr_policy_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sr_policy_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sr_policy_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Untested verify functions: {missing}"
        )

        print(
            f"\nSR-Policy verify coverage: {len(names)} verify_* functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
