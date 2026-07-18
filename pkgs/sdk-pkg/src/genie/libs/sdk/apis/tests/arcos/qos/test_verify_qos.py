#!/usr/bin/env python3
"""Unit tests for arcOS QoS verify APIs (full coverage).

Verify helpers wrap qos.get.is_qos_policy_present (imported directly into
the verify module namespace) in a Timeout loop; positive cases return on
the first iteration, negatives use max_time=0 to fast-fail without
sleeping.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.qos import verify as qos_verify
from genie.libs.sdk.apis.arcos.qos.verify import (
    verify_qos_policy_present,
    verify_qos_policy_not_present,
)

MOD = "genie.libs.sdk.apis.arcos.qos.verify"


class _DummyDevice:
    name = "rtr1"


class TestVerifyQosPolicyPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.is_qos_policy_present", return_value=True)
    def test_present_true_first_try(self, mock_is):
        self.assertTrue(
            verify_qos_policy_present(self.device, "ingress-pol")
        )

    @patch(f"{MOD}.is_qos_policy_present", return_value=False)
    def test_present_false_fast_fail(self, mock_is):
        self.assertFalse(
            verify_qos_policy_present(
                self.device, "ingress-pol", max_time=0
            )
        )

    @patch(f"{MOD}.is_qos_policy_present", side_effect=Exception("boom"))
    def test_present_exception_fast_fail(self, mock_is):
        self.assertFalse(
            verify_qos_policy_present(
                self.device, "ingress-pol", max_time=0
            )
        )

    @patch(f"{MOD}.is_qos_policy_present")
    def test_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = False
        self.assertFalse(
            verify_qos_policy_present(
                self.device, "ingress-pol", max_time=0.05, check_interval=0.02
            )
        )
        self.assertGreater(mock_is.call_count, 1)


class TestVerifyQosPolicyNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.is_qos_policy_present", return_value=False)
    def test_not_present_true_first_try(self, mock_is):
        self.assertTrue(
            verify_qos_policy_not_present(self.device, "ingress-pol")
        )

    @patch(f"{MOD}.is_qos_policy_present", return_value=True)
    def test_not_present_false_fast_fail(self, mock_is):
        self.assertFalse(
            verify_qos_policy_not_present(
                self.device, "ingress-pol", max_time=0
            )
        )

    @patch(f"{MOD}.is_qos_policy_present", side_effect=Exception("boom"))
    def test_not_present_exception_fast_fail(self, mock_is):
        # is_qos_policy_present raising is treated as "still present" ->
        # verify_qos_policy_not_present should fast-fail to False.
        self.assertFalse(
            verify_qos_policy_not_present(
                self.device, "ingress-pol", max_time=0
            )
        )

    @patch(f"{MOD}.is_qos_policy_present")
    def test_not_present_exhausts_timeout(self, mock_is):
        mock_is.return_value = True
        self.assertFalse(
            verify_qos_policy_not_present(
                self.device, "ingress-pol", max_time=0.05, check_interval=0.02
            )
        )
        self.assertGreater(mock_is.call_count, 1)


class TestQosVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    qos/verify.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(qos_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == qos_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered QoS verify functions: {missing}")

        print(
            f"\nQoS verify coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
