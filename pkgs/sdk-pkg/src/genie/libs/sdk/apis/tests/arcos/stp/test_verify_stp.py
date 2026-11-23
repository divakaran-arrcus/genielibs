#!/usr/bin/env python3
"""Unit tests for arcOS STP verify APIs (full coverage).

The verify helpers wrap the get helpers (``genie.libs.sdk.apis.arcos.stp.get``)
in a Timeout poll loop. ``Timeout(max_time=0)`` never enters the loop, so a
negative test that only uses ``max_time=0`` passes without exercising
anything. These tests patch ``Timeout`` with a scripted fake that runs a fixed
number of iterations without sleeping, so each negative case really polls.
"""

import inspect
import unittest
from unittest.mock import patch

import genie.libs.sdk.apis.arcos.stp.verify as verify_module
from genie.libs.sdk.apis.arcos.stp.verify import (
    _get_stp_global_flag,
    verify_stp_enabled_protocol,
    verify_stp_disabled,
    verify_stp_bpdu_guard,
    verify_stp_bridge_assurance,
)

MOD = "genie.libs.sdk.apis.arcos.stp.verify"


class _DummyDevice:
    name = "rtr1"


class _FakeTimeout:
    """Runs exactly ``iterations`` loop passes; ``sleep`` is a no-op."""

    iterations = 2

    def __init__(self, max_time, interval):
        self._left = self.iterations
        self.sleeps = 0

    def iterate(self):
        if self._left <= 0:
            return False
        self._left -= 1
        return True

    def sleep(self):
        self.sleeps += 1


@patch(f"{MOD}.Timeout", _FakeTimeout)
class TestGetStpGlobalFlag(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_stp_global")
    def test_flag_true(self, mock_get):
        mock_get.return_value = {"bpdu-guard": True}
        self.assertIs(_get_stp_global_flag(self.device, "bpdu-guard"), True)

    @patch(f"{MOD}.get_stp_global")
    def test_flag_false(self, mock_get):
        mock_get.return_value = {"bpdu-guard": False}
        self.assertIs(_get_stp_global_flag(self.device, "bpdu-guard"), False)

    @patch(f"{MOD}.get_stp_global")
    def test_flag_absent_is_none(self, mock_get):
        mock_get.return_value = {"enabled-protocol": "RAPID_PVST"}
        self.assertIsNone(_get_stp_global_flag(self.device, "bpdu-guard"))

    @patch(f"{MOD}.get_stp_global")
    def test_empty_state_is_none(self, mock_get):
        mock_get.return_value = {}
        self.assertIsNone(
            _get_stp_global_flag(self.device, "bridge-assurance"))


@patch(f"{MOD}.Timeout", _FakeTimeout)
class TestVerifyStpEnabledProtocol(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_default_rapid_pvst_matches(self, mock_get):
        mock_get.return_value = "RAPID_PVST"
        self.assertTrue(verify_stp_enabled_protocol(self.device))

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_match_is_case_insensitive(self, mock_get):
        mock_get.return_value = "rapid_pvst"
        self.assertTrue(
            verify_stp_enabled_protocol(self.device, "Rapid_Pvst"))

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_mismatch_polls_then_fails(self, mock_get):
        mock_get.return_value = "MSTP"
        self.assertFalse(
            verify_stp_enabled_protocol(self.device, "RAPID_PVST"))
        self.assertEqual(mock_get.call_count, _FakeTimeout.iterations)

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_converges_on_second_poll(self, mock_get):
        mock_get.side_effect = ["MSTP", "RAPID_PVST"]
        self.assertTrue(verify_stp_enabled_protocol(self.device))
        self.assertEqual(mock_get.call_count, 2)

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_none_never_matches(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(verify_stp_enabled_protocol(self.device, "NONE"))

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_get_exception_is_retried(self, mock_get):
        mock_get.side_effect = [RuntimeError("boom"), "RAPID_PVST"]
        self.assertTrue(verify_stp_enabled_protocol(self.device))

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_get_exception_every_poll_fails(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        self.assertFalse(verify_stp_enabled_protocol(self.device))
        self.assertEqual(mock_get.call_count, _FakeTimeout.iterations)


@patch(f"{MOD}.Timeout", _FakeTimeout)
class TestVerifyStpDisabled(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_disabled_when_none(self, mock_get):
        mock_get.return_value = "NONE"
        self.assertTrue(verify_stp_disabled(self.device))

    @patch(f"{MOD}.get_stp_enabled_protocol")
    def test_not_disabled_when_running(self, mock_get):
        mock_get.return_value = "RAPID_PVST"
        self.assertFalse(verify_stp_disabled(self.device))
        self.assertEqual(mock_get.call_count, _FakeTimeout.iterations)

    @patch(f"{MOD}.verify_stp_enabled_protocol")
    def test_delegates_with_none_and_timing(self, mock_verify):
        mock_verify.return_value = True
        verify_stp_disabled(self.device, max_time=7, check_interval=3)
        mock_verify.assert_called_once_with(
            device=self.device, expected_protocol="NONE",
            max_time=7, check_interval=3)


def _flag_cases(test_fn_name, verify_fn, key):
    """Build the shared positive/negative cases for a global boolean flag."""

    @patch(f"{MOD}.Timeout", _FakeTimeout)
    class _Cases(unittest.TestCase):
        def setUp(self):
            self.device = _DummyDevice()

        @patch(f"{MOD}.get_stp_global")
        def test_enabled_matches(self, mock_get):
            mock_get.return_value = {key: True}
            self.assertTrue(verify_fn(self.device))

        @patch(f"{MOD}.get_stp_global")
        def test_disabled_matches_when_expected_false(self, mock_get):
            mock_get.return_value = {key: False}
            self.assertTrue(verify_fn(self.device, expected_enabled=False))

        @patch(f"{MOD}.get_stp_global")
        def test_mismatch_polls_then_fails(self, mock_get):
            mock_get.return_value = {key: False}
            self.assertFalse(verify_fn(self.device, expected_enabled=True))
            self.assertEqual(mock_get.call_count, _FakeTimeout.iterations)

        @patch(f"{MOD}.get_stp_global")
        def test_absent_is_not_treated_as_disabled(self, mock_get):
            mock_get.return_value = {"enabled-protocol": "RAPID_PVST"}
            self.assertFalse(verify_fn(self.device, expected_enabled=False))

        @patch(f"{MOD}.get_stp_global")
        def test_converges_on_second_poll(self, mock_get):
            mock_get.side_effect = [{key: False}, {key: True}]
            self.assertTrue(verify_fn(self.device))

        @patch(f"{MOD}._get_stp_global_flag")
        def test_get_exception_is_retried(self, mock_flag):
            mock_flag.side_effect = [RuntimeError("boom"), True]
            self.assertTrue(verify_fn(self.device))
            mock_flag.assert_called_with(self.device, key)

    _Cases.__name__ = test_fn_name
    _Cases.__qualname__ = test_fn_name
    return _Cases


TestVerifyStpBpduGuard = _flag_cases(
    "TestVerifyStpBpduGuard", verify_stp_bpdu_guard, "bpdu-guard")
TestVerifyStpBridgeAssurance = _flag_cases(
    "TestVerifyStpBridgeAssurance", verify_stp_bridge_assurance,
    "bridge-assurance")


class TestStpVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify function in
    stp/verify.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest``.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(verify_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == verify_module.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered stp verify functions: {missing}")


if __name__ == "__main__":
    unittest.main()
