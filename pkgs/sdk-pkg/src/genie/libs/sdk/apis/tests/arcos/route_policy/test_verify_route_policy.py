#!/usr/bin/env python3
"""Unit tests for arcOS routing-policy verify APIs (full coverage).

Every verify_* helper in ``genie.libs.sdk.apis.arcos.route_policy.verify``
polls one of the ``get_*`` helpers from
``genie.libs.sdk.apis.arcos.route_policy.get`` inside a
``genie.utils.timeout.Timeout`` loop and returns a bool. Positive
("found-first-try") cases patch the get helper to return the passing value
immediately with a small non-zero max_time -- the loop body runs exactly
once and returns on the first check.

Negatives mirror the isis/bgp verify pattern (see
``.../tests/arcos/bgp/test_verify_bgp.py``): a naive
``max_time=0`` fast-return never enters the Timeout loop body at all
(``Timeout(max_time=0, ...).iterate()`` returns False immediately), so a
negative built only that way never actually calls the underlying get
helper -- it proves nothing about the polling/exception-handling logic.
Each verify_* function below therefore also gets:

  * a "mismatch/absent -> False" case using a small non-zero max_time
    (0.05) + check_interval (0.02) so the loop body actually runs,
    asserting the mocked get helper was called at least once (and, where
    the loop is expected to exhaust the timeout, at least twice).
  * a real exception case: the get helper is mocked with
    side_effect=Exception, again with small non-zero timing, asserting the
    function returns False and the helper was actually invoked --
    exercising the try/except path for real instead of skipping it via
    max_time=0.

The max_time=0 fast-return cases are kept alongside the above (not removed)
as extra coverage of the zero-timeout short-circuit, but are never the only
negative for a given function.

The final ``TestCoverage`` class asserts that every public verify_*
function defined in the source module is referenced by name somewhere in
this test file's source -- an order-safe source-scan (mirrors
``ospf/test_get_ospf.py``) rather than a runtime call-recording registry,
since the latter is order-dependent under `python -m unittest`'s
alphabetical class ordering.
"""

import inspect
import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.route_policy import verify as verify_mod
from genie.libs.sdk.apis.arcos.route_policy.verify import (
    verify_prefix_set_present,
    verify_prefix_set_not_present,
    verify_policy_definition_present,
    verify_policy_definition_not_present,
    verify_tag_set_present,
)


def _all_verify_functions():
    """All public verify_* functions defined in the module."""
    return {
        name
        for name, obj in inspect.getmembers(verify_mod, inspect.isfunction)
        if obj.__module__ == verify_mod.__name__ and name.startswith("verify_")
    }


class _DummyDevice:
    def __init__(self):
        self.name = "rtr1"


PRESENT = {"name": "present-item"}

# Small, real, non-zero timings so the Timeout loop body actually executes
# (Timeout(max_time=0, ...) never enters the loop at all).
EXHAUST_MAX_TIME = 0.05
EXHAUST_INTERVAL = 0.02


class TestPrefixSetVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(verify_prefix_set_present(self.d, "ps1"))
        mock_get.assert_called_with(self.d, "ps1")

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_prefix_set_present(self.d, "ps1", max_time=0, check_interval=0)
        )

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_absent_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_prefix_set_present(
            self.d, "ps1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_handles_exception(self, mock_get):
        """get_prefix_set raising is caught -- verify returns False, and the
        helper was actually invoked (proving the try/except path runs)."""
        mock_get.side_effect = Exception("boom")
        result = verify_prefix_set_present(
            self.d, "ps1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertTrue(mock_get.called)

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_true(self, mock_get):
        mock_get.return_value = None
        self.assertTrue(verify_prefix_set_not_present(self.d, "ps1"))

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_false_fast_fail(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertFalse(
            verify_prefix_set_not_present(
                self.d, "ps1", max_time=0, check_interval=0
            )
        )

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_still_present_exhausts_timeout(self, mock_get):
        mock_get.return_value = PRESENT
        result = verify_prefix_set_not_present(
            self.d, "ps1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_handles_exception(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_prefix_set_not_present(
            self.d, "ps1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertTrue(mock_get.called)


class TestPolicyDefinitionVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(verify_policy_definition_present(self.d, "pol1"))
        mock_get.assert_called_with(self.d, "pol1")

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_policy_definition_present(
                self.d, "pol1", max_time=0, check_interval=0
            )
        )

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_present_absent_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_policy_definition_present(
            self.d, "pol1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_present_handles_exception(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_policy_definition_present(
            self.d, "pol1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertTrue(mock_get.called)

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_not_present_true(self, mock_get):
        mock_get.return_value = None
        self.assertTrue(verify_policy_definition_not_present(self.d, "pol1"))

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_not_present_false_fast_fail(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertFalse(
            verify_policy_definition_not_present(
                self.d, "pol1", max_time=0, check_interval=0
            )
        )

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_not_present_still_present_exhausts_timeout(
        self, mock_get
    ):
        mock_get.return_value = PRESENT
        result = verify_policy_definition_not_present(
            self.d, "pol1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_not_present_handles_exception(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_policy_definition_not_present(
            self.d, "pol1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertTrue(mock_get.called)


class TestTagSetVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(verify_tag_set_present(self.d, "ts1"))
        mock_get.assert_called_with(self.d, "ts1")

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_tag_set_present(self.d, "ts1", max_time=0, check_interval=0)
        )

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_absent_exhausts_timeout(self, mock_get):
        mock_get.return_value = None
        result = verify_tag_set_present(
            self.d, "ts1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertGreaterEqual(mock_get.call_count, 2)

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_handles_exception(self, mock_get):
        mock_get.side_effect = Exception("boom")
        result = verify_tag_set_present(
            self.d, "ts1",
            max_time=EXHAUST_MAX_TIME, check_interval=EXHAUST_INTERVAL,
        )
        self.assertFalse(result)
        self.assertTrue(mock_get.called)


# ---------------------------------------------------------------------------
# Coverage check: machine-checked, order-safe under both pytest and
# `python -m unittest` (alphabetical class order) since it scans this file's
# own source text instead of relying on a runtime call-recording registry
# populated by other test classes running first.
# ---------------------------------------------------------------------------


class TestCoverage(unittest.TestCase):
    def test_all_verify_functions_exercised(self):
        with open(__file__, "r") as f:
            source = f.read()

        expected = _all_verify_functions()
        missing = [n for n in expected if n not in source]
        self.assertEqual(
            missing,
            [],
            f"verify functions never referenced in this test file: "
            f"{sorted(missing)}",
        )
        # Sanity: the reference census counted 5 verify_ fns.
        self.assertEqual(len(expected), 5)


if __name__ == "__main__":
    unittest.main()
