#!/usr/bin/env python3
"""Unit tests for arcOS routing-policy verify APIs (full coverage).

Every verify_* helper in ``genie.libs.sdk.apis.arcos.route_policy.verify``
polls one of the ``get_*`` helpers from
``genie.libs.sdk.apis.arcos.route_policy.get`` inside a
``genie.utils.timeout.Timeout`` loop and returns a bool. Positive cases
return on the first iteration; negatives use ``max_time=0`` to fast-fail
without sleeping.

A module-level coverage registry (``_CALLED``) tracks which public verify_*
functions have been exercised. The final ``TestCoverage`` class (run last --
pytest preserves file order) asserts full coverage.
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

# ---------------------------------------------------------------------------
# Coverage tracking
# ---------------------------------------------------------------------------

_CALLED = set()


def _c(func, *args, **kwargs):
    """Invoke ``func`` and record it as covered by a positive-path test."""
    result = func(*args, **kwargs)
    _CALLED.add(func.__name__)
    return result


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


class TestPrefixSetVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(_c(verify_prefix_set_present, self.d, "ps1"))
        mock_get.assert_called_with(self.d, "ps1")

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_prefix_set_present(self.d, "ps1", max_time=0, check_interval=0)
        )

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_true(self, mock_get):
        mock_get.return_value = None
        self.assertTrue(_c(verify_prefix_set_not_present, self.d, "ps1"))

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_not_present_false_fast_fail(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertFalse(
            verify_prefix_set_not_present(
                self.d, "ps1", max_time=0, check_interval=0
            )
        )

    @patch(f"{verify_mod.__name__}.get_prefix_set")
    def test_prefix_set_present_handles_exception(self, mock_get):
        """get_prefix_set raising is caught -- verify fast-fails to False."""
        mock_get.side_effect = Exception("boom")
        self.assertFalse(
            verify_prefix_set_present(self.d, "ps1", max_time=0, check_interval=0)
        )


class TestPolicyDefinitionVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(
            _c(verify_policy_definition_present, self.d, "pol1")
        )
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
    def test_policy_definition_not_present_true(self, mock_get):
        mock_get.return_value = None
        self.assertTrue(
            _c(verify_policy_definition_not_present, self.d, "pol1")
        )

    @patch(f"{verify_mod.__name__}.get_policy_definition")
    def test_policy_definition_not_present_false_fast_fail(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertFalse(
            verify_policy_definition_not_present(
                self.d, "pol1", max_time=0, check_interval=0
            )
        )


class TestTagSetVerifyApis(unittest.TestCase):
    def setUp(self):
        self.d = _DummyDevice()

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_true(self, mock_get):
        mock_get.return_value = PRESENT
        self.assertTrue(_c(verify_tag_set_present, self.d, "ts1"))
        mock_get.assert_called_with(self.d, "ts1")

    @patch(f"{verify_mod.__name__}.get_tag_set")
    def test_tag_set_present_false_fast_fail(self, mock_get):
        mock_get.return_value = None
        self.assertFalse(
            verify_tag_set_present(self.d, "ts1", max_time=0, check_interval=0)
        )


# ---------------------------------------------------------------------------
# Coverage check (must run last -- pytest preserves in-file definition order)
# ---------------------------------------------------------------------------


class TestCoverage(unittest.TestCase):
    def test_all_verify_functions_exercised(self):
        expected = _all_verify_functions()
        missing = expected - _CALLED
        self.assertEqual(
            missing,
            set(),
            f"verify functions never exercised by a positive-path test: "
            f"{sorted(missing)}",
        )
        # Sanity: the reference census counted 5 verify_ fns.
        self.assertEqual(len(expected), 5)


if __name__ == "__main__":
    unittest.main()
