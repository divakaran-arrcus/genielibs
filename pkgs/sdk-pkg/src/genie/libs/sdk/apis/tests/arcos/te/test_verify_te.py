#!/usr/bin/env python3
"""Unit tests for arcOS TE verify APIs (full coverage).

Both verify_* helpers poll is_te_admin_group_present (imported at module
load into genie.libs.sdk.apis.arcos.te.verify) inside a genie.utils.timeout
Timeout loop. Timeout(max_time=0) never enters the poll loop at all, so:
  - fast "loop never runs" negatives use max_time=0 (matches the trivial
    fall-through `return False`).
  - found-first-try positives use a small non-zero max_time so the loop
    runs at least once.
  - exhausts-timeout paths use a small non-zero max_time/check_interval so
    the loop actually iterates more than once before giving up.
The underlying helper is patched on the verify module's own namespace
(where it was imported), not on the get module.
"""

import unittest
from unittest.mock import patch, Mock

from genie.libs.sdk.apis.arcos.te.verify import (
    verify_te_admin_group_present,
    verify_te_admin_group_not_present,
)

_PATCH_TARGET = "genie.libs.sdk.apis.arcos.te.verify.is_te_admin_group_present"


class TestVerifyTeAdminGroupPresent(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_present_found_first_try(self):
        with patch(_PATCH_TARGET, return_value=True) as m:
            result = verify_te_admin_group_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertTrue(result)
        self.assertEqual(m.call_count, 1)

    def test_present_fast_fail_zero_max_time(self):
        # max_time=0 never enters the poll loop -> immediate False, no calls.
        with patch(_PATCH_TARGET, return_value=True) as m:
            result = verify_te_admin_group_present(self.device, "red", max_time=0)
        self.assertFalse(result)
        m.assert_not_called()

    def test_present_exhausts_timeout(self):
        with patch(_PATCH_TARGET, return_value=False) as m:
            result = verify_te_admin_group_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertFalse(result)
        self.assertGreater(m.call_count, 1)

    def test_present_helper_raises_then_exhausts(self):
        with patch(_PATCH_TARGET, side_effect=RuntimeError("boom")) as m:
            result = verify_te_admin_group_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertFalse(result)
        self.assertGreaterEqual(m.call_count, 1)

    def test_present_named_instance(self):
        with patch(_PATCH_TARGET, return_value=True) as m:
            result = verify_te_admin_group_present(
                self.device, "red", network_instance="vrf1",
                max_time=0.05, check_interval=0.02,
            )
        self.assertTrue(result)
        _, kwargs = m.call_args
        self.assertEqual(kwargs.get("network_instance"), "vrf1")


class TestVerifyTeAdminGroupNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_not_present_found_first_try(self):
        with patch(_PATCH_TARGET, return_value=False) as m:
            result = verify_te_admin_group_not_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertTrue(result)
        self.assertEqual(m.call_count, 1)

    def test_not_present_fast_fail_zero_max_time(self):
        # max_time=0 never enters the poll loop -> immediate False.
        with patch(_PATCH_TARGET, return_value=False) as m:
            result = verify_te_admin_group_not_present(self.device, "red", max_time=0)
        self.assertFalse(result)
        m.assert_not_called()

    def test_not_present_exhausts_timeout(self):
        with patch(_PATCH_TARGET, return_value=True) as m:
            result = verify_te_admin_group_not_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertFalse(result)
        self.assertGreater(m.call_count, 1)

    def test_not_present_helper_raises_then_exhausts(self):
        # exception path treats `present` as True (conservative default) ->
        # never satisfies "not present" -> exhausts timeout -> False.
        with patch(_PATCH_TARGET, side_effect=RuntimeError("boom")) as m:
            result = verify_te_admin_group_not_present(
                self.device, "red", max_time=0.05, check_interval=0.02
            )
        self.assertFalse(result)
        self.assertGreaterEqual(m.call_count, 1)

    def test_all_public_functions_covered(self):
        import inspect
        import genie.libs.sdk.apis.arcos.te.verify as te_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(te_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == te_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered TE verify functions: {missing}")

        print(f"\nTE verify coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
