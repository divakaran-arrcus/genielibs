#!/usr/bin/env python3
"""Unit tests for arcOS static routing verify APIs (full coverage).

Each verify_* helper polls a `genie.utils.timeout.Timeout` loop around a
get.py helper (is_static_route_present / get_static_route_tag), imported
directly into the verify module's namespace. Timeout(max_time=0) never
enters the poll loop (0 iterations), so it can't exercise the loop body
(the comparison, log.debug, and timeout.sleep() lines) -- only the final
return/log.warning. To get full coverage of both the "found on first try"
and "times out after N unsuccessful polls" paths without any real sleeping,
Timeout itself is patched (at the verify module namespace) with a fake that
yields a scripted number of True iterations before returning False, and
whose .sleep() is a no-op. The underlying get.py helpers are patched at the
verify module namespace as well, matching the "or patch the underlying
get/is helper on the verify module namespace" guidance.
"""

import unittest
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.static_routing.verify import (
    verify_static_route_present,
    verify_static_route_not_present,
    verify_static_route_tag,
)

MOD = "genie.libs.sdk.apis.arcos.static_routing.verify"


class _FakeTimeout:
    """Drop-in for genie.utils.timeout.Timeout with scripted iterate()
    results and an instant (no-op) sleep()."""

    def __init__(self, iterate_results):
        self._results = list(iterate_results)
        self.sleep = Mock(return_value=None)

    def __call__(self, *args, **kwargs):
        # Timeout(max_time, check_interval) constructor call in verify.py
        return self

    def iterate(self):
        if self._results:
            return self._results.pop(0)
        return False


def _device():
    d = Mock()
    d.name = "rtr1"
    return d


class TestVerifyStaticRoutePresent(unittest.TestCase):
    def setUp(self):
        self.device = _device()

    def test_present_found_first_iteration(self):
        fake_timeout = _FakeTimeout([True])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.is_static_route_present", return_value=True) as m:
            result = verify_static_route_present(self.device, "10.0.0.0/8")
        self.assertTrue(result)
        m.assert_called_once()

    def test_present_never_found_times_out(self):
        """Loop runs twice (both False), third iterate() call returns False
        -> exits loop -> log.warning -> return False."""
        fake_timeout = _FakeTimeout([True, True, False])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.is_static_route_present", return_value=False) as m:
            result = verify_static_route_present(
                self.device, "10.0.0.0/8", max_time=30, check_interval=5
            )
        self.assertFalse(result)
        self.assertEqual(m.call_count, 2)
        self.assertEqual(fake_timeout.sleep.call_count, 2)

    def test_present_custom_ni_pi_forwarded(self):
        fake_timeout = _FakeTimeout([True])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.is_static_route_present", return_value=True) as m:
            verify_static_route_present(self.device, "10.0.0.0/8", ni="vrf1", pi="pi1")
        m.assert_called_with(self.device, "10.0.0.0/8", ni="vrf1", pi="pi1")


class TestVerifyStaticRouteNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = _device()

    def test_not_present_confirmed_first_iteration(self):
        fake_timeout = _FakeTimeout([True])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.is_static_route_present", return_value=False) as m:
            result = verify_static_route_not_present(self.device, "10.0.0.0/8")
        self.assertTrue(result)
        m.assert_called_once()

    def test_not_present_still_present_times_out(self):
        fake_timeout = _FakeTimeout([True, True, False])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.is_static_route_present", return_value=True) as m:
            result = verify_static_route_not_present(
                self.device, "10.0.0.0/8", max_time=30, check_interval=5
            )
        self.assertFalse(result)
        self.assertEqual(m.call_count, 2)
        self.assertEqual(fake_timeout.sleep.call_count, 2)


class TestVerifyStaticRouteTag(unittest.TestCase):
    def setUp(self):
        self.device = _device()

    def test_tag_matches_first_iteration(self):
        fake_timeout = _FakeTimeout([True])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.get_static_route_tag", return_value=500) as m:
            result = verify_static_route_tag(self.device, "10.0.0.0/8", 500)
        self.assertTrue(result)
        m.assert_called_once()

    def test_tag_mismatch_times_out(self):
        """actual_tag (5) != expected_tag (999) on every iteration -> loop
        exhausts -> final log.warning re-queries the tag once more."""
        fake_timeout = _FakeTimeout([True, True, False])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.get_static_route_tag", return_value=5) as m:
            result = verify_static_route_tag(
                self.device, "10.0.0.0/8", 999, max_time=30, check_interval=5
            )
        self.assertFalse(result)
        # Called twice inside the loop + once more for the final log.warning.
        self.assertEqual(m.call_count, 3)

    def test_tag_none_when_route_absent_times_out(self):
        """actual_tag is None (route not found) -> never matches -> times out."""
        fake_timeout = _FakeTimeout([True, False])
        with patch(f"{MOD}.Timeout", fake_timeout), \
                patch(f"{MOD}.get_static_route_tag", return_value=None) as m:
            result = verify_static_route_tag(self.device, "9.9.9.0/24", 100)
        self.assertFalse(result)
        self.assertEqual(m.call_count, 2)


if __name__ == "__main__":
    unittest.main()
