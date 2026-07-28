#!/usr/bin/env python3
"""Unit tests for arcOS OSPF verify APIs (full coverage).

Every verify_* helper wraps an underlying get_*/is_* helper (imported into
verify.py's own namespace) in a ``genie.utils.timeout.Timeout`` poll loop.
With ``max_time=0`` the loop body never executes at all (0 iterations) --
useful to fast-fail without ever invoking the get helper. To actually
exercise the loop on a negative path (multiple failed polls before giving
up) a small non-zero max_time/check_interval pair is used instead
(0.05s / 0.02s), which completes in well under a second.
"""

import unittest
from unittest.mock import Mock, patch

from genie.libs.sdk.apis.arcos.ospf import verify as ospf_verify
from genie.libs.sdk.apis.arcos.ospf.verify import (
    verify_ospf_neighbor_full,
    verify_ospf_router_id,
    verify_ospf_area_count,
    verify_ospf_area_type,
    verify_ospf_interface_metric,
    verify_ospf_interface_passive,
    verify_ospf_spf_initial_delay,
    verify_ospf_route_present,
    verify_ospf_interface_auth_type,
    verify_ospf_route_preference,
    verify_ospf_max_lsa,
    verify_ospf_maintenance_mode_state,
)

_MOD = "genie.libs.sdk.apis.arcos.ospf.verify"


def _never_called(*args, **kwargs):  # pragma: no cover - defensive
    raise AssertionError(
        "get/is helper should not be called when the Timeout loop never "
        "iterates (max_time=0)"
    )


class TestVerifyOspfNeighborFull(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.is_ospf_neighbor_full", return_value=True):
            self.assertTrue(
                verify_ospf_neighbor_full(Mock(), "4.4.4.2")
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.is_ospf_neighbor_full", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_neighbor_full(Mock(), "4.4.4.2", max_time=0)
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.is_ospf_neighbor_full", return_value=False):
            self.assertFalse(
                verify_ospf_neighbor_full(
                    Mock(), "4.4.4.2", max_time=0.05, check_interval=0.02
                )
            )

    def test_exception_in_get_helper_keeps_polling(self):
        with patch(f"{_MOD}.is_ospf_neighbor_full",
                   side_effect=RuntimeError("boom")):
            self.assertFalse(
                verify_ospf_neighbor_full(
                    Mock(), "4.4.4.2", max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfRouterId(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_router_id", return_value="4.4.4.4"):
            self.assertTrue(verify_ospf_router_id(Mock(), "4.4.4.4"))

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_router_id", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_router_id(Mock(), "4.4.4.4", max_time=0)
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.get_ospf_router_id", return_value="9.9.9.9"):
            self.assertFalse(
                verify_ospf_router_id(
                    Mock(), "4.4.4.4", max_time=0.05, check_interval=0.02
                )
            )

    def test_exception_in_get_helper_keeps_polling(self):
        with patch(f"{_MOD}.get_ospf_router_id",
                   side_effect=RuntimeError("boom")):
            self.assertFalse(
                verify_ospf_router_id(
                    Mock(), "4.4.4.4", max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfAreaCount(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_area_count", return_value=2):
            self.assertTrue(verify_ospf_area_count(Mock(), 2))

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_area_count", side_effect=_never_called):
            self.assertFalse(verify_ospf_area_count(Mock(), 2, max_time=0))

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.get_ospf_area_count", return_value=1):
            self.assertFalse(
                verify_ospf_area_count(
                    Mock(), 2, max_time=0.05, check_interval=0.02
                )
            )

    def test_exception_in_get_helper_keeps_polling(self):
        with patch(f"{_MOD}.get_ospf_area_count",
                   side_effect=RuntimeError("boom")):
            self.assertFalse(
                verify_ospf_area_count(
                    Mock(), 2, max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfAreaType(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_area_type",
                   return_value="AREA_TYPE_STUB"):
            self.assertTrue(
                verify_ospf_area_type(Mock(), "1", "AREA_TYPE_STUB")
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_area_type", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_area_type(
                    Mock(), "1", "AREA_TYPE_STUB", max_time=0
                )
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.get_ospf_area_type",
                   return_value="AREA_TYPE_NORMAL"):
            self.assertFalse(
                verify_ospf_area_type(
                    Mock(), "1", "AREA_TYPE_STUB",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyOspfInterfaceMetric(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_interface_metric", return_value=100):
            self.assertTrue(
                verify_ospf_interface_metric(Mock(), "swp1", 100)
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_interface_metric",
                   side_effect=_never_called):
            self.assertFalse(
                verify_ospf_interface_metric(
                    Mock(), "swp1", 100, max_time=0
                )
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.get_ospf_interface_metric", return_value=None):
            self.assertFalse(
                verify_ospf_interface_metric(
                    Mock(), "swp1", 100, max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfInterfacePassive(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.is_ospf_interface_passive", return_value=True):
            self.assertTrue(
                verify_ospf_interface_passive(Mock(), "swp1", True)
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.is_ospf_interface_passive",
                   side_effect=_never_called):
            self.assertFalse(
                verify_ospf_interface_passive(
                    Mock(), "swp1", True, max_time=0
                )
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.is_ospf_interface_passive", return_value=False):
            self.assertFalse(
                verify_ospf_interface_passive(
                    Mock(), "swp1", True, max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfSpfInitialDelay(unittest.TestCase):
    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_spf_initial_delay", return_value=50):
            self.assertTrue(verify_ospf_spf_initial_delay(Mock(), 50))

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_spf_initial_delay",
                   side_effect=_never_called):
            self.assertFalse(
                verify_ospf_spf_initial_delay(Mock(), 50, max_time=0)
            )

    def test_exhaust_timeout(self):
        with patch(f"{_MOD}.get_ospf_spf_initial_delay", return_value=100):
            self.assertFalse(
                verify_ospf_spf_initial_delay(
                    Mock(), 50, max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyOspfRoutePresent(unittest.TestCase):
    _ROUTE = {"path-type": "intra-area", "metric": 10}

    def test_found_first_try_no_filters(self):
        with patch(f"{_MOD}.get_ospf_route", return_value=self._ROUTE):
            self.assertTrue(
                verify_ospf_route_present(Mock(), "4.4.4.4/32")
            )

    def test_found_first_try_with_matching_filters(self):
        with patch(f"{_MOD}.get_ospf_route", return_value=self._ROUTE):
            self.assertTrue(
                verify_ospf_route_present(
                    Mock(), "4.4.4.4/32",
                    path_type="intra-area", expected_metric=10,
                )
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_route", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_route_present(
                    Mock(), "4.4.4.4/32", max_time=0
                )
            )

    def test_exhaust_timeout_route_missing(self):
        with patch(f"{_MOD}.get_ospf_route", return_value=None):
            self.assertFalse(
                verify_ospf_route_present(
                    Mock(), "4.4.4.4/32",
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_path_type_mismatch(self):
        with patch(f"{_MOD}.get_ospf_route", return_value=self._ROUTE):
            self.assertFalse(
                verify_ospf_route_present(
                    Mock(), "4.4.4.4/32", path_type="inter-area",
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_metric_mismatch(self):
        with patch(f"{_MOD}.get_ospf_route", return_value=self._ROUTE):
            self.assertFalse(
                verify_ospf_route_present(
                    Mock(), "4.4.4.4/32", expected_metric=999,
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyOspfInterfaceAuthType(unittest.TestCase):
    _INTF_CRYPTO = {"authentication": {"auth-type": "OSPF_AUTH_CRYPTO_KEY"}}
    _INTF_FLAT = {"auth-type": "OSPF_AUTH_NULL"}

    def test_found_first_try_nested_auth(self):
        with patch(f"{_MOD}.get_ospf_interface", return_value=self._INTF_CRYPTO):
            self.assertTrue(
                verify_ospf_interface_auth_type(
                    Mock(), "swp1", "OSPF_AUTH_CRYPTO_KEY"
                )
            )

    def test_found_first_try_flat_auth(self):
        with patch(f"{_MOD}.get_ospf_interface", return_value=self._INTF_FLAT):
            self.assertTrue(
                verify_ospf_interface_auth_type(
                    Mock(), "swp1", "OSPF_AUTH_NULL"
                )
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_interface", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_interface_auth_type(
                    Mock(), "swp1", "OSPF_AUTH_CRYPTO_KEY", max_time=0
                )
            )

    def test_exhaust_timeout_mismatch(self):
        with patch(f"{_MOD}.get_ospf_interface", return_value=self._INTF_CRYPTO):
            self.assertFalse(
                verify_ospf_interface_auth_type(
                    Mock(), "swp1", "OSPF_AUTH_NULL",
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_interface_not_found(self):
        with patch(f"{_MOD}.get_ospf_interface", return_value=None):
            self.assertFalse(
                verify_ospf_interface_auth_type(
                    Mock(), "swp9", "OSPF_AUTH_CRYPTO_KEY",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyOspfRoutePreference(unittest.TestCase):
    _DATA = {"route-preference": {"intra-area": 110, "inter-area": 110,
                                   "external": 150}}

    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertTrue(
                verify_ospf_route_preference(
                    Mock(), intra_area=110, inter_area=110, external=150
                )
            )

    def test_found_first_try_partial_filter(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertTrue(
                verify_ospf_route_preference(Mock(), intra_area=110)
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_global", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_route_preference(
                    Mock(), intra_area=110, max_time=0
                )
            )

    def test_exhaust_timeout_mismatch(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertFalse(
                verify_ospf_route_preference(
                    Mock(), intra_area=999,
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_missing_data(self):
        with patch(f"{_MOD}.get_ospf_global", return_value={}):
            self.assertFalse(
                verify_ospf_route_preference(
                    Mock(), intra_area=110,
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyOspfMaxLsa(unittest.TestCase):
    _DATA = {"max-lsa": {"lsa-limit": 50000, "warning-threshold": 80,
                          "state": "OK"}}

    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertTrue(
                verify_ospf_max_lsa(
                    Mock(), lsa_limit=50000, warning_threshold=80, state="OK"
                )
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_global", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_max_lsa(Mock(), lsa_limit=50000, max_time=0)
            )

    def test_exhaust_timeout_mismatch(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertFalse(
                verify_ospf_max_lsa(
                    Mock(), lsa_limit=1,
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_missing_data(self):
        with patch(f"{_MOD}.get_ospf_global", return_value={}):
            self.assertFalse(
                verify_ospf_max_lsa(
                    Mock(), lsa_limit=50000,
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyOspfMaintenanceModeState(unittest.TestCase):
    _DATA = {"maintenance-mode": {"state": "ACTIVE", "trigger": "ALWAYS"}}

    def test_found_first_try(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertTrue(
                verify_ospf_maintenance_mode_state(Mock(), "ACTIVE")
            )

    def test_fast_fail_max_time_zero(self):
        with patch(f"{_MOD}.get_ospf_global", side_effect=_never_called):
            self.assertFalse(
                verify_ospf_maintenance_mode_state(
                    Mock(), "ACTIVE", max_time=0
                )
            )

    def test_exhaust_timeout_mismatch(self):
        with patch(f"{_MOD}.get_ospf_global", return_value=self._DATA):
            self.assertFalse(
                verify_ospf_maintenance_mode_state(
                    Mock(), "DISABLED",
                    max_time=0.05, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_missing_data(self):
        with patch(f"{_MOD}.get_ospf_global", return_value={}):
            self.assertFalse(
                verify_ospf_maintenance_mode_state(
                    Mock(), "ACTIVE",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestOspfVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    ospf/verify.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ospf_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ospf_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered OSPF verify functions: {missing}")

        print(f"\nOSPF verify coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
