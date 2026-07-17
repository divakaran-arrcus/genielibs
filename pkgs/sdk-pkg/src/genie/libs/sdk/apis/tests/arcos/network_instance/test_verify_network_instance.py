#!/usr/bin/env python3
"""Unit tests for arcOS Network Instance verify APIs (full coverage).

Every verify_* helper wraps a get_*/is_* helper (imported into the verify
module's namespace) in a genie.utils.timeout.Timeout poll loop. Tests patch
the underlying helper *on the verify module*, since that's where the name
is bound (``from ...get import is_network_instance_present, ...``).

Timeout(max_time=0) never enters the poll loop (0 iterations) -- handy for
an immediate-fail fast path, but it can't exercise the try/except body or
the loop-continuation branches. Those are covered separately with a small
non-zero real Timeout (max_time=0.05, check_interval=0.02, ~3-4 iterations
in ~50ms) driving either a raising mock (exception branch, then natural
timeout) or a scripted side_effect list (found on a later iteration).
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.network_instance.verify import (
    verify_network_instance_present,
    verify_network_instance_not_present,
    verify_network_instance_interface_present,
    verify_network_instance_fdb_mac_present,
    verify_network_instance_fdb_mac_not_present,
)

_MOD = "genie.libs.sdk.apis.arcos.network_instance.verify"


class _DummyDevice:
    def __init__(self):
        self.name = "rtr1"


class TestVerifyNetworkInstancePresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    def test_found_first_try(self):
        with patch(f"{_MOD}.is_network_instance_present", return_value=True):
            self.assertTrue(
                verify_network_instance_present(self.device, "vlan100")
            )

    def test_fast_fail_not_found(self):
        with patch(f"{_MOD}.is_network_instance_present", return_value=False):
            self.assertFalse(
                verify_network_instance_present(
                    self.device, "vlan100", max_time=0
                )
            )

    def test_found_on_later_iteration(self):
        with patch(
            f"{_MOD}.is_network_instance_present",
            side_effect=[False, False, True],
        ):
            self.assertTrue(
                verify_network_instance_present(
                    self.device, "vlan100", max_time=0.1, check_interval=0.02
                )
            )

    def test_exhaust_timeout_via_exception(self):
        """Every poll raises -> except branch sets present=False each time
        -> loop naturally times out -> returns False."""
        with patch(
            f"{_MOD}.is_network_instance_present",
            side_effect=RuntimeError("device unreachable"),
        ):
            self.assertFalse(
                verify_network_instance_present(
                    self.device, "vlan100", max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyNetworkInstanceNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    def test_found_first_try(self):
        with patch(f"{_MOD}.is_network_instance_present", return_value=False):
            self.assertTrue(
                verify_network_instance_not_present(self.device, "vlan100")
            )

    def test_fast_fail_still_present(self):
        with patch(f"{_MOD}.is_network_instance_present", return_value=True):
            self.assertFalse(
                verify_network_instance_not_present(
                    self.device, "vlan100", max_time=0
                )
            )

    def test_found_absent_on_later_iteration(self):
        with patch(
            f"{_MOD}.is_network_instance_present",
            side_effect=[True, True, False],
        ):
            self.assertTrue(
                verify_network_instance_not_present(
                    self.device, "vlan100", max_time=0.1, check_interval=0.02
                )
            )

    def test_exhaust_timeout_via_exception(self):
        """Exception path sets present=True (defensive) -> never satisfies
        'not present' -> loop times out -> returns False."""
        with patch(
            f"{_MOD}.is_network_instance_present",
            side_effect=RuntimeError("device unreachable"),
        ):
            self.assertFalse(
                verify_network_instance_not_present(
                    self.device, "vlan100", max_time=0.05, check_interval=0.02
                )
            )


class TestVerifyNetworkInstanceInterfacePresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    def test_found_first_try(self):
        with patch(
            f"{_MOD}.get_network_instance_interfaces",
            return_value={"swp1.100": {}},
        ):
            self.assertTrue(
                verify_network_instance_interface_present(
                    self.device, "vlan100", "swp1.100"
                )
            )

    def test_fast_fail_not_found(self):
        with patch(
            f"{_MOD}.get_network_instance_interfaces", return_value={}
        ):
            self.assertFalse(
                verify_network_instance_interface_present(
                    self.device, "vlan100", "swp1.100", max_time=0
                )
            )

    def test_found_on_later_iteration(self):
        with patch(
            f"{_MOD}.get_network_instance_interfaces",
            side_effect=[{}, {}, {"swp1.100": {}}],
        ):
            self.assertTrue(
                verify_network_instance_interface_present(
                    self.device, "vlan100", "swp1.100",
                    max_time=0.1, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_via_exception(self):
        with patch(
            f"{_MOD}.get_network_instance_interfaces",
            side_effect=RuntimeError("device unreachable"),
        ):
            self.assertFalse(
                verify_network_instance_interface_present(
                    self.device, "vlan100", "swp1.100",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyNetworkInstanceFdbMacPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    def test_found_first_try(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            return_value={"aa:bb:cc:dd:ee:ff": {}},
        ):
            self.assertTrue(
                verify_network_instance_fdb_mac_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff"
                )
            )

    def test_fast_fail_not_found(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries", return_value={}
        ):
            self.assertFalse(
                verify_network_instance_fdb_mac_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff", max_time=0
                )
            )

    def test_found_on_later_iteration(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            side_effect=[{}, {"aa:bb:cc:dd:ee:ff": {}}],
        ):
            self.assertTrue(
                verify_network_instance_fdb_mac_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff",
                    max_time=0.1, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_via_exception(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            side_effect=RuntimeError("device unreachable"),
        ):
            self.assertFalse(
                verify_network_instance_fdb_mac_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyNetworkInstanceFdbMacNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    def test_found_first_try(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries", return_value={}
        ):
            self.assertTrue(
                verify_network_instance_fdb_mac_not_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff"
                )
            )

    def test_fast_fail_still_present(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            return_value={"aa:bb:cc:dd:ee:ff": {}},
        ):
            self.assertFalse(
                verify_network_instance_fdb_mac_not_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff", max_time=0
                )
            )

    def test_found_absent_on_later_iteration(self):
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            side_effect=[{"aa:bb:cc:dd:ee:ff": {}}, {}],
        ):
            self.assertTrue(
                verify_network_instance_fdb_mac_not_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff",
                    max_time=0.1, check_interval=0.02,
                )
            )

    def test_exhaust_timeout_via_exception(self):
        """Exception path sets present=True (defensive) -> never satisfies
        'not present' -> loop times out -> returns False."""
        with patch(
            f"{_MOD}.get_network_instance_fdb_mac_entries",
            side_effect=RuntimeError("device unreachable"),
        ):
            self.assertFalse(
                verify_network_instance_fdb_mac_not_present(
                    self.device, "vlan100", "aa:bb:cc:dd:ee:ff",
                    max_time=0.05, check_interval=0.02,
                )
            )


class TestVerifyNetworkInstanceCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    network_instance/verify.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect
        from genie.libs.sdk.apis.arcos.network_instance import verify as ni_verify

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ni_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ni_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Network Instance verify functions: {missing}")

        print(
            f"\nNetwork Instance verify coverage: "
            f"{len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
