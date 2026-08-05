#!/usr/bin/env python3
"""Unit tests for arcOS LLDP verify APIs (full coverage).

verify_lldp_neighbor_present / verify_lldp_neighbor_not_present wrap
get_lldp_interface in a Timeout poll loop. Positive cases return True on the
first iteration. get_lldp_interface is patched where it is imported into the
verify module.

Note on negative cases: genie.utils.timeout.Timeout with max_time=0 never
enters the poll loop body at all (0 iterations), so a bare `max_time=0`
"fast-fail" never actually calls get_lldp_interface -- it would just
trivially hit the final `return False` regardless of what the mock returns.
To genuinely exercise the loop body (the comparison logic, the
`_has_neighbor_with_system_name` None-handling, and the `timeout.sleep()`
line) while still running fast, negative cases use a small positive
max_time (0.05s) with a smaller check_interval (0.02s), which guarantees at
least one real iteration against the mock before the poll expires.
"""

import unittest
from unittest.mock import patch

from genie.libs.sdk.apis.arcos.lldp.verify import (
    verify_lldp_neighbor_present,
    verify_lldp_neighbor_not_present,
)

MOD = "genie.libs.sdk.apis.arcos.lldp.verify"

INTF_WITH_NEIGHBOR = {
    "name": "swp1",
    "neighbors": {
        "nbr1": {"id": "nbr1", "system-name": "rtr2"},
    },
}

INTF_NO_NEIGHBOR = {
    "name": "swp1",
    "neighbors": {},
}

INTF_NO_NEIGHBORS_KEY = {
    "name": "swp1",
}


import inspect
import genie.libs.sdk.apis.arcos.lldp.verify as verify_module
class _DummyDevice:
    def __init__(self):
        self.name = "rtr1"


class TestVerifyLldpNeighborPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_match(self, mock_get):
        mock_get.return_value = INTF_WITH_NEIGHBOR
        self.assertTrue(
            verify_lldp_neighbor_present(self.device, "swp1", "rtr2")
        )

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_no_match(self, mock_get):
        mock_get.return_value = INTF_NO_NEIGHBOR
        self.assertFalse(
            verify_lldp_neighbor_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_no_neighbors_key(self, mock_get):
        mock_get.return_value = INTF_NO_NEIGHBORS_KEY
        self.assertFalse(
            verify_lldp_neighbor_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_intf_data_none(self, mock_get):
        """get_lldp_interface returns None (interface not found) --
        _has_neighbor_with_system_name's `if not intf_data` branch."""
        mock_get.return_value = None
        self.assertFalse(
            verify_lldp_neighbor_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_get_lldp_interface_raises(self, mock_get):
        """get_lldp_interface raising is caught and treated as no data."""
        mock_get.side_effect = Exception("boom")
        self.assertFalse(
            verify_lldp_neighbor_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_present_zero_max_time_trivial_false(self, mock_get):
        """max_time=0 never enters the poll loop -- the function returns
        False immediately without ever calling get_lldp_interface."""
        mock_get.return_value = INTF_WITH_NEIGHBOR
        self.assertFalse(
            verify_lldp_neighbor_present(
                self.device, "swp1", "rtr2", max_time=0, check_interval=0
            )
        )
        mock_get.assert_not_called()


class TestVerifyLldpNeighborNotPresent(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.get_lldp_interface")
    def test_not_present_match(self, mock_get):
        mock_get.return_value = INTF_NO_NEIGHBOR
        self.assertTrue(
            verify_lldp_neighbor_not_present(self.device, "swp1", "rtr2")
        )

    @patch(f"{MOD}.get_lldp_interface")
    def test_not_present_still_present(self, mock_get):
        mock_get.return_value = INTF_WITH_NEIGHBOR
        self.assertFalse(
            verify_lldp_neighbor_not_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_not_present_intf_data_none_treated_as_present(self, mock_get):
        """get_lldp_interface returns None -- code assumes 'present' as the
        safe default for not_present, so it should NOT report success."""
        mock_get.return_value = None
        self.assertFalse(
            verify_lldp_neighbor_not_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()

    @patch(f"{MOD}.get_lldp_interface")
    def test_not_present_get_lldp_interface_raises(self, mock_get):
        mock_get.side_effect = Exception("boom")
        self.assertFalse(
            verify_lldp_neighbor_not_present(
                self.device, "swp1", "rtr2",
                max_time=0.05, check_interval=0.02,
            )
        )
        mock_get.assert_called()




class TestLldpVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify function in
    lldp/verify.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(verify_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == verify_module.__name__
            and (name.startswith("verify_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered lldp verify functions: {missing}")
if __name__ == "__main__":
    unittest.main()
