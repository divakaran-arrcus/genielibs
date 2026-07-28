#!/usr/bin/env python3
"""Unit tests for arcOS BGP verify APIs (full coverage).

Verify helpers wrap the get helpers in a Timeout loop; positive cases return on
the first iteration, negatives use max_time=0 to fast-fail. The underlying
parser (ShowBgpNeighbor) is patched to drive canned output for the two
original tests; the rest of this file patches the *get* helper functions
directly (module-level imports in verify.py — patched at the verify module's
namespace) since that isolates the Timeout-loop behavior from the get-layer
parsing logic already covered in test_get_bgp.py.

verify_bgp_neighbor_configured / verify_bgp_peer_group_configured import
their get_bgp_running_config_* helper *locally* inside the function body
(``from genie.libs.sdk.apis.arcos.bgp.get import ...``), so those two are
patched at the original definition site (genie.libs.sdk.apis.arcos.bgp.get),
not at the verify module's namespace — patching verify.<name> would have no
effect since the name is rebound on every call.

A machine coverage check (test_zzz_all_functions_covered) asserts every
public verify_* function in genie.libs.sdk.apis.arcos.bgp.verify was
exercised.
"""

import inspect
import unittest
from unittest.mock import patch, Mock

import genie.libs.sdk.apis.arcos.bgp.verify as verify_module
from genie.libs.sdk.apis.arcos.bgp.verify import (
    verify_bgp_neighbor_state,
    verify_bgp_neighbor_established,
    verify_bgp_neighbor_present,
    verify_bgp_neighbor_not_present,
    verify_bgp_route_present,
    verify_bgp_route_not_present,
    verify_bgp_as_configured,
    verify_bgp_router_id_configured,
    verify_bgp_neighbor_configured,
    verify_bgp_peer_group_configured,
)

MOD = "genie.libs.sdk.apis.arcos.bgp.verify"
GET_MOD = "genie.libs.sdk.apis.arcos.bgp.get"

NB = "genie.libs.parser.arcos.show_bgp.ShowBgpNeighbor"
NEIGHBORS = {
    "neighbors": {
        "10.0.0.2": {"state": "ESTABLISHED"},
    }
}

# ---------------------------------------------------------------------------
# Machine coverage tracking
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


verify_bgp_neighbor_state = _track("verify_bgp_neighbor_state", verify_bgp_neighbor_state)
verify_bgp_neighbor_established = _track(
    "verify_bgp_neighbor_established", verify_bgp_neighbor_established
)
verify_bgp_neighbor_present = _track(
    "verify_bgp_neighbor_present", verify_bgp_neighbor_present
)
verify_bgp_neighbor_not_present = _track(
    "verify_bgp_neighbor_not_present", verify_bgp_neighbor_not_present
)
verify_bgp_route_present = _track("verify_bgp_route_present", verify_bgp_route_present)
verify_bgp_route_not_present = _track(
    "verify_bgp_route_not_present", verify_bgp_route_not_present
)
verify_bgp_as_configured = _track("verify_bgp_as_configured", verify_bgp_as_configured)
verify_bgp_router_id_configured = _track(
    "verify_bgp_router_id_configured", verify_bgp_router_id_configured
)
verify_bgp_neighbor_configured = _track(
    "verify_bgp_neighbor_configured", verify_bgp_neighbor_configured
)
verify_bgp_peer_group_configured = _track(
    "verify_bgp_peer_group_configured", verify_bgp_peer_group_configured
)


class TestVerifyBgp(unittest.TestCase):
    @patch(NB)
    def test_neighbor_present(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertTrue(verify_bgp_neighbor_present(Mock(), "10.0.0.2"))

    @patch(NB)
    def test_neighbor_present_false_fast_fail(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertFalse(
            verify_bgp_neighbor_present(Mock(), "9.9.9.9", max_time=0)
        )

    @patch(NB)
    def test_neighbor_not_present_true(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertTrue(verify_bgp_neighbor_not_present(Mock(), "9.9.9.9"))

    @patch(NB)
    def test_neighbor_not_present_false_fast_fail(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertFalse(
            verify_bgp_neighbor_not_present(Mock(), "10.0.0.2", max_time=0)
        )


class TestVerifyBgpNeighborState(unittest.TestCase):
    """verify_bgp_neighbor_state, verify_bgp_neighbor_established"""

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_state_matches_first_try(self, mock_state):
        mock_state.return_value = "ESTABLISHED"
        self.assertTrue(
            verify_bgp_neighbor_state(
                Mock(), "10.0.0.2", "ESTABLISHED", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_state_case_insensitive(self, mock_state):
        mock_state.return_value = "established"
        self.assertTrue(
            verify_bgp_neighbor_state(
                Mock(), "10.0.0.2", "ESTABLISHED", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_state_mismatch_fast_fail(self, mock_state):
        mock_state.return_value = "IDLE"
        self.assertFalse(
            verify_bgp_neighbor_state(Mock(), "10.0.0.2", "ESTABLISHED", max_time=0)
        )
        mock_state.assert_not_called()

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_state_exception_treated_as_none(self, mock_state):
        mock_state.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_neighbor_state(
                Mock(), "10.0.0.2", "ESTABLISHED", max_time=0.05, check_interval=0.02
            )
        )

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_state_retries_then_matches(self, mock_state):
        mock_state.side_effect = [None, "IDLE", "ESTABLISHED"]
        self.assertTrue(
            verify_bgp_neighbor_state(
                Mock(), "10.0.0.2", "ESTABLISHED", max_time=1, check_interval=0
            )
        )

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_established_wraps_state(self, mock_state):
        mock_state.return_value = "ESTABLISHED"
        self.assertTrue(
            verify_bgp_neighbor_established(
                Mock(), "10.0.0.2", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.get_bgp_neighbor_state")
    def test_established_fast_fail(self, mock_state):
        mock_state.return_value = "IDLE"
        self.assertFalse(
            verify_bgp_neighbor_established(Mock(), "10.0.0.2", max_time=0)
        )


class TestVerifyBgpRoute(unittest.TestCase):
    """verify_bgp_route_present, verify_bgp_route_not_present"""

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_present_first_try(self, mock_present):
        mock_present.return_value = True
        self.assertTrue(
            verify_bgp_route_present(
                Mock(), "10.0.0.0/24", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_present_fast_fail(self, mock_present):
        mock_present.return_value = False
        self.assertFalse(
            verify_bgp_route_present(Mock(), "10.0.0.0/24", max_time=0)
        )
        mock_present.assert_not_called()

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_present_exception_treated_as_absent(self, mock_present):
        mock_present.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_route_present(
                Mock(), "10.0.0.0/24", max_time=0.05, check_interval=0.02
            )
        )

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_not_present_true(self, mock_present):
        mock_present.return_value = False
        self.assertTrue(
            verify_bgp_route_not_present(
                Mock(), "10.0.0.0/24", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_not_present_fast_fail(self, mock_present):
        mock_present.return_value = True
        self.assertFalse(
            verify_bgp_route_not_present(Mock(), "10.0.0.0/24", max_time=0)
        )

    @patch(f"{MOD}.is_bgp_route_present")
    def test_route_not_present_exception_treated_as_present(self, mock_present):
        mock_present.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_route_not_present(
                Mock(), "10.0.0.0/24", max_time=0.05, check_interval=0.02
            )
        )


class TestVerifyBgpRunningConfig(unittest.TestCase):
    """verify_bgp_as_configured, verify_bgp_router_id_configured"""

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_as_matches_first_try(self, mock_cfg):
        mock_cfg.return_value = {"as": 65001}
        self.assertTrue(
            verify_bgp_as_configured(Mock(), 65001, max_time=1, check_interval=1)
        )

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_as_mismatch_fast_fail(self, mock_cfg):
        mock_cfg.return_value = {"as": 65002}
        self.assertFalse(
            verify_bgp_as_configured(Mock(), 65001, max_time=0)
        )
        mock_cfg.assert_not_called()

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_as_exception_treated_as_unconfigured(self, mock_cfg):
        mock_cfg.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_as_configured(Mock(), 65001, max_time=0.05, check_interval=0.02)
        )

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_router_id_matches_first_try(self, mock_cfg):
        mock_cfg.return_value = {"router-id": "1.1.1.1"}
        self.assertTrue(
            verify_bgp_router_id_configured(
                Mock(), "1.1.1.1", max_time=1, check_interval=1
            )
        )

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_router_id_mismatch_fast_fail(self, mock_cfg):
        mock_cfg.return_value = {"router-id": "2.2.2.2"}
        self.assertFalse(
            verify_bgp_router_id_configured(Mock(), "1.1.1.1", max_time=0)
        )

    @patch(f"{MOD}.get_bgp_running_config_global")
    def test_router_id_exception_treated_as_unconfigured(self, mock_cfg):
        mock_cfg.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_router_id_configured(
                Mock(), "1.1.1.1", max_time=0.05, check_interval=0.02
            )
        )


class TestVerifyBgpNeighborAndPeerGroupConfigured(unittest.TestCase):
    """verify_bgp_neighbor_configured, verify_bgp_peer_group_configured.

    Both import their get_bgp_running_config_* helper locally inside the
    function body, so patch at the get module (original definition site).
    """

    @patch(f"{GET_MOD}.get_bgp_running_config_neighbors")
    def test_neighbor_configured_true(self, mock_nbrs):
        mock_nbrs.return_value = {"10.0.0.2": {"peer-as": 65002}}
        self.assertTrue(
            verify_bgp_neighbor_configured(
                Mock(), "10.0.0.2", max_time=1, check_interval=1
            )
        )

    @patch(f"{GET_MOD}.get_bgp_running_config_neighbors")
    def test_neighbor_configured_fast_fail(self, mock_nbrs):
        mock_nbrs.return_value = {"10.0.0.2": {"peer-as": 65002}}
        self.assertFalse(
            verify_bgp_neighbor_configured(Mock(), "9.9.9.9", max_time=0)
        )

    @patch(f"{GET_MOD}.get_bgp_running_config_neighbors")
    def test_neighbor_configured_exception(self, mock_nbrs):
        mock_nbrs.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_neighbor_configured(
                Mock(), "10.0.0.2", max_time=0.05, check_interval=0.02
            )
        )

    @patch(f"{GET_MOD}.get_bgp_running_config_peer_groups")
    def test_peer_group_configured_true(self, mock_pgs):
        mock_pgs.return_value = {"PG1": {"peer-as": 65000}}
        self.assertTrue(
            verify_bgp_peer_group_configured(
                Mock(), "PG1", max_time=1, check_interval=1
            )
        )

    @patch(f"{GET_MOD}.get_bgp_running_config_peer_groups")
    def test_peer_group_configured_fast_fail(self, mock_pgs):
        mock_pgs.return_value = {"PG1": {"peer-as": 65000}}
        self.assertFalse(
            verify_bgp_peer_group_configured(Mock(), "PG9", max_time=0)
        )

    @patch(f"{GET_MOD}.get_bgp_running_config_peer_groups")
    def test_peer_group_configured_exception(self, mock_pgs):
        mock_pgs.side_effect = Exception("boom")
        self.assertFalse(
            verify_bgp_peer_group_configured(
                Mock(), "PG1", max_time=0.05, check_interval=0.02
            )
        )


class TestVerifyBgpCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in verify.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(verify_module, inspect.isfunction)
            if obj.__module__ == verify_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in bgp/verify.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
