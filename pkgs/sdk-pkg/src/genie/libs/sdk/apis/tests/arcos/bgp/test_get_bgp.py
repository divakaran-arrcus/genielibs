#!/usr/bin/env python3
"""Unit tests for arcOS BGP get APIs (full coverage).

The BGP get helpers instantiate the parser class directly
(``ShowBgpGlobalState(device).parse(...)``) via a *local* import inside each
``_parse_bgp_*`` helper (e.g. ``from genie.libs.parser.arcos.show_bgp import
ShowBgpNeighbor``), so tests patch the parser classes at their original
definition site in ``genie.libs.parser.arcos.show_bgp`` — patching at the
get.py usage site would have no effect since the name is rebound on every
call, not held as a module-level reference in get.py.

Canned data matches the ``show_bgp.py`` schemas:
  - ShowBgpGlobalState: flat dict (as, router-id, ...)
  - ShowBgpNeighbor: {"neighbors": {addr: {"session-state": ..., ...}}}
  - ShowBgpGlobalAfiSafi: {"afi-safis": {name: {...}}}
  - ShowBgpRibRoute: {"routes": {prefix: {"paths": [...]}}}
  - ShowBgpConfig: {"network-instance": {ni: {"bgp": {pi: {"config":
    {...}, "neighbors": {...}, "peer-groups": {...}}}}}}

A machine coverage check (test_zzz_all_functions_covered) asserts every
public get_*/is_* function in genie.libs.sdk.apis.arcos.bgp.get was
exercised by some test in this file.
"""

import inspect
import unittest
from unittest.mock import patch, Mock

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.bgp.get as get_module
from genie.libs.sdk.apis.arcos.bgp.get import (
    get_bgp_global_state,
    get_bgp_as_number,
    get_bgp_router_id,
    get_bgp_neighbors,
    get_bgp_neighbor,
    get_bgp_neighbor_state,
    get_bgp_neighbor_count,
    is_bgp_neighbor_present,
    get_bgp_afi_safis,
    get_bgp_afi_safi,
    get_bgp_routes,
    get_bgp_route,
    is_bgp_route_present,
    get_bgp_route_count,
    get_bgp_running_config,
    get_bgp_running_config_global,
    get_bgp_running_config_neighbors,
    get_bgp_running_config_neighbor,
    get_bgp_running_config_peer_groups,
    get_bgp_running_config_peer_group,
)

GS = "genie.libs.parser.arcos.show_bgp.ShowBgpGlobalState"
NB = "genie.libs.parser.arcos.show_bgp.ShowBgpNeighbor"
AFI = "genie.libs.parser.arcos.show_bgp.ShowBgpGlobalAfiSafi"
RR = "genie.libs.parser.arcos.show_bgp.ShowBgpRibRoute"
RC = "genie.libs.parser.arcos.show_bgp.ShowBgpConfig"

GLOBAL = {"as": 65001, "router-id": "1.1.1.1"}
NEIGHBORS = {
    "neighbors": {
        "10.0.0.2": {"state": "ESTABLISHED"},
        "10.0.0.3": {"state": "IDLE"},
    }
}
NEIGHBORS_FULL = {
    "neighbors": {
        "10.0.0.2": {"session-state": "ESTABLISHED", "peer-as": 65002},
        "10.0.0.3": {"session-state": "IDLE", "peer-as": 65003},
    }
}
AFI_SAFIS = {
    "afi-safis": {
        "IPV4_UNICAST": {"enabled": True, "total-paths": 10, "total-prefixes": 5},
        "IPV6_UNICAST": {"enabled": False},
    }
}
ROUTES = {
    "routes": {
        "10.0.0.0/24": {
            "paths": [
                {"origin": "IGP", "valid-route": True, "next-hop": "10.0.0.1"},
            ],
        },
        "192.168.1.0/24": {"paths": [{"origin": "EGP"}]},
    }
}
RUNNING_CONFIG = {
    "network-instance": {
        "default": {
            "bgp": {
                "default": {
                    "config": {"as": 65001, "router-id": "1.1.1.1"},
                    "neighbors": {
                        "10.0.0.2": {"peer-as": 65002, "description": "peer2"},
                    },
                    "peer-groups": {
                        "PG1": {"peer-as": 65000},
                    },
                }
            }
        }
    }
}


# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


get_bgp_global_state = _track("get_bgp_global_state", get_bgp_global_state)
get_bgp_as_number = _track("get_bgp_as_number", get_bgp_as_number)
get_bgp_router_id = _track("get_bgp_router_id", get_bgp_router_id)
get_bgp_neighbors = _track("get_bgp_neighbors", get_bgp_neighbors)
get_bgp_neighbor = _track("get_bgp_neighbor", get_bgp_neighbor)
get_bgp_neighbor_state = _track("get_bgp_neighbor_state", get_bgp_neighbor_state)
get_bgp_neighbor_count = _track("get_bgp_neighbor_count", get_bgp_neighbor_count)
is_bgp_neighbor_present = _track("is_bgp_neighbor_present", is_bgp_neighbor_present)
get_bgp_afi_safis = _track("get_bgp_afi_safis", get_bgp_afi_safis)
get_bgp_afi_safi = _track("get_bgp_afi_safi", get_bgp_afi_safi)
get_bgp_routes = _track("get_bgp_routes", get_bgp_routes)
get_bgp_route = _track("get_bgp_route", get_bgp_route)
is_bgp_route_present = _track("is_bgp_route_present", is_bgp_route_present)
get_bgp_route_count = _track("get_bgp_route_count", get_bgp_route_count)
get_bgp_running_config = _track("get_bgp_running_config", get_bgp_running_config)
get_bgp_running_config_global = _track(
    "get_bgp_running_config_global", get_bgp_running_config_global
)
get_bgp_running_config_neighbors = _track(
    "get_bgp_running_config_neighbors", get_bgp_running_config_neighbors
)
get_bgp_running_config_neighbor = _track(
    "get_bgp_running_config_neighbor", get_bgp_running_config_neighbor
)
get_bgp_running_config_peer_groups = _track(
    "get_bgp_running_config_peer_groups", get_bgp_running_config_peer_groups
)
get_bgp_running_config_peer_group = _track(
    "get_bgp_running_config_peer_group", get_bgp_running_config_peer_group
)


class TestGetBgp(unittest.TestCase):
    @patch(GS)
    def test_global_state(self, mock_gs):
        mock_gs.return_value.parse.return_value = GLOBAL
        self.assertEqual(get_bgp_global_state(Mock()), GLOBAL)

    @patch(GS)
    def test_as_number(self, mock_gs):
        mock_gs.return_value.parse.return_value = GLOBAL
        self.assertEqual(get_bgp_as_number(Mock()), 65001)

    @patch(GS)
    def test_router_id(self, mock_gs):
        mock_gs.return_value.parse.return_value = GLOBAL
        self.assertEqual(get_bgp_router_id(Mock()), "1.1.1.1")

    @patch(NB)
    def test_neighbor_count(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertEqual(get_bgp_neighbor_count(Mock()), 2)

    @patch(NB)
    def test_neighbor_present(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS
        self.assertTrue(is_bgp_neighbor_present(Mock(), "10.0.0.2"))
        self.assertFalse(is_bgp_neighbor_present(Mock(), "9.9.9.9"))


class TestGetBgpEmpty(unittest.TestCase):
    @patch(GS)
    def test_as_number_none(self, mock_gs):
        mock_gs.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertIsNone(get_bgp_as_number(Mock()))

    @patch(GS)
    def test_router_id_none(self, mock_gs):
        mock_gs.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertIsNone(get_bgp_router_id(Mock()))

    @patch(NB)
    def test_neighbor_count_zero(self, mock_nb):
        mock_nb.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_neighbor_count(Mock()), 0)


class TestGetBgpNeighbors(unittest.TestCase):
    """get_bgp_neighbors, get_bgp_neighbor, get_bgp_neighbor_state"""

    @patch(NB)
    def test_get_neighbors(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS_FULL
        result = get_bgp_neighbors(Mock())
        self.assertEqual(set(result), {"10.0.0.2", "10.0.0.3"})

    @patch(NB)
    def test_get_neighbors_empty(self, mock_nb):
        mock_nb.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_neighbors(Mock()), {})

    @patch(NB)
    def test_get_neighbor_found(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS_FULL
        nbr = get_bgp_neighbor(Mock(), "10.0.0.2")
        self.assertEqual(nbr["peer-as"], 65002)

    @patch(NB)
    def test_get_neighbor_missing(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS_FULL
        self.assertIsNone(get_bgp_neighbor(Mock(), "9.9.9.9"))

    @patch(NB)
    def test_get_neighbor_state(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS_FULL
        self.assertEqual(
            get_bgp_neighbor_state(Mock(), "10.0.0.2"), "ESTABLISHED"
        )

    @patch(NB)
    def test_get_neighbor_state_missing(self, mock_nb):
        mock_nb.return_value.parse.return_value = NEIGHBORS_FULL
        self.assertIsNone(get_bgp_neighbor_state(Mock(), "9.9.9.9"))


class TestGetBgpAfiSafis(unittest.TestCase):
    """get_bgp_afi_safis, get_bgp_afi_safi"""

    @patch(AFI)
    def test_get_afi_safis(self, mock_afi):
        mock_afi.return_value.parse.return_value = AFI_SAFIS
        result = get_bgp_afi_safis(Mock())
        self.assertEqual(set(result), {"IPV4_UNICAST", "IPV6_UNICAST"})

    @patch(AFI)
    def test_get_afi_safis_empty(self, mock_afi):
        mock_afi.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_afi_safis(Mock()), {})

    @patch(AFI)
    def test_get_afi_safi_found(self, mock_afi):
        mock_afi.return_value.parse.return_value = AFI_SAFIS
        result = get_bgp_afi_safi(Mock(), "IPV4_UNICAST")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["total-paths"], 10)

    @patch(AFI)
    def test_get_afi_safi_missing(self, mock_afi):
        mock_afi.return_value.parse.return_value = AFI_SAFIS
        self.assertIsNone(get_bgp_afi_safi(Mock(), "L2VPN_EVPN"))


class TestGetBgpRoutes(unittest.TestCase):
    """get_bgp_routes, get_bgp_route, is_bgp_route_present, get_bgp_route_count"""

    @patch(RR)
    def test_get_routes(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        result = get_bgp_routes(Mock())
        self.assertEqual(set(result), {"10.0.0.0/24", "192.168.1.0/24"})

    @patch(RR)
    def test_get_routes_empty(self, mock_rr):
        mock_rr.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_routes(Mock()), {})

    @patch(RR)
    def test_get_route_found(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        route = get_bgp_route(Mock(), "10.0.0.0/24")
        self.assertEqual(len(route["paths"]), 1)
        self.assertEqual(route["paths"][0]["origin"], "IGP")

    @patch(RR)
    def test_get_route_single_match_fallback(self, mock_rr):
        single = {"routes": {"10.0.0.0/24": {"paths": [{"origin": "IGP"}]}}}
        mock_rr.return_value.parse.return_value = single
        # Parser may have normalized the prefix; a single-route result
        # falls back to returning that one route regardless of key.
        route = get_bgp_route(Mock(), "10.0.0.0/25")
        self.assertEqual(route["paths"][0]["origin"], "IGP")

    @patch(RR)
    def test_get_route_missing(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        self.assertIsNone(get_bgp_route(Mock(), "172.16.0.0/24"))

    @patch(RR)
    def test_is_route_present_true(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        self.assertTrue(is_bgp_route_present(Mock(), "10.0.0.0/24"))

    @patch(RR)
    def test_is_route_present_false(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        self.assertFalse(is_bgp_route_present(Mock(), "172.16.0.0/24"))

    @patch(RR)
    def test_get_route_count(self, mock_rr):
        mock_rr.return_value.parse.return_value = ROUTES
        self.assertEqual(get_bgp_route_count(Mock()), 2)

    @patch(RR)
    def test_get_route_count_empty(self, mock_rr):
        mock_rr.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_route_count(Mock()), 0)


class TestGetBgpRunningConfig(unittest.TestCase):
    """get_bgp_running_config* family (ShowBgpConfig)"""

    @patch(RC)
    def test_get_running_config(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        inst = get_bgp_running_config(Mock())
        self.assertIn("config", inst)
        self.assertIn("neighbors", inst)
        self.assertIn("peer-groups", inst)

    @patch(RC)
    def test_get_running_config_empty(self, mock_rc):
        mock_rc.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_bgp_running_config(Mock()), {})

    @patch(RC)
    def test_get_running_config_global(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        cfg = get_bgp_running_config_global(Mock())
        self.assertEqual(cfg["as"], 65001)
        self.assertEqual(cfg["router-id"], "1.1.1.1")

    @patch(RC)
    def test_get_running_config_neighbors(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        nbrs = get_bgp_running_config_neighbors(Mock())
        self.assertIn("10.0.0.2", nbrs)

    @patch(RC)
    def test_get_running_config_neighbor_found(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        nbr = get_bgp_running_config_neighbor(Mock(), "10.0.0.2")
        self.assertEqual(nbr["peer-as"], 65002)

    @patch(RC)
    def test_get_running_config_neighbor_missing(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        self.assertIsNone(get_bgp_running_config_neighbor(Mock(), "9.9.9.9"))

    @patch(RC)
    def test_get_running_config_peer_groups(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        pgs = get_bgp_running_config_peer_groups(Mock())
        self.assertIn("PG1", pgs)

    @patch(RC)
    def test_get_running_config_peer_group_found(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        pg = get_bgp_running_config_peer_group(Mock(), "PG1")
        self.assertEqual(pg["peer-as"], 65000)

    @patch(RC)
    def test_get_running_config_peer_group_missing(self, mock_rc):
        mock_rc.return_value.parse.return_value = RUNNING_CONFIG
        self.assertIsNone(get_bgp_running_config_peer_group(Mock(), "PG9"))

    @patch(RC)
    def test_get_running_config_subcommand_failure(self, mock_rc):
        mock_rc.return_value.parse.side_effect = SubCommandFailure("boom")
        self.assertEqual(get_bgp_running_config(Mock()), {})

    @patch(RC)
    def test_get_running_config_unexpected_exception(self, mock_rc):
        mock_rc.return_value.parse.side_effect = ValueError("weird")
        self.assertEqual(get_bgp_running_config(Mock()), {})


class TestGetBgpCoverage(unittest.TestCase):
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in get.py must
        have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(get_module, inspect.isfunction)
            if obj.__module__ == get_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in bgp/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
