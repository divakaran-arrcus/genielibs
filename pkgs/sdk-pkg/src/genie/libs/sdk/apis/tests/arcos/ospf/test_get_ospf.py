#!/usr/bin/env python3
"""Unit tests for arcOS OSPF get APIs (full coverage).

Every get_*/is_* helper instantiates one of six arcOS OSPF parser classes
and calls ``.parse()``. Six classes (ShowOspfGlobal/Neighbor/Area/Interface/
SpfThrottle/Lsdb) are imported at module load time in get.py, so they are
patched at their import site:
``genie.libs.sdk.apis.arcos.ospf.get.ShowX``. ShowOspfGlobalRib is imported
locally (inside the function body, guarded by try/except ImportError), so
it is patched at its parser home module:
``genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib``.
"""

import sys
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.ospf import get as ospf_get
from genie.libs.sdk.apis.arcos.ospf.get import (
    get_ospf_global,
    get_ospf_router_id,
    get_ospf_neighbor_count,
    get_ospf_neighbors,
    is_ospf_neighbor_full,
    get_ospf_areas,
    get_ospf_area,
    get_ospf_area_count,
    get_ospf_area_type,
    get_ospf_interfaces,
    get_ospf_interface,
    get_ospf_interface_metric,
    is_ospf_interface_passive,
    get_ospf_spf_throttle,
    get_ospf_spf_initial_delay,
    get_ospf_lsdb,
    get_ospf_lsdb_lsa_count,
    get_ospf_route,
    get_ospf_routes,
)


def _parser_mock(retval=None, raise_exc=None):
    """Build a Mock usable as a MetaParser-class stand-in: calling it (as
    ``ShowX(device=device)``) returns an object whose ``.parse(**kwargs)``
    returns ``retval`` or raises ``raise_exc``."""
    instance = Mock()
    if raise_exc is not None:
        instance.parse.side_effect = raise_exc
    else:
        instance.parse.return_value = retval
    return Mock(return_value=instance)


_GLOBAL_DATA = {
    "router-id": "4.4.4.4",
    "log-adjacency-changes": "LOG_ADJ_ENABLE_DETAILED",
    "max-ecmp-paths": 4,
    "abr-router": False,
    "asbr-router": False,
    "area-count": 2,
    "neighbor-count": 3,
    "full-neighbor-count": 2,
    "up-interface-count": 4,
    "route-preference": {"intra-area": 110, "inter-area": 110, "external": 150},
    "max-lsa": {"lsa-limit": 50000, "warning-threshold": 80, "state": "OK"},
    "maintenance-mode": {"state": "DISABLED", "trigger": "NONE"},
}

_NEIGHBORS_DATA = {
    "neighbors": {
        "0:swp1:4.4.4.2": {
            "area": 0, "interface": "swp1",
            "neighbor-router-id": "4.4.4.2",
            "neighbor-ip-address": "10.14.1.2",
            "adjacency-state": "NEIGHBOR_FULL",
            "priority": 1,
        },
        "0:swp2:4.4.4.3": {
            "area": 0, "interface": "swp2",
            "neighbor-router-id": "4.4.4.3",
            "adjacency-state": "NEIGHBOR_2WAY",
        },
    }
}

_AREAS_DATA = {
    "areas": {
        "0": {
            "identifier": 0, "area-type": "AREA_TYPE_NORMAL",
            "advertise-summary-lsas": True,
            "configured-interface-count": 2, "up-interface-count": 2,
            "neighbor-count": 1, "full-neighbor-count": 1,
        },
        "1": {
            "identifier": 1, "area-type": "AREA_TYPE_STUB",
            "stub-default-cost": 10,
            "configured-interface-count": 1, "up-interface-count": 1,
        },
    }
}

_INTERFACES_DATA = {
    "areas": {
        "0": {
            "interfaces": {
                "swp1": {
                    "id": "swp1", "network-type": "POINT_TO_POINT_NETWORK",
                    "metric": 100, "passive": False, "ignore-mtu": False,
                    "interface-up": True, "interface-state": "POINT_TO_POINT",
                    "instance-id": 0, "interface-id": 5,
                    "authentication": {"auth-type": "OSPF_AUTH_CRYPTO_KEY"},
                },
                "swp2": {
                    "id": "swp2", "metric": 10, "passive": True,
                    "interface-up": True,
                    "authentication": {"auth-type": "OSPF_AUTH_NULL"},
                },
            }
        }
    }
}

_SPF_THROTTLE_DATA = {
    "spf-initial-delay": 50,
    "spf-short-delay": 200,
    "spf-long-delay": 5000,
    "time-to-learn-interval": 500,
    "holddown-interval": 10000,
}

_LSDB_DATA = {
    "areas": {
        "0": {
            "lsa-types": {
                "ROUTER_LSA": {
                    "lsa-type": "ROUTER_LSA",
                    "lsas": {
                        "4.4.4.1:4.4.4.1": {
                            "link-state-id": "4.4.4.1",
                            "advertising-router": "4.4.4.1",
                            "ls-age": 10,
                        },
                        "4.4.4.2:4.4.4.2": {
                            "link-state-id": "4.4.4.2",
                            "advertising-router": "4.4.4.2",
                            "ls-age": 20,
                        },
                    },
                },
                "AS_EXTERNAL_LSA": {
                    "lsa-type": "AS_EXTERNAL_LSA",
                    "lsas": {
                        "10.0.0.5:4.4.4.1": {
                            "link-state-id": "10.0.0.5",
                            "advertising-router": "4.4.4.1",
                        },
                    },
                },
            }
        }
    }
}

_RIB_DATA = {
    "routes": {
        "4.4.4.4/32": {
            "prefix": "4.4.4.4/32",
            "path-type": "intra-area",
            "metric": 10,
            "area": "0",
        },
        "10.0.0.0/24": {
            "prefix": "10.0.0.0/24",
            "path-type": "external-type-2",
            "metric": 20,
        },
    }
}


class TestGetOspfGlobal(unittest.TestCase):
    """get_ospf_global, get_ospf_router_id, get_ospf_neighbor_count."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(_GLOBAL_DATA))
    def test_get_global(self):
        self.assertEqual(get_ospf_global(Mock()), _GLOBAL_DATA)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(_GLOBAL_DATA))
    def test_get_router_id(self):
        self.assertEqual(get_ospf_router_id(Mock()), "4.4.4.4")

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(_GLOBAL_DATA))
    def test_get_neighbor_count(self):
        self.assertEqual(get_ospf_neighbor_count(Mock()), 2)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_global_empty(self):
        self.assertEqual(get_ospf_global(Mock()), {})

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_router_id_empty(self):
        self.assertIsNone(get_ospf_router_id(Mock()))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_neighbor_count_empty(self):
        self.assertEqual(get_ospf_neighbor_count(Mock()), 0)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfGlobal",
           new=_parser_mock(raise_exc=ValueError("boom")))
    def test_get_global_generic_exception(self):
        self.assertEqual(get_ospf_global(Mock()), {})


class TestGetOspfNeighbors(unittest.TestCase):
    """get_ospf_neighbors, is_ospf_neighbor_full."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(_NEIGHBORS_DATA))
    def test_get_neighbors(self):
        result = get_ospf_neighbors(Mock())
        self.assertEqual(len(result), 2)
        self.assertIn("0:swp1:4.4.4.2", result)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(_NEIGHBORS_DATA))
    def test_is_neighbor_full_true(self):
        self.assertTrue(is_ospf_neighbor_full(Mock(), "4.4.4.2"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(_NEIGHBORS_DATA))
    def test_is_neighbor_full_false_2way(self):
        self.assertFalse(is_ospf_neighbor_full(Mock(), "4.4.4.3"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(_NEIGHBORS_DATA))
    def test_is_neighbor_full_not_found(self):
        self.assertFalse(is_ospf_neighbor_full(Mock(), "9.9.9.9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_neighbors_empty(self):
        self.assertEqual(get_ospf_neighbors(Mock()), {})

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfNeighbor",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_is_neighbor_full_empty(self):
        self.assertFalse(is_ospf_neighbor_full(Mock(), "4.4.4.2"))


class TestGetOspfAreas(unittest.TestCase):
    """get_ospf_areas, get_ospf_area, get_ospf_area_count,
    get_ospf_area_type."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_areas(self):
        self.assertEqual(len(get_ospf_areas(Mock())), 2)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_area(self):
        area = get_ospf_area(Mock(), "0")
        self.assertEqual(area["area-type"], "AREA_TYPE_NORMAL")

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_area_not_found(self):
        self.assertIsNone(get_ospf_area(Mock(), "9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_area_count(self):
        self.assertEqual(get_ospf_area_count(Mock()), 2)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_area_type(self):
        self.assertEqual(get_ospf_area_type(Mock(), "1"), "AREA_TYPE_STUB")

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(_AREAS_DATA))
    def test_get_area_type_not_found(self):
        self.assertIsNone(get_ospf_area_type(Mock(), "9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfArea",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_areas_empty(self):
        self.assertEqual(get_ospf_areas(Mock()), {})
        self.assertEqual(get_ospf_area_count(Mock()), 0)


class TestGetOspfInterfaces(unittest.TestCase):
    """get_ospf_interfaces, get_ospf_interface, get_ospf_interface_metric,
    is_ospf_interface_passive."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_get_interfaces(self):
        areas = get_ospf_interfaces(Mock())
        self.assertIn("0", areas)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_get_interface(self):
        intf = get_ospf_interface(Mock(), "swp1")
        self.assertEqual(intf["metric"], 100)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_get_interface_not_found(self):
        self.assertIsNone(get_ospf_interface(Mock(), "swp9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_get_interface_metric(self):
        self.assertEqual(get_ospf_interface_metric(Mock(), "swp1"), 100)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_get_interface_metric_not_found(self):
        self.assertIsNone(get_ospf_interface_metric(Mock(), "swp9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_is_interface_passive_true(self):
        self.assertTrue(is_ospf_interface_passive(Mock(), "swp2"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_is_interface_passive_false(self):
        self.assertFalse(is_ospf_interface_passive(Mock(), "swp1"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(_INTERFACES_DATA))
    def test_is_interface_passive_not_found(self):
        self.assertIsNone(is_ospf_interface_passive(Mock(), "swp9"))

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfInterface",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_interfaces_empty(self):
        self.assertEqual(get_ospf_interfaces(Mock()), {})


class TestGetOspfSpfThrottle(unittest.TestCase):
    """get_ospf_spf_throttle, get_ospf_spf_initial_delay."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfSpfThrottle",
           new=_parser_mock(_SPF_THROTTLE_DATA))
    def test_get_spf_throttle(self):
        self.assertEqual(get_ospf_spf_throttle(Mock()), _SPF_THROTTLE_DATA)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfSpfThrottle",
           new=_parser_mock(_SPF_THROTTLE_DATA))
    def test_get_spf_initial_delay(self):
        self.assertEqual(get_ospf_spf_initial_delay(Mock()), 50)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfSpfThrottle",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_spf_throttle_empty(self):
        self.assertEqual(get_ospf_spf_throttle(Mock()), {})

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfSpfThrottle",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_spf_initial_delay_empty(self):
        self.assertIsNone(get_ospf_spf_initial_delay(Mock()))


class TestGetOspfLsdb(unittest.TestCase):
    """get_ospf_lsdb, get_ospf_lsdb_lsa_count."""

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(_LSDB_DATA))
    def test_get_lsdb(self):
        areas = get_ospf_lsdb(Mock())
        self.assertIn("0", areas)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(_LSDB_DATA))
    def test_get_lsdb_lsa_count_by_type(self):
        self.assertEqual(
            get_ospf_lsdb_lsa_count(Mock(), area="0", lsa_type="ROUTER_LSA"), 2
        )
        self.assertEqual(
            get_ospf_lsdb_lsa_count(Mock(), area="0",
                                     lsa_type="AS_EXTERNAL_LSA"), 1
        )

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(_LSDB_DATA))
    def test_get_lsdb_lsa_count_total(self):
        self.assertEqual(get_ospf_lsdb_lsa_count(Mock(), area="0"), 3)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(_LSDB_DATA))
    def test_get_lsdb_lsa_count_unknown_type(self):
        self.assertEqual(
            get_ospf_lsdb_lsa_count(Mock(), area="0", lsa_type="NETWORK_LSA"), 0
        )

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(_LSDB_DATA))
    def test_get_lsdb_lsa_count_unknown_area(self):
        self.assertEqual(get_ospf_lsdb_lsa_count(Mock(), area="9"), 0)

    @patch("genie.libs.sdk.apis.arcos.ospf.get.ShowOspfLsdb",
           new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")))
    def test_get_lsdb_empty(self):
        self.assertEqual(get_ospf_lsdb(Mock()), {})
        self.assertEqual(get_ospf_lsdb_lsa_count(Mock()), 0)


class TestGetOspfRoute(unittest.TestCase):
    """get_ospf_route, get_ospf_routes (locally-imported
    ShowOspfGlobalRib parser)."""

    def test_get_route_found(self):
        with patch("genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
                   new=_parser_mock(_RIB_DATA)):
            route = get_ospf_route(Mock(), "4.4.4.4/32")
        self.assertEqual(route["metric"], 10)

    def test_get_route_not_found(self):
        with patch("genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
                   new=_parser_mock(_RIB_DATA)):
            self.assertIsNone(get_ospf_route(Mock(), "9.9.9.9/32"))

    def test_get_routes(self):
        with patch("genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
                   new=_parser_mock(_RIB_DATA)):
            routes = get_ospf_routes(Mock())
        self.assertEqual(len(routes), 2)

    def test_get_route_empty_parser(self):
        with patch(
            "genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
            new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")),
        ):
            self.assertIsNone(get_ospf_route(Mock(), "4.4.4.4/32"))

    def test_get_routes_empty_parser(self):
        with patch(
            "genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
            new=_parser_mock(raise_exc=SchemaEmptyParserError("empty")),
        ):
            self.assertEqual(get_ospf_routes(Mock()), {})

    def test_get_route_generic_exception(self):
        with patch(
            "genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
            new=_parser_mock(raise_exc=ValueError("boom")),
        ):
            self.assertIsNone(get_ospf_route(Mock(), "4.4.4.4/32"))

    def test_get_routes_generic_exception(self):
        with patch(
            "genie.libs.parser.arcos.show_ospf.ShowOspfGlobalRib",
            new=_parser_mock(raise_exc=ValueError("boom")),
        ):
            self.assertEqual(get_ospf_routes(Mock()), {})

    def test_get_route_import_error(self):
        name = "genie.libs.parser.arcos.show_ospf"
        with patch.dict(sys.modules, {name: None}):
            self.assertIsNone(get_ospf_route(Mock(), "4.4.4.4/32"))

    def test_get_routes_import_error(self):
        name = "genie.libs.parser.arcos.show_ospf"
        with patch.dict(sys.modules, {name: None}):
            self.assertEqual(get_ospf_routes(Mock()), {})


class TestOspfGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    ospf/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ospf_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ospf_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered OSPF get functions: {missing}")

        print(
            f"\nOSPF get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
