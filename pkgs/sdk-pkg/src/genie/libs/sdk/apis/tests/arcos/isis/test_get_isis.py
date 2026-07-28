#!/usr/bin/env python3
"""Unit tests for arcOS ISIS get APIs (full coverage).

Uses a dummy device whose ``parse()`` returns pre-canned parser output (matching
the arcOS ISIS parser model), so the get helpers are exercised without a real
device. Mirrors the arcos/route_policy API test style.

isis/get.py has two call shapes:

* Most helpers call ``device.parse(<cmd>)`` directly -- a ``_DummyDevice``
  stub returning a canned dict exercises these.
* A subset (``get_isis_route``, the flex-algo helpers, ``get_isis_fast_reroute``,
  ``get_isis_protection_trackers``, ``get_isis_micro_loop_avoidance``) do a
  *local* ``from genie.libs.parser.arcos.show_isis import ShowX`` inside the
  function body and call ``ShowX(device=device).parse(...)`` directly (no
  ``output=`` passed in, so ``device.parse()`` is never invoked). Because the
  import happens fresh on every call, the patch target must be the parser's
  *home* module (``genie.libs.parser.arcos.show_isis.ShowX``), not the API
  module -- patching the API module's namespace would have no effect since
  nothing is ever imported into it.

A machine coverage check (``TestGetIsisCoverage``) at the bottom asserts every
public ``get_*``/``is_*`` function in ``isis/get.py`` is referenced by name
somewhere in this test file's source -- an order-safe source-scan (mirrors
``ospf/test_get_ospf.py``) instead of a runtime call-recording wrapper, since
the latter is order-dependent under `python -m unittest`'s alphabetical
class ordering.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.isis.get as get_module
from genie.libs.sdk.apis.arcos.isis.get import (
    get_isis_net,
    get_isis_system_id,
    get_isis_adjacency,
    get_isis_adjacency_count,
    is_isis_adjacency_present,
    get_isis_adjacency_state,
    get_isis_interface,
    get_isis_routes,
    get_isis_global,
    get_isis_route,
    get_isis_lsp_count,
    get_isis_redis_route,
    get_isis_redis_routes,
    get_isis_redis_route_source,
    get_isis_lsp,
    get_isis_global_timers,
    get_isis_flex_algo_routes,
    get_isis_flex_algo_route,
    get_isis_flex_algo_route_count,
    is_isis_flex_algo_route_present,
    get_isis_flex_algo_fast_reroute,
    get_isis_flex_algo_definitions,
    get_isis_flex_algo_definition,
    get_isis_flex_algo_fast_reroutes,
    is_isis_flex_algo_fast_reroute_present,
    get_isis_fast_reroute,
    get_isis_protection_trackers,
    get_isis_micro_loop_avoidance,
    get_isis_mla_status_timestamp,
)


# Combined parsed structure: get_isis_net/system_id read ["global"];
# get_isis_adjacency reads ["interface"] under isis[<instance>]. Extended
# (census backfill) with "interfaces" (get_isis_interface), "routes"
# (get_isis_routes), "redistribute-routes" (get_isis_redis_route*),
# "database" (get_isis_lsp*), and "global"."timers" (get_isis_global_timers)
# -- all siblings under the same isis[<instance>] dict, so device.parse()
# (which ignores the command string and returns this fixture unconditionally)
# serves every device.parse()-based helper from one shared fixture.
_PARSED = {
    "network-instance": {
        "default": {
            "isis": {
                "default": {
                    "global": {
                        "net": ["49.0000.0000.0000.0005.00"],
                        "system-id": "0000.0000.0005",
                    },
                    "timers": {
                        "lsp-lifetime-interval": 1200,
                        "lsp-refresh-interval": 600,
                        "lsp-flood-delay-adj-up": 0,
                        "spf": {
                            "spf-hold-interval": "5000",
                            "spf-first-interval": "50",
                            "spf-second-interval": "200",
                            "spf-mla-interval": "25",
                        },
                    },
                    "interface": {
                        "swp1": {
                            "level": {
                                2: {
                                    "adjacency": {
                                        "rtr2": {
                                            "state": "UP",
                                            "adjacency-type": "LEVEL_2",
                                        }
                                    }
                                }
                            }
                        },
                        "swp2": {
                            "level": {
                                1: {
                                    "adjacency": {
                                        "rtr3": {"state": "UP"}
                                    }
                                }
                            }
                        },
                    },
                    "interfaces": {
                        "swp1": {
                            "enabled": True,
                            "circuit_type": "level-2",
                            "mtu": 1500,
                            "network_type": "point-to-point",
                        },
                    },
                    "routes": {
                        "IPV4-UNICAST": {
                            "afi-name": "IPV4",
                            "safi-name": "UNICAST",
                            "routes": {
                                "5.5.5.5/32": {
                                    "prefix": "5.5.5.5/32",
                                    "best-level-number": 2,
                                    "levels": {
                                        "2": {
                                            "level-number": 2,
                                            "metric": 20,
                                        }
                                    },
                                },
                            },
                        },
                    },
                    "redistribute-routes": {
                        "IPV4-UNICAST": {
                            "afi-name": "IPV4",
                            "safi-name": "UNICAST",
                            "routes": {
                                "100.100.100.0/24": {
                                    "prefix": "100.100.100.0/24",
                                    "levels": {
                                        "2": {
                                            "source-identifier": "STATIC",
                                            "route-tag": 1000,
                                            "metric": 10,
                                        }
                                    },
                                },
                            },
                        },
                    },
                    "database": {
                        "rtr1.00-00": {
                            "lsp-id": "rtr1.00-00",
                            "sequence": 5,
                            "checksum": 1234,
                            "remaining-lifetime": 1180,
                        },
                        "rtr2.00-00": {
                            "lsp-id": "rtr2.00-00",
                            "sequence": 3,
                            "checksum": 5678,
                            "remaining-lifetime": 1190,
                        },
                    },
                }
            }
        }
    }
}


class _DummyDevice:
    """Returns a fixed parsed dict, or raises, from parse()."""

    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestGetIsisData(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_isis_net(self):
        self.assertEqual(get_isis_net(self.device), "49.0000.0000.0000.0005.00")

    def test_get_isis_system_id(self):
        self.assertEqual(get_isis_system_id(self.device), "0000.0000.0005")

    def test_get_isis_adjacency_all(self):
        result = get_isis_adjacency(self.device)
        self.assertIn("interface", result)
        self.assertEqual(set(result["interface"]), {"swp1", "swp2"})

    def test_get_isis_adjacency_interface_filter(self):
        result = get_isis_adjacency(self.device, interface="swp1")
        self.assertEqual(set(result["interface"]), {"swp1"})

    def test_get_isis_adjacency_interface_filter_miss(self):
        # No match -> empty dict (helper returns {} when nothing matches).
        result = get_isis_adjacency(self.device, interface="swp9")
        self.assertEqual(result, {})

    def test_get_isis_adjacency_count(self):
        self.assertEqual(get_isis_adjacency_count(self.device), 2)

    def test_get_isis_adjacency_count_interface(self):
        self.assertEqual(
            get_isis_adjacency_count(self.device, interface="swp1"), 1
        )


class TestGetIsisEmpty(unittest.TestCase):
    """Empty / no-data behavior: helpers degrade to None / empty, not raise."""

    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_get_isis_net_none(self):
        self.assertIsNone(get_isis_net(self.device))

    def test_get_isis_system_id_none(self):
        self.assertIsNone(get_isis_system_id(self.device))

    def test_get_isis_adjacency_empty(self):
        self.assertEqual(get_isis_adjacency(self.device), {})

    def test_get_isis_adjacency_count_zero(self):
        self.assertEqual(get_isis_adjacency_count(self.device), 0)


# ---------------------------------------------------------------------------
# Census-backfill additions: remaining device.parse()-based helpers.
# ---------------------------------------------------------------------------


class TestGetIsisMoreDeviceParse(unittest.TestCase):
    """Positive-path coverage for the remaining device.parse()-based get/is_ helpers."""

    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_is_isis_adjacency_present_true(self):
        self.assertTrue(is_isis_adjacency_present(self.device, adjacency="rtr2"))

    def test_is_isis_adjacency_present_false(self):
        self.assertFalse(is_isis_adjacency_present(self.device, adjacency="rtrX"))

    def test_get_isis_adjacency_state(self):
        self.assertEqual(
            get_isis_adjacency_state(self.device, adjacency="rtr2"), "UP"
        )

    def test_get_isis_adjacency_state_missing(self):
        self.assertIsNone(
            get_isis_adjacency_state(self.device, adjacency="rtrX")
        )

    def test_get_isis_interface(self):
        result = get_isis_interface(self.device, "swp1")
        self.assertEqual(result["mtu"], 1500)

    def test_get_isis_interface_missing(self):
        self.assertIsNone(get_isis_interface(self.device, "swp9"))

    def test_get_isis_routes(self):
        routes = get_isis_routes(self.device, address_family="ipv4")
        self.assertIn("5.5.5.5/32", routes)

    def test_get_isis_routes_bad_af(self):
        with self.assertRaises(ValueError):
            get_isis_routes(self.device, address_family="ipv5")

    def test_get_isis_global(self):
        result = get_isis_global(self.device)
        self.assertEqual(result["system-id"], "0000.0000.0005")

    def test_get_isis_lsp_count(self):
        self.assertEqual(get_isis_lsp_count(self.device, level="1"), 2)
        self.assertEqual(get_isis_lsp_count(self.device, level="level-2"), 2)

    def test_get_isis_lsp_count_bad_level(self):
        self.assertEqual(get_isis_lsp_count(self.device, level="bogus"), 0)

    def test_get_isis_lsp(self):
        lsps = get_isis_lsp(self.device)
        self.assertEqual(len(lsps), 2)

    def test_get_isis_lsp_filtered(self):
        lsps = get_isis_lsp(self.device, lsp_id="rtr1")
        self.assertEqual(len(lsps), 1)
        self.assertEqual(lsps[0]["lsp-id"], "rtr1.00-00")

    def test_get_isis_lsp_bad_level(self):
        self.assertEqual(get_isis_lsp(self.device, level="bogus"), [])

    def test_get_isis_redis_route(self):
        route = get_isis_redis_route(self.device, "100.100.100.0/24")
        self.assertEqual(route["prefix"], "100.100.100.0/24")

    def test_get_isis_redis_route_missing(self):
        self.assertIsNone(get_isis_redis_route(self.device, "9.9.9.9/32"))

    def test_get_isis_redis_routes(self):
        routes = get_isis_redis_routes(self.device)
        self.assertEqual(len(routes), 1)

    def test_get_isis_redis_route_source(self):
        source = get_isis_redis_route_source(self.device, "100.100.100.0/24")
        self.assertEqual(source["source_protocol"], "STATIC")
        self.assertEqual(source["tag"], 1000)
        self.assertEqual(source["metric"], 10)
        self.assertTrue(source["is_redistributed"])

    def test_get_isis_redis_route_source_missing(self):
        self.assertIsNone(
            get_isis_redis_route_source(self.device, "9.9.9.9/32")
        )

    def test_get_isis_global_timers(self):
        timers = get_isis_global_timers(self.device)
        self.assertEqual(timers["lsp-refresh-interval"], 600)


class TestGetIsisMoreEmpty(unittest.TestCase):
    """Degrade paths (SchemaEmptyParserError) for the same helpers."""

    def setUp(self):
        self.device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))

    def test_is_isis_adjacency_present_false(self):
        self.assertFalse(is_isis_adjacency_present(self.device, adjacency="rtr2"))

    def test_get_isis_adjacency_state_none(self):
        self.assertIsNone(get_isis_adjacency_state(self.device, adjacency="rtr2"))

    def test_get_isis_interface_none(self):
        self.assertIsNone(get_isis_interface(self.device, "swp1"))

    def test_get_isis_routes_empty(self):
        self.assertEqual(get_isis_routes(self.device), {})

    def test_get_isis_global_empty(self):
        self.assertEqual(get_isis_global(self.device), {})

    def test_get_isis_lsp_count_zero(self):
        self.assertEqual(get_isis_lsp_count(self.device, level="1"), 0)

    def test_get_isis_lsp_empty(self):
        self.assertEqual(get_isis_lsp(self.device), [])

    def test_get_isis_redis_route_none(self):
        self.assertIsNone(get_isis_redis_route(self.device, "100.100.100.0/24"))

    def test_get_isis_redis_routes_empty(self):
        self.assertEqual(get_isis_redis_routes(self.device), [])

    def test_get_isis_redis_route_source_none(self):
        self.assertIsNone(
            get_isis_redis_route_source(self.device, "100.100.100.0/24")
        )

    def test_get_isis_global_timers_empty(self):
        self.assertEqual(get_isis_global_timers(self.device), {})


class TestGetIsisSubCommandFailure(unittest.TestCase):
    """SubCommandFailure degrade path for the helpers that explicitly catch it."""

    def setUp(self):
        self.device = _DummyDevice(raise_exc=SubCommandFailure("boom"))

    def test_get_isis_adjacency_subcommand_failure(self):
        self.assertEqual(get_isis_adjacency(self.device), {})

    def test_get_isis_global_timers_subcommand_failure(self):
        self.assertEqual(get_isis_global_timers(self.device), {})


# ---------------------------------------------------------------------------
# Census-backfill additions: helpers that do a local parser-class import and
# call ShowX(device=device).parse(...) directly. Patch target is the parser's
# home module (genie.libs.parser.arcos.show_isis.ShowX), since the import
# happens fresh inside the function body on every call.
# ---------------------------------------------------------------------------

PARSER_MODULE = "genie.libs.parser.arcos.show_isis"


class TestGetIsisRoute(unittest.TestCase):
    """get_isis_route -- patches ShowIsisRoute."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisRoute")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    def _parsed(self, prefix="5.5.5.5/32", second_prefix=None):
        routes = {
            prefix: {
                "prefix": prefix,
                "best-level-number": 2,
                "levels": {
                    "2": {
                        "level-number": 2,
                        "metric": 20,
                        "next-hops": [
                            {
                                "next-hop-address": "10.1.5.5",
                                "outgoing-interface": "swp1",
                            },
                            {
                                "next-hop-address": "10.2.5.5",
                                "outgoing-interface": "swp2",
                                "backup": True,
                            },
                        ],
                    }
                },
            }
        }
        if second_prefix:
            routes[second_prefix] = {
                "prefix": second_prefix,
                "best-level-number": 1,
                "levels": {"1": {"level-number": 1, "metric": 10}},
            }
        return {
            "network-instance": {
                "default": {
                    "isis": {
                        "default": {
                            "routes": {
                                "IPV4-UNICAST": {
                                    "afi-name": "IPV4",
                                    "safi-name": "UNICAST",
                                    "routes": routes,
                                }
                            }
                        }
                    }
                }
            }
        }

    def test_get_isis_route_found(self):
        self._patch(return_value=self._parsed())
        route = get_isis_route(None, "5.5.5.5/32")
        self.assertIsNotNone(route)
        self.assertEqual(route["best-level-number"], 2)

    def test_get_isis_route_not_found(self):
        # Two routes present (so the "len==1" fallback doesn't kick in) and
        # neither matches, even fuzzily, the requested prefix.
        self._patch(
            return_value=self._parsed(
                prefix="5.5.5.5/32", second_prefix="7.7.7.7/32"
            )
        )
        self.assertIsNone(get_isis_route(None, "9.9.9.9/32"))

    def test_get_isis_route_single_fallback(self):
        # Exactly one route present, keyed differently than requested prefix.
        self._patch(return_value=self._parsed(prefix="7.7.7.7/32"))
        route = get_isis_route(None, "7.7.7.7")
        self.assertIsNotNone(route)
        self.assertEqual(route["prefix"], "7.7.7.7/32")

    def test_get_isis_route_schema_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_isis_route(None, "5.5.5.5/32"))

    def test_get_isis_route_bad_af(self):
        with self.assertRaises(ValueError):
            get_isis_route(None, "5.5.5.5/32", address_family="ipv5")

    def test_get_isis_route_unexpected_exception(self):
        self._patch(side_effect=ValueError("boom"))
        self.assertIsNone(get_isis_route(None, "5.5.5.5/32"))


class TestGetIsisFlexAlgoRoute(unittest.TestCase):
    """get_isis_flex_algo_routes/route/route_count/is_present -- patches ShowIsisFlexAlgoRoute."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisFlexAlgoRoute")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "flex-algo-routes": {
                            "IPV4-UNICAST": {
                                "afi-name": "IPV4",
                                "safi-name": "UNICAST",
                                "algorithms": {
                                    "128": {
                                        "id": 128,
                                        "routes": {
                                            "10.0.0.0/24": {
                                                "prefix": "10.0.0.0/24",
                                                "best-level-number": 2,
                                            }
                                        },
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_flex_algo_routes(self):
        self._patch(return_value=self.PARSED)
        result = get_isis_flex_algo_routes(None)
        self.assertIn("IPV4-UNICAST", result)

    def test_get_isis_flex_algo_routes_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_flex_algo_routes(None), {})

    def test_get_isis_flex_algo_route_found(self):
        self._patch(return_value=self.PARSED)
        route = get_isis_flex_algo_route(None, "10.0.0.0/24")
        self.assertIsNotNone(route)
        self.assertEqual(route["best-level-number"], 2)

    def test_get_isis_flex_algo_route_not_found(self):
        self._patch(return_value=self.PARSED)
        self.assertIsNone(get_isis_flex_algo_route(None, "9.9.9.9/32"))

    def test_get_isis_flex_algo_route_count(self):
        self._patch(return_value=self.PARSED)
        self.assertEqual(get_isis_flex_algo_route_count(None), 1)

    def test_is_isis_flex_algo_route_present_true(self):
        self._patch(return_value=self.PARSED)
        self.assertTrue(is_isis_flex_algo_route_present(None, "10.0.0.0/24"))

    def test_is_isis_flex_algo_route_present_false(self):
        self._patch(return_value=self.PARSED)
        self.assertFalse(is_isis_flex_algo_route_present(None, "9.9.9.9/32"))


class TestGetIsisFlexAlgoFastReroute(unittest.TestCase):
    """flex-algo FRR helpers -- patches ShowIsisFlexAlgoFastReroute."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisFlexAlgoFastReroute")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "flex-algo-fast-reroute": {
                            "IPV4-UNICAST": {
                                "afi-name": "IPV4",
                                "safi-name": "UNICAST",
                                "algorithms": {
                                    "128": {
                                        "id": 128,
                                        "prefixes": {
                                            "3.3.3.3/32": {
                                                "prefix": "3.3.3.3/32",
                                                "levels": {
                                                    "2": {
                                                        "level-number": 2,
                                                        "reroute-type": "TI_LFA",
                                                        "metric": 30,
                                                        "nexthop-address": "10.2.3.3",
                                                        "nexthop-interface": "swp2",
                                                        "flags": [],
                                                        "last-updated-time": "",
                                                        "origin-system-id": "rtr3.00",
                                                    }
                                                },
                                            }
                                        },
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_flex_algo_fast_reroute(self):
        self._patch(return_value=self.PARSED)
        result = get_isis_flex_algo_fast_reroute(None)
        self.assertIn("IPV4-UNICAST", result)

    def test_get_isis_flex_algo_fast_reroute_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_flex_algo_fast_reroute(None), {})

    def test_get_isis_flex_algo_fast_reroutes(self):
        self._patch(return_value=self.PARSED)
        prefixes = get_isis_flex_algo_fast_reroutes(None, algo=128)
        self.assertIn("3.3.3.3/32", prefixes)

    def test_get_isis_flex_algo_fast_reroutes_missing_algo(self):
        self._patch(return_value=self.PARSED)
        self.assertEqual(
            get_isis_flex_algo_fast_reroutes(None, algo=200), {}
        )

    def test_is_isis_flex_algo_fast_reroute_present_true(self):
        self._patch(return_value=self.PARSED)
        self.assertTrue(
            is_isis_flex_algo_fast_reroute_present(None, "3.3.3.3/32", algo=128)
        )

    def test_is_isis_flex_algo_fast_reroute_present_false(self):
        self._patch(return_value=self.PARSED)
        self.assertFalse(
            is_isis_flex_algo_fast_reroute_present(None, "9.9.9.9/32", algo=128)
        )


class TestGetIsisFlexAlgoDefinitions(unittest.TestCase):
    """get_isis_flex_algo_definitions/definition -- patches ShowIsisConfig."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisConfig")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "config": {
                            "global": {
                                "flexible-algorithms": {
                                    "128": {
                                        "id": 128,
                                        "advertise-definition-enabled": True,
                                        "metric-type": "IGP",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_flex_algo_definitions(self):
        self._patch(return_value=self.PARSED)
        definitions = get_isis_flex_algo_definitions(None)
        self.assertIn("128", definitions)

    def test_get_isis_flex_algo_definitions_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_flex_algo_definitions(None), {})

    def test_get_isis_flex_algo_definition_found(self):
        self._patch(return_value=self.PARSED)
        definition = get_isis_flex_algo_definition(None, 128)
        self.assertIsNotNone(definition)
        self.assertEqual(definition["metric-type"], "IGP")

    def test_get_isis_flex_algo_definition_not_found(self):
        self._patch(return_value=self.PARSED)
        self.assertIsNone(get_isis_flex_algo_definition(None, 200))


class TestGetIsisFastReroute(unittest.TestCase):
    """get_isis_fast_reroute -- patches ShowIsisFastReroute."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisFastReroute")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "fast-reroute": {
                            "IPV4-UNICAST": {
                                "afi-name": "IPV4",
                                "safi-name": "UNICAST",
                                "prefixes": {
                                    "6.6.6.6/32": {
                                        "prefix": "6.6.6.6/32",
                                        "levels": {
                                            "2": {
                                                "level-number": 2,
                                                "reroute-type": "TI_LFA",
                                                "metric": 30,
                                                "nexthop-address": "10.2.6.6",
                                                "nexthop-interface": "swp2",
                                                "flags": [],
                                                "last-updated-time": "",
                                                "origin-system-id": "rtr6.00",
                                                "pq-node-system-id": "rtr3.00",
                                            }
                                        },
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_fast_reroute(self):
        self._patch(return_value=self.PARSED)
        entries = get_isis_fast_reroute(None, prefix="6.6.6.6/32")
        self.assertIn("6.6.6.6/32", entries)

    def test_get_isis_fast_reroute_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_fast_reroute(None), {})

    def test_get_isis_fast_reroute_subcommand_failure(self):
        self._patch(side_effect=SubCommandFailure("boom"))
        self.assertEqual(get_isis_fast_reroute(None), {})

    def test_get_isis_fast_reroute_bad_af(self):
        with self.assertRaises(ValueError):
            get_isis_fast_reroute(None, address_family="ipv5")


class TestGetIsisProtectionTrackers(unittest.TestCase):
    """get_isis_protection_trackers -- patches ShowIsisProtectionTracker."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisProtectionTracker")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "global": {
                            "protection-trackers": {
                                "protection-tracker": {
                                    "1": {
                                        "id": 1,
                                        "reference-count": 2,
                                        "interface": "swp1",
                                        "system-id": "rtr2.00",
                                        "last-updated-time": "2026-01-01T00:00:00Z",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_protection_trackers(self):
        self._patch(return_value=self.PARSED)
        trackers = get_isis_protection_trackers(None)
        self.assertIn("1", trackers)
        self.assertEqual(trackers["1"]["interface"], "swp1")

    def test_get_isis_protection_trackers_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_protection_trackers(None), {})

    def test_get_isis_protection_trackers_subcommand_failure(self):
        self._patch(side_effect=SubCommandFailure("boom"))
        self.assertEqual(get_isis_protection_trackers(None), {})


class TestGetIsisMicroLoopAvoidance(unittest.TestCase):
    """get_isis_micro_loop_avoidance / get_isis_mla_status_timestamp -- patches
    ShowIsisMicroLoopAvoidance."""

    def _patch(self, return_value=None, side_effect=None):
        patcher = patch(f"{PARSER_MODULE}.ShowIsisMicroLoopAvoidance")
        mock_cls = patcher.start()
        self.addCleanup(patcher.stop)
        if side_effect is not None:
            mock_cls.return_value.parse.side_effect = side_effect
        else:
            mock_cls.return_value.parse.return_value = return_value
        return mock_cls

    PARSED = {
        "network-instance": {
            "default": {
                "isis": {
                    "default": {
                        "global": {
                            "micro-loop-avoidance": {
                                "srv6-enabled": True,
                                "rib-update-delay": 500,
                                "status": {
                                    "0-0-MT-0": {
                                        "algo": 0,
                                        "level": 0,
                                        "topology-id": "MT-0",
                                        "mla-state": "ACTIVE",
                                        "last-event": "LINK-DOWN",
                                        "near-node": "rtr1",
                                        "far-node": "rtr2",
                                        "spf-start-timestamp": "2026-01-01T00:00:00Z",
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }

    def test_get_isis_micro_loop_avoidance(self):
        self._patch(return_value=self.PARSED)
        mla = get_isis_micro_loop_avoidance(None)
        self.assertTrue(mla["srv6-enabled"])
        self.assertIn("status", mla)

    def test_get_isis_micro_loop_avoidance_empty(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_micro_loop_avoidance(None), {})

    def test_get_isis_micro_loop_avoidance_subcommand_failure(self):
        self._patch(side_effect=SubCommandFailure("boom"))
        self.assertEqual(get_isis_micro_loop_avoidance(None), {})

    def test_get_isis_mla_status_timestamp_found(self):
        self._patch(return_value=self.PARSED)
        self.assertEqual(
            get_isis_mla_status_timestamp(None, algo=0),
            "2026-01-01T00:00:00Z",
        )

    def test_get_isis_mla_status_timestamp_no_row(self):
        self._patch(return_value=self.PARSED)
        self.assertEqual(get_isis_mla_status_timestamp(None, algo=99), "")

    def test_get_isis_mla_status_timestamp_error(self):
        self._patch(side_effect=SchemaEmptyParserError("empty"))
        self.assertEqual(get_isis_mla_status_timestamp(None, algo=0), "")


# ---------------------------------------------------------------------------
# Machine coverage check.
# ---------------------------------------------------------------------------


class TestGetIsisCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    isis/get.py must be referenced by name somewhere in this test file's
    source. Order-safe under both pytest and `python -m unittest`
    (alphabetical class order), since it scans source text instead of
    relying on side effects from other test classes having already run.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        public_fns = {
            name
            for name in dir(get_module)
            if callable(getattr(get_module, name))
            and (name.startswith("get_") or name.startswith("is_"))
            and getattr(getattr(get_module, name), "__module__", None)
            == get_module.__name__
        }
        missing = [n for n in public_fns if n not in source]
        self.assertEqual(
            missing,
            [],
            f"Untested public get_/is_ functions in isis/get.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
