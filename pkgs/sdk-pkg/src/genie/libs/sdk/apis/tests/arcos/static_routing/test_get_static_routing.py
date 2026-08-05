#!/usr/bin/env python3
"""Unit tests for arcOS static routing get APIs (full coverage).

genie.libs.sdk.apis.arcos.static_routing.get instantiates the
ShowStaticRoutingConfig parser directly (`ShowStaticRoutingConfig(device=device)`)
and calls `.parse(network_instance=ni, protocol_instance=pi)` -- it never uses
device.parse()/device.execute() directly. Tests patch the parser class at the
module namespace and feed it canned data matching the parser's schema
(network-instances -> protocols -> static-routes -> next-hops).
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.static_routing.get import (
    get_static_routes,
    get_static_route,
    get_static_route_count,
    get_static_route_next_hops,
    get_static_route_tag,
    is_static_route_present,
)

MOD = "genie.libs.sdk.apis.arcos.static_routing.get"

PARSED_OUTPUT = {
    "network-instances": {
        "default": {
            "protocols": {
                "default": {
                    "identifier": "STATIC",
                    "name": "default",
                    "static-routes": {
                        "10.0.0.0/8": {
                            "prefix": "10.0.0.0/8",
                            "set-tag": 500,
                            "next-hops": {
                                "1": {
                                    "index": "1",
                                    "next-hop": "10.1.1.1",
                                    "interface": "swp1",
                                    "metric": 100,
                                }
                            },
                        },
                        "192.168.0.0/16": {
                            "prefix": "192.168.0.0/16",
                            "set-tag": "1000",
                            "next-hops": {
                                "1": {"index": "1", "next-hop": "DROP"}
                            },
                        },
                        "172.16.0.0/12": {
                            "prefix": "172.16.0.0/12",
                        },
                    },
                }
            }
        }
    }
}


import inspect
import genie.libs.sdk.apis.arcos.static_routing.get as get_module
def _device():
    d = Mock()
    d.name = "rtr1"
    return d


class TestGetStaticRoutes(unittest.TestCase):
    """get_static_routes / get_static_route / get_static_route_count /
    get_static_route_next_hops / is_static_route_present / get_static_route_tag
    -- happy path against canned parsed data."""

    def setUp(self):
        self.device = _device()
        patcher = patch(f"{MOD}.ShowStaticRoutingConfig")
        self.mock_parser_cls = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser_cls.return_value.parse.return_value = PARSED_OUTPUT

    def test_get_static_routes(self):
        routes = get_static_routes(self.device)
        self.assertEqual(
            set(routes), {"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
        )
        self.mock_parser_cls.assert_called_with(device=self.device)

    def test_get_static_routes_passes_ni_pi(self):
        get_static_routes(self.device, ni="vrf1", pi="pi1")
        self.mock_parser_cls.return_value.parse.assert_called_with(
            network_instance="vrf1", protocol_instance="pi1"
        )

    def test_get_static_route_found(self):
        route = get_static_route(self.device, "10.0.0.0/8")
        self.assertEqual(route["prefix"], "10.0.0.0/8")

    def test_get_static_route_not_found(self):
        self.assertIsNone(get_static_route(self.device, "9.9.9.0/24"))

    def test_get_static_route_count(self):
        self.assertEqual(get_static_route_count(self.device), 3)

    def test_get_static_route_next_hops_found(self):
        nh = get_static_route_next_hops(self.device, "10.0.0.0/8")
        self.assertEqual(nh["1"]["next-hop"], "10.1.1.1")

    def test_get_static_route_next_hops_route_missing(self):
        self.assertEqual(get_static_route_next_hops(self.device, "9.9.9.0/24"), {})

    def test_get_static_route_next_hops_no_next_hops_key(self):
        """172.16.0.0/12 has no 'next-hops' key at all -> {} via .get default."""
        self.assertEqual(
            get_static_route_next_hops(self.device, "172.16.0.0/12"), {}
        )

    def test_is_static_route_present_true(self):
        self.assertTrue(is_static_route_present(self.device, "10.0.0.0/8"))

    def test_is_static_route_present_false(self):
        self.assertFalse(is_static_route_present(self.device, "9.9.9.0/24"))

    def test_get_static_route_tag_int(self):
        self.assertEqual(get_static_route_tag(self.device, "10.0.0.0/8"), 500)

    def test_get_static_route_tag_string_cast_to_int(self):
        """set-tag stored as string '1000' must be cast to int."""
        tag = get_static_route_tag(self.device, "192.168.0.0/16")
        self.assertEqual(tag, 1000)
        self.assertIsInstance(tag, int)

    def test_get_static_route_tag_absent_on_route(self):
        """172.16.0.0/12 has no 'set-tag' key -> None."""
        self.assertIsNone(get_static_route_tag(self.device, "172.16.0.0/12"))

    def test_get_static_route_tag_route_missing(self):
        self.assertIsNone(get_static_route_tag(self.device, "9.9.9.0/24"))


class TestGetStaticRoutesEmptyAndErrors(unittest.TestCase):
    """_parse_static_routing exception handling: SchemaEmptyParserError,
    SubCommandFailure, and generic Exception all degrade to {}."""

    def setUp(self):
        self.device = _device()
        self.patcher = patch(f"{MOD}.ShowStaticRoutingConfig")
        self.mock_parser_cls = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_schema_empty_parser_error(self):
        self.mock_parser_cls.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )
        self.assertEqual(get_static_routes(self.device), {})

    def test_subcommand_failure(self):
        self.mock_parser_cls.return_value.parse.side_effect = SubCommandFailure(
            "cmd failed"
        )
        self.assertEqual(get_static_routes(self.device), {})

    def test_generic_exception(self):
        self.mock_parser_cls.return_value.parse.side_effect = Exception("boom")
        self.assertEqual(get_static_routes(self.device), {})

    def test_downstream_apis_degrade_gracefully_on_error(self):
        self.mock_parser_cls.return_value.parse.side_effect = Exception("boom")
        self.assertIsNone(get_static_route(self.device, "10.0.0.0/8"))
        self.assertEqual(get_static_route_count(self.device), 0)
        self.assertEqual(get_static_route_next_hops(self.device, "10.0.0.0/8"), {})
        self.assertFalse(is_static_route_present(self.device, "10.0.0.0/8"))
        self.assertIsNone(get_static_route_tag(self.device, "10.0.0.0/8"))

    def test_ni_not_present_in_parsed_output(self):
        """Query a network-instance absent from the parsed result -> {}."""
        self.mock_parser_cls.return_value.parse.return_value = PARSED_OUTPUT
        self.assertEqual(get_static_routes(self.device, ni="vrf-missing"), {})




class TestStaticRoutingGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get/is function in
    static_routing/get.py must be referenced by name somewhere in this test
    file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(get_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == get_module.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered static_routing get functions: {missing}")
if __name__ == "__main__":
    unittest.main()
