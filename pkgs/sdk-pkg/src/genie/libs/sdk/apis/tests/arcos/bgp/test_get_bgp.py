#!/usr/bin/env python3
"""Unit tests for arcOS BGP get APIs.

The BGP get helpers instantiate the parser class directly
(``ShowBgpGlobalState(device).parse(...)``), so we patch the parser classes
where they are imported (in the parser module) and drive canned output.
"""

import unittest
from unittest.mock import patch, Mock

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.bgp.get import (
    get_bgp_global_state,
    get_bgp_as_number,
    get_bgp_router_id,
    get_bgp_neighbor_count,
    is_bgp_neighbor_present,
)

GS = "genie.libs.parser.arcos.show_bgp.ShowBgpGlobalState"
NB = "genie.libs.parser.arcos.show_bgp.ShowBgpNeighbor"

GLOBAL = {"as": 65001, "router-id": "1.1.1.1"}
NEIGHBORS = {
    "neighbors": {
        "10.0.0.2": {"state": "ESTABLISHED"},
        "10.0.0.3": {"state": "IDLE"},
    }
}


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


if __name__ == "__main__":
    unittest.main()
