#!/usr/bin/env python3
"""Unit tests for arcOS LLDP get APIs (full coverage).

Unlike most arcOS get helpers, the LLDP get functions instantiate the
``ShowLldpState`` / ``ShowLldpInterface`` parser classes directly (Genie's
device.parse() lookup does not auto-discover arcOS parsers) and call
``.parse()`` on the instance. Tests patch the parser classes where they are
imported into the ``get`` module and use a lightweight dummy device.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.lldp.get import (
    get_lldp_state,
    get_lldp_interface,
    get_lldp_neighbors,
    get_lldp_neighbor_count,
)

MOD = "genie.libs.sdk.apis.arcos.lldp.get"

# ---------------------------------------------------------------------------
# Canned parser output (matches ShowLldpState / ShowLldpInterface schemas)
# ---------------------------------------------------------------------------

STATE_OUTPUT = {
    "hello-timer": "30",
    "system-name": "rtr1",
    "system-description": "Arrcus ArcOS 5.2.0",
    "counters": {
        "frame-in": "1024",
        "frame-out": "980",
    },
}

INTERFACE_OUTPUT = {
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "mode": "TX_RX",
            "neighbors": {
                "nbr1": {
                    "id": "nbr1",
                    "system-name": "rtr2",
                    "chassis-id": "00:11:22:33:44:55",
                    "port-id": "swp2",
                },
            },
        },
        "swp2": {
            "name": "swp2",
            "enabled": True,
            "mode": "TX_RX",
            "neighbors": {
                "nbr2": {"id": "nbr2", "system-name": "rtr3"},
                "nbr3": {"id": "nbr3", "system-name": "rtr4"},
            },
        },
        "swp3": {
            "name": "swp3",
            "enabled": False,
            # no "neighbors" key at all
        },
    }
}

INTERFACE_OUTPUT_SINGLE = {
    "interfaces": {
        "swp1": {
            "name": "swp1",
            "enabled": True,
            "neighbors": {},
        },
    }
}


class _DummyDevice:
    def __init__(self):
        self.name = "rtr1"


class TestGetLldpState(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLldpState")
    def test_get_lldp_state(self, mock_parser):
        mock_parser.return_value.parse.return_value = STATE_OUTPUT
        result = get_lldp_state(self.device)
        self.assertEqual(result["hello-timer"], "30")
        self.assertEqual(result["system-name"], "rtr1")
        self.assertEqual(result["counters"]["frame-in"], "1024")

    @patch(f"{MOD}.ShowLldpState")
    def test_get_lldp_state_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_lldp_state(self.device), {})

    @patch(f"{MOD}.ShowLldpState")
    def test_get_lldp_state_generic_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("boom")
        self.assertEqual(get_lldp_state(self.device), {})


class TestGetLldpInterface(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_found(self, mock_parser):
        mock_parser.return_value.parse.return_value = INTERFACE_OUTPUT
        result = get_lldp_interface(self.device, "swp1")
        self.assertEqual(result["name"], "swp1")
        self.assertIn("nbr1", result["neighbors"])

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_fallback_single_entry(self, mock_parser):
        """Requested interface not present, but exactly one entry in the
        parsed result -- fallback returns that single entry."""
        mock_parser.return_value.parse.return_value = INTERFACE_OUTPUT_SINGLE
        result = get_lldp_interface(self.device, "swp99")
        self.assertEqual(result["name"], "swp1")

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_not_found_multi_entry(self, mock_parser):
        """Requested interface not present and more than one entry exists
        -- no fallback, returns None."""
        mock_parser.return_value.parse.return_value = INTERFACE_OUTPUT
        result = get_lldp_interface(self.device, "swp99")
        self.assertIsNone(result)

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertIsNone(get_lldp_interface(self.device, "swp1"))

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_subcommand_failure(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SubCommandFailure(
            "no such command")
        self.assertIsNone(get_lldp_interface(self.device, "swp1"))

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_interface_generic_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("boom")
        self.assertIsNone(get_lldp_interface(self.device, "swp1"))


class TestGetLldpNeighbors(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_neighbors_filters_empty(self, mock_parser):
        mock_parser.return_value.parse.return_value = INTERFACE_OUTPUT
        result = get_lldp_neighbors(self.device)
        # swp1 and swp2 have neighbors, swp3 has none (no key) -> excluded
        self.assertIn("swp1", result)
        self.assertIn("swp2", result)
        self.assertNotIn("swp3", result)

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_neighbors_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_lldp_neighbors(self.device), {})


class TestGetLldpNeighborCount(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_neighbor_count(self, mock_parser):
        mock_parser.return_value.parse.return_value = INTERFACE_OUTPUT
        # swp1: 1 neighbor, swp2: 2 neighbors, swp3: 0 -> total 3
        self.assertEqual(get_lldp_neighbor_count(self.device), 3)

    @patch(f"{MOD}.ShowLldpInterface")
    def test_get_lldp_neighbor_count_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_lldp_neighbor_count(self.device), 0)


if __name__ == "__main__":
    unittest.main()
