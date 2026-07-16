#!/usr/bin/env python3
"""Unit tests for arcOS LDP get APIs (full coverage).

The LDP get helpers instantiate the ``ShowLdpInterface`` / ``ShowLdpSession``
/ ``ShowLdpNeighbor`` parser classes directly (Genie's device.parse() lookup
does not auto-discover arcOS parsers) and call ``.parse()`` on the instance.
Tests patch the parser classes where they are imported into the ``get``
module and use a lightweight dummy device.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.ldp.get import (
    get_ldp_interfaces,
    get_ldp_sessions,
    get_ldp_session,
    get_ldp_session_state,
    get_ldp_neighbors,
    get_ldp_session_count,
)

MOD = "genie.libs.sdk.apis.arcos.ldp.get"

# ---------------------------------------------------------------------------
# Canned parser output (matches ShowLdpInterface / ShowLdpSession /
# ShowLdpNeighbor schemas in genie.libs.parser.arcos.show_ldp)
# ---------------------------------------------------------------------------

INTERFACES_OUTPUT = {
    "interfaces": {
        "swp1": {
            "interface-id": "swp1",
            "hello-holdtime": 15,
            "hello-interval": 5,
            "link-hello": True,
            "address-families": {
                "IPV4": {"afi-name": "IPV4", "enabled": True},
            },
        },
        "swp2": {
            "interface-id": "swp2",
            "link-hello": True,
        },
    }
}

SESSIONS_OUTPUT = {
    "sessions": {
        "1.1.1.1": {
            "peer-address": "1.1.1.1",
            "local-address": "2.2.2.2",
            "session-state": "Operational",
            "session-role": "ACTIVE",
            "local-lsr-id": "2.2.2.2",
            "remote-lsr-id": "1.1.1.1",
        },
        "3.3.3.3": {
            "peer-address": "3.3.3.3",
            "session-state": "Nonexistent",
        },
    }
}

NEIGHBORS_OUTPUT = {
    "neighbors": {
        "1.1.1.1/0": {
            "lsr-id": "1.1.1.1",
            "label-space-id": 0,
            "auth-enable": True,
            "targeted-hello-holdtime": 45,
            "targeted-address-families": {
                "IPV4": {
                    "afi-name": "IPV4",
                    "enabled": True,
                    "destination-address": "1.1.1.1",
                },
            },
        },
    }
}


class _DummyDevice:
    def __init__(self):
        self.name = "rtr1"


class TestGetLdpInterfaces(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpInterface")
    def test_get_ldp_interfaces(self, mock_parser):
        mock_parser.return_value.parse.return_value = INTERFACES_OUTPUT
        result = get_ldp_interfaces(self.device)
        self.assertIn("swp1", result)
        self.assertEqual(result["swp1"]["hello-holdtime"], 15)
        self.assertIn("swp2", result)

    @patch(f"{MOD}.ShowLdpInterface")
    def test_get_ldp_interfaces_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_ldp_interfaces(self.device), {})

    @patch(f"{MOD}.ShowLdpInterface")
    def test_get_ldp_interfaces_generic_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("boom")
        self.assertEqual(get_ldp_interfaces(self.device), {})


class TestGetLdpSessions(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_sessions(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        result = get_ldp_sessions(self.device)
        self.assertIn("1.1.1.1", result)
        self.assertIn("3.3.3.3", result)
        self.assertEqual(result["1.1.1.1"]["session-state"], "Operational")

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_sessions_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_ldp_sessions(self.device), {})

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_sessions_generic_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("boom")
        self.assertEqual(get_ldp_sessions(self.device), {})


class TestGetLdpSession(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_found(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        result = get_ldp_session(self.device, "1.1.1.1")
        self.assertEqual(result["peer-address"], "1.1.1.1")

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_not_found(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        self.assertIsNone(get_ldp_session(self.device, "9.9.9.9"))

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertIsNone(get_ldp_session(self.device, "1.1.1.1"))


class TestGetLdpSessionState(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_state_found(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        self.assertEqual(
            get_ldp_session_state(self.device, "1.1.1.1"), "Operational")

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_state_not_found(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        self.assertIsNone(get_ldp_session_state(self.device, "9.9.9.9"))

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_state_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertIsNone(get_ldp_session_state(self.device, "1.1.1.1"))


class TestGetLdpNeighbors(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpNeighbor")
    def test_get_ldp_neighbors(self, mock_parser):
        mock_parser.return_value.parse.return_value = NEIGHBORS_OUTPUT
        result = get_ldp_neighbors(self.device)
        self.assertIn("1.1.1.1/0", result)
        self.assertTrue(result["1.1.1.1/0"]["auth-enable"])

    @patch(f"{MOD}.ShowLdpNeighbor")
    def test_get_ldp_neighbors_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_ldp_neighbors(self.device), {})

    @patch(f"{MOD}.ShowLdpNeighbor")
    def test_get_ldp_neighbors_generic_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = Exception("boom")
        self.assertEqual(get_ldp_neighbors(self.device), {})


class TestGetLdpSessionCount(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_count(self, mock_parser):
        mock_parser.return_value.parse.return_value = SESSIONS_OUTPUT
        self.assertEqual(get_ldp_session_count(self.device), 2)

    @patch(f"{MOD}.ShowLdpSession")
    def test_get_ldp_session_count_empty_parser_error(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty")
        self.assertEqual(get_ldp_session_count(self.device), 0)


class TestLdpGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_* function in
    ldp/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        from genie.libs.sdk.apis.arcos.ldp import get as ldp_get

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(ldp_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == ldp_get.__name__
            and name.startswith("get_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [], f"Uncovered LDP get functions: {missing}")

        print(f"\nLDP get coverage: {len(names)} total, 0 missing")


if __name__ == "__main__":
    unittest.main()
