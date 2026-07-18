#!/usr/bin/env python3
"""Unit tests for arcOS RSVP-TE get APIs (full coverage).

get.py's ``get_rsvp_global`` instantiates
``genie.libs.parser.arcos.show_rsvp_te.ShowRsvpGlobal`` directly (NOT
device.parse()), so tests patch ``ShowRsvpGlobal`` in the get module's
namespace and drive the public get_* helper off canned parser output that
matches the ShowRsvpGlobal schema.
"""

import unittest
from unittest.mock import patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.rsvp_te import get as rsvp_te_get
from genie.libs.sdk.apis.arcos.rsvp_te.get import get_rsvp_global

MOD = "genie.libs.sdk.apis.arcos.rsvp_te.get"

_PARSED = {
    "hello-supported": True,
    "hello-interval": 5,
    "refresh-reduction": True,
}

_PARSED_MINIMAL = {
    "hello-supported": False,
}


class _DummyDevice:
    """Placeholder device -- ShowRsvpGlobal is patched, so this is unused
    beyond being a valid argument."""
    name = "rtr1"


class TestGetRsvpGlobal(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice()

    @patch(f"{MOD}.ShowRsvpGlobal")
    def test_get_rsvp_global(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED
        result = get_rsvp_global(self.device)
        self.assertTrue(result["hello-supported"])
        self.assertEqual(result["hello-interval"], 5)
        self.assertTrue(result["refresh-reduction"])

    @patch(f"{MOD}.ShowRsvpGlobal")
    def test_get_rsvp_global_minimal(self, mock_parser):
        mock_parser.return_value.parse.return_value = _PARSED_MINIMAL
        result = get_rsvp_global(self.device)
        self.assertFalse(result["hello-supported"])
        self.assertNotIn("hello-interval", result)

    @patch(f"{MOD}.ShowRsvpGlobal")
    def test_get_rsvp_global_empty_on_schema_empty(self, mock_parser):
        mock_parser.return_value.parse.side_effect = SchemaEmptyParserError("empty")
        self.assertEqual(get_rsvp_global(self.device), {})

    @patch(f"{MOD}.ShowRsvpGlobal")
    def test_get_rsvp_global_empty_on_unexpected_exception(self, mock_parser):
        mock_parser.return_value.parse.side_effect = ValueError("boom")
        self.assertEqual(get_rsvp_global(self.device), {})


class TestRsvpTeGetFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    rsvp_te/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(rsvp_te_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == rsvp_te_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered RSVP-TE get/is functions: {missing}")

        print(
            f"\nRSVP-TE get/is coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
