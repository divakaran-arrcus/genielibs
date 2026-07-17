#!/usr/bin/env python3
"""Unit tests for arcOS Telemetry get APIs (full coverage).

genie.libs.sdk.apis.arcos.telemetry.get.get_telemetry_state instantiates
``genie.libs.parser.arcos.show_telemetry.ShowTelemetry`` directly (bypassing
``device.parse``) and calls ``.parse()`` on it. Tests therefore patch the
``ShowTelemetry`` name as imported into the ``get`` module and return canned
parser output shaped like the real ``ShowTelemetry`` schema.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.telemetry import get as telemetry_get
from genie.libs.sdk.apis.arcos.telemetry.get import get_telemetry_state

MOD = "genie.libs.sdk.apis.arcos.telemetry.get"

CANNED_OUTPUT = {
    "status": "on",
    "cuid": "CUST123",
    "destination-groups": {
        "DG1": {
            "name": "DG1",
            "destinations": ["10.0.0.5:50051"],
        },
    },
    "subscriptions": {
        "SUB1": {
            "name": "SUB1",
            "sensors": ["interfaces", "isis"],
            "destination-group": "DG1",
        },
    },
}


class TestGetTelemetry(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowTelemetry")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_telemetry_state(self):
        result = get_telemetry_state(self.device)
        self.assertEqual(result["status"], "on")
        self.assertEqual(result["cuid"], "CUST123")
        self.assertIn("DG1", result["destination-groups"])
        self.assertEqual(
            result["destination-groups"]["DG1"]["destinations"],
            ["10.0.0.5:50051"],
        )
        self.assertIn("SUB1", result["subscriptions"])
        self.assertEqual(
            result["subscriptions"]["SUB1"]["sensors"], ["interfaces", "isis"]
        )
        self.assertEqual(
            result["subscriptions"]["SUB1"]["destination-group"], "DG1"
        )


class TestGetTelemetryEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- get_telemetry_state should
    degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowTelemetry")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )

    def test_get_telemetry_state_empty(self):
        self.assertEqual(get_telemetry_state(self.device), {})


class TestGetTelemetryGenericException(unittest.TestCase):
    """Any unexpected exception from the parser should also degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowTelemetry")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = RuntimeError("boom")

    def test_get_telemetry_state_generic_exception(self):
        self.assertEqual(get_telemetry_state(self.device), {})


class TestTelemetryGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    telemetry/get.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(telemetry_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == telemetry_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Telemetry get functions: {missing}")

        print(
            f"\nTelemetry get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
