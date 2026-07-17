#!/usr/bin/env python3
"""Unit tests for arcOS sFlow get APIs (full coverage).

genie.libs.sdk.apis.arcos.sflow.get.get_sflow_state instantiates
``genie.libs.parser.arcos.show_sflow.ShowSflow`` directly (bypassing
``device.parse``) and calls ``.parse()`` on it. Tests therefore patch the
``ShowSflow`` name as imported into the ``get`` module and return canned
parser output shaped like the real ``ShowSflow`` schema.
"""

import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.sflow import get as sflow_get
from genie.libs.sdk.apis.arcos.sflow.get import get_sflow_state

MOD = "genie.libs.sdk.apis.arcos.sflow.get"

CANNED_OUTPUT = {
    "counter-sampling-interval": 30,
    "packet-sampling-rate": 1000,
    "network-instance": "default",
    "counter-samples": 100,
    "packet-samples": 200,
    "collectors": {
        "10.0.0.5:6343": {"address": "10.0.0.5", "port": 6343},
    },
    "interfaces": {
        "swp1": {"name": "swp1", "direction": "ingress",
                  "packet-sampling-rate": 500},
    },
}


class TestGetSflow(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowSflow")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_sflow_state(self):
        result = get_sflow_state(self.device)
        self.assertEqual(result["counter-sampling-interval"], 30)
        self.assertEqual(result["packet-sampling-rate"], 1000)
        self.assertEqual(result["network-instance"], "default")
        self.assertIn("10.0.0.5:6343", result["collectors"])
        self.assertIn("swp1", result["interfaces"])


class TestGetSflowEmpty(unittest.TestCase):
    """Parser raises SchemaEmptyParserError -- get_sflow_state should
    degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowSflow")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
            "empty"
        )

    def test_get_sflow_state_empty(self):
        self.assertEqual(get_sflow_state(self.device), {})


class TestGetSflowGenericException(unittest.TestCase):
    """Any unexpected exception from the parser should also degrade to {}
    (get_sflow_state catches the broad Exception case too)."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowSflow")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.side_effect = RuntimeError("boom")

    def test_get_sflow_state_generic_exception(self):
        self.assertEqual(get_sflow_state(self.device), {})


class TestSflowGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    sflow/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(sflow_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == sflow_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered sFlow get functions: {missing}")

        print(
            f"\nsFlow get coverage: {len(names)} functions, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
