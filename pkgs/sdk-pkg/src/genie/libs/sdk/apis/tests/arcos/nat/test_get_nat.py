#!/usr/bin/env python3
"""Unit tests for arcOS NAT get APIs (full coverage).

genie.libs.sdk.apis.arcos.nat.get.get_nat_instance instantiates
``genie.libs.parser.arcos.show_nat.ShowNatInstance`` directly and calls
``.parse(instance_id=...)`` on it. Tests therefore patch the ``ShowNatInstance``
name as imported into the ``get`` module and return canned parser output
shaped like the real ``ShowNatInstance`` schema (``{"instances": {...}}``
keyed by instance id).
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from genie.metaparser.util.exceptions import SchemaEmptyParserError

from genie.libs.sdk.apis.arcos.nat import get as nat_get
from genie.libs.sdk.apis.arcos.nat.get import get_nat_instance

MOD = "genie.libs.sdk.apis.arcos.nat.get"

CANNED_OUTPUT = {
    "instances": {
        "1": {
            "id": 1,
            "name": "napt1",
            "enabled": True,
            "type": "napt44",
            "mapping-entries": {
                "1": {
                    "id": 1,
                    "internal-src-address": "10.10.0.0/16",
                    "total-packets": 100,
                    "total-bytes": 5000,
                },
            },
            "policies": {
                "1": {"id": 1, "external-interface": "swp1"},
            },
        }
    }
}


class TestGetNat(unittest.TestCase):
    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"
        patcher = patch(f"{MOD}.ShowNatInstance")
        self.mock_parser = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_parser.return_value.parse.return_value = CANNED_OUTPUT

    def test_get_nat_instance_found(self):
        result = get_nat_instance(self.device, 1)
        self.assertEqual(result, CANNED_OUTPUT)
        self.mock_parser.return_value.parse.assert_called_with(instance_id=1)

    def test_get_nat_instance_fields(self):
        result = get_nat_instance(self.device, 1)
        entry = result["instances"]["1"]
        self.assertEqual(entry["name"], "napt1")
        self.assertTrue(entry["enabled"])
        self.assertEqual(
            entry["mapping-entries"]["1"]["internal-src-address"],
            "10.10.0.0/16",
        )
        self.assertEqual(
            entry["policies"]["1"]["external-interface"], "swp1"
        )


class TestGetNatDegrade(unittest.TestCase):
    """Parser raises -- get_nat_instance should degrade to {}."""

    def setUp(self):
        self.device = Mock()
        self.device.name = "rtr1"

    def test_get_nat_instance_empty(self):
        with patch(f"{MOD}.ShowNatInstance") as mock_parser:
            mock_parser.return_value.parse.side_effect = SchemaEmptyParserError(
                "empty"
            )
            self.assertEqual(get_nat_instance(self.device, 1), {})

    def test_get_nat_instance_exception(self):
        with patch(f"{MOD}.ShowNatInstance") as mock_parser:
            mock_parser.return_value.parse.side_effect = RuntimeError("boom")
            self.assertEqual(get_nat_instance(self.device, 1), {})


class TestNatGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_*/is_* function in
    nat/get.py must be referenced by name somewhere in this test file's
    source.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(nat_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == nat_get.__name__
            and (name.startswith("get_") or name.startswith("is_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(missing, [], f"Uncovered NAT get functions: {missing}")

        print(f"\nNAT get coverage: {len(names)} functions, 0 missing")


if __name__ == "__main__":
    unittest.main()
