#!/usr/bin/env python3
"""Unit tests for arcOS version get APIs (full coverage).

Both get helpers call ``device.parse("show version")`` directly (the
ShowVersion parser class is never imported into get.py, so there is
nothing to patch at module scope) -- a dummy device shim with a
``parse()`` method that returns canned ShowVersion-shaped output, raises
SchemaEmptyParserError, or raises a generic Exception is enough to
exercise both success and degrade paths.
"""

import inspect
import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.version import get as version_get
from genie.libs.sdk.apis.arcos.version.get import (
    get_version_info,
    get_software_version,
)

_PARSED = {
    "version": {
        "sw-version": "v8.4.1.EFT1:Jan_16_26:2_43_AM",
        "software": "ArcOS",
        "platform": "ACX7240",
        "form-factor": "1RU",
        "num-cpu-cores": "16",
        "cpu-info": "Intel(R) Xeon(R)",
        "total-memory": "32G",
        "uptime": "10 days, 3:21:05",
    }
}


class _DummyDevice:
    def __init__(self, parsed=None, raise_exc=None):
        self._parsed = parsed
        self._raise = raise_exc

    def parse(self, command):  # pragma: no cover - trivial
        if self._raise is not None:
            raise self._raise
        return self._parsed


class TestGetVersionInfo(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_version_info(self):
        self.assertEqual(get_version_info(self.device), _PARSED["version"])

    def test_get_version_info_schema_empty(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertEqual(get_version_info(device), {})

    def test_get_version_info_generic_exception(self):
        device = _DummyDevice(raise_exc=RuntimeError("boom"))
        self.assertEqual(get_version_info(device), {})

    def test_get_version_info_missing_version_key(self):
        device = _DummyDevice(parsed={})
        self.assertEqual(get_version_info(device), {})

    def test_get_version_info_non_dict_version(self):
        device = _DummyDevice(parsed={"version": "not-a-dict"})
        self.assertEqual(get_version_info(device), {})

    def test_get_version_info_none_output(self):
        device = _DummyDevice(parsed=None)
        with self.assertRaises(AttributeError):
            get_version_info(device)


class TestGetSoftwareVersion(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_get_software_version(self):
        self.assertEqual(
            get_software_version(self.device),
            "v8.4.1.EFT1:Jan_16_26:2_43_AM",
        )

    def test_get_software_version_missing_field(self):
        device = _DummyDevice(parsed={"version": {"software": "ArcOS"}})
        self.assertIsNone(get_software_version(device))

    def test_get_software_version_empty_string(self):
        device = _DummyDevice(parsed={"version": {"sw-version": ""}})
        self.assertIsNone(get_software_version(device))

    def test_get_software_version_non_str(self):
        device = _DummyDevice(parsed={"version": {"sw-version": 8.4}})
        self.assertIsNone(get_software_version(device))

    def test_get_software_version_schema_empty(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertIsNone(get_software_version(device))


class TestVersionGetCoverage(unittest.TestCase):
    """Machine-checked coverage: every public get_* function in
    version/get.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(version_get).items()
            if inspect.isfunction(obj)
            and obj.__module__ == version_get.__name__
            and name.startswith("get_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered version get functions: {missing}")

        print(
            f"\nVersion get coverage: {len(names)} get_* functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
