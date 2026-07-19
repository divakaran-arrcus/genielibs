#!/usr/bin/env python3
"""Unit tests for arcOS version verify APIs (full coverage).

verify_software_version is intentionally simple (no Timeout/polling --
the software version is static for the duration of a test run), so it
is exercised directly with matching/mismatching/missing values rather
than via a Timeout(max_time=0) fast-fail.
"""

import inspect
import unittest

from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.libs.sdk.apis.arcos.version import verify as version_verify
from genie.libs.sdk.apis.arcos.version.verify import verify_software_version

_PARSED = {
    "version": {
        "sw-version": "v8.4.1.EFT1:Jan_16_26:2_43_AM",
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


class TestVerifySoftwareVersion(unittest.TestCase):
    def setUp(self):
        self.device = _DummyDevice(parsed=_PARSED)

    def test_match(self):
        self.assertTrue(
            verify_software_version(
                self.device, "v8.4.1.EFT1:Jan_16_26:2_43_AM"
            )
        )

    def test_mismatch(self):
        self.assertFalse(
            verify_software_version(self.device, "v9.0.0")
        )

    def test_missing_version_false(self):
        device = _DummyDevice(raise_exc=SchemaEmptyParserError("empty"))
        self.assertFalse(verify_software_version(device, "v8.4.1"))


class TestVersionVerifyCoverage(unittest.TestCase):
    """Machine-checked coverage: every public verify_* function in
    version/verify.py must be referenced by name somewhere in this test
    file's source.
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(version_verify).items()
            if inspect.isfunction(obj)
            and obj.__module__ == version_verify.__name__
            and name.startswith("verify_")
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered version verify functions: {missing}")

        print(
            f"\nVersion verify coverage: {len(names)} verify_* functions, "
            f"0 missing"
        )


if __name__ == "__main__":
    unittest.main()
