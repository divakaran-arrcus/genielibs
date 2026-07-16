#!/usr/bin/env python3
"""Unit tests for arcOS STP configure/unconfigure APIs (full coverage).

Both helpers in genie.libs.sdk.apis.arcos.stp.configure build a top-level
`stp ...` CLI config list and call `device.configure(config)`. Tests mock
device.configure and assert on the emitted CLI.
"""

import unittest
from unittest.mock import Mock

from genie.libs.sdk.apis.arcos.stp import configure as stp_configure
from genie.libs.sdk.apis.arcos.stp.configure import (
    configure_stp_protocol,
    unconfigure_stp_protocol,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureStp(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_stp_protocol_default(self):
        configure_stp_protocol(self.d)
        self.assertIn("stp enabled-protocol RAPID_PVST", self.d.cfg())

    def test_configure_stp_protocol_none(self):
        configure_stp_protocol(self.d, protocol="NONE")
        self.assertIn("stp enabled-protocol NONE", self.d.cfg())

    def test_unconfigure_stp_protocol(self):
        unconfigure_stp_protocol(self.d)
        self.assertIn("no stp enabled-protocol", self.d.cfg())


class TestConfigureStpErrors(unittest.TestCase):
    """SubCommandFailure from device.configure() is re-raised with context."""

    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_stp_protocol_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            configure_stp_protocol(self.d)

    def test_unconfigure_stp_protocol_failure(self):
        from unicon.core.errors import SubCommandFailure

        self.d.configure = Mock(side_effect=SubCommandFailure("bad config"))
        with self.assertRaises(SubCommandFailure):
            unconfigure_stp_protocol(self.d)


class TestStpConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in stp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(stp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == stp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered STP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nSTP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
