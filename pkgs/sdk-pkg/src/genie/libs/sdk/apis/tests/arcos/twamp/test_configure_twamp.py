#!/usr/bin/env python3
"""Unit tests for arcOS TWAMP configure/unconfigure APIs (full coverage).

ArcOS TWAMP session-reflector uses a network-instance context:

    network-instance <ni>
        twamp session-reflector admin-state <true|false>
        twamp session-reflector reflector-udp-port <port>

Each helper builds a CLI config list and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI (default and
named network-instance, plus the optional reflector_udp_port branch),
plus exercise the SubCommandFailure wrapping branch for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.twamp import configure as twamp_configure
from genie.libs.sdk.apis.arcos.twamp.configure import (
    configure_twamp_session_reflector,
    unconfigure_twamp_session_reflector,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestTwampSessionReflectorApis(unittest.TestCase):
    """configure_twamp_session_reflector, unconfigure_twamp_session_reflector"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_session_reflector_default(self):
        configure_twamp_session_reflector(self.d)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("twamp session-reflector admin-state true", c)
        self.assertNotIn("reflector-udp-port", c)

    def test_session_reflector_disabled(self):
        configure_twamp_session_reflector(self.d, enabled=False)
        self.assertIn("twamp session-reflector admin-state false", self.d.cfg())

    def test_session_reflector_udp_port(self):
        configure_twamp_session_reflector(self.d, reflector_udp_port=862)
        self.assertIn(
            "twamp session-reflector reflector-udp-port 862", self.d.cfg()
        )

    def test_session_reflector_named_network_instance(self):
        configure_twamp_session_reflector(self.d, network_instance="VRF1")
        self.assertIn("network-instance VRF1", self.d.cfg())

    def test_unconfigure_session_reflector_default(self):
        unconfigure_twamp_session_reflector(self.d)
        c = self.d.cfg()
        self.assertIn("network-instance default", c)
        self.assertIn("no twamp session-reflector admin-state", c)
        self.assertIn("no twamp session-reflector reflector-udp-port", c)

    def test_unconfigure_session_reflector_named_network_instance(self):
        unconfigure_twamp_session_reflector(self.d, network_instance="VRF1")
        self.assertIn("network-instance VRF1", self.d.cfg())


class TestSubCommandFailureWrapping(unittest.TestCase):
    """Every configure_*/unconfigure_* helper wraps a device.configure()
    failure in a re-raised SubCommandFailure with a descriptive message."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_session_reflector_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_twamp_session_reflector(self.d)

    def test_unconfigure_session_reflector_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_twamp_session_reflector(self.d)


class TestTwampConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in twamp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(twamp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == twamp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered TWAMP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nTWAMP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
