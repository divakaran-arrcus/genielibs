#!/usr/bin/env python3
"""Unit tests for arcOS LLDP configure/unconfigure APIs (full coverage).

ArcOS LLDP uses flat global commands (no network-instance/protocol context):

    lldp hello-timer <seconds>
    lldp interface <name> mode <TX_RX|TX_ONLY|RX_ONLY>
    lldp interface <name> enabled <true|false>

Each helper builds a small CLI config list and calls device.configure(list).
Tests mock device.configure and assert the emitted CLI, plus exercise the
SubCommandFailure wrapping branch for each direct (non-delegating) helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.lldp import configure as lldp_configure
from genie.libs.sdk.apis.arcos.lldp.configure import (
    configure_lldp_hello_timer,
    unconfigure_lldp_hello_timer,
    configure_lldp_interface_mode,
    unconfigure_lldp_interface_mode,
    configure_lldp_interface_enabled,
    unconfigure_lldp_interface_enabled,
    configure_lldp_interface_disabled,
    unconfigure_lldp_interface_disabled,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestHelloTimerApis(unittest.TestCase):
    """configure_lldp_hello_timer, unconfigure_lldp_hello_timer"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_hello_timer(self):
        configure_lldp_hello_timer(self.d, 35)
        self.assertIn("lldp hello-timer 35", self.d.cfg())

    def test_unconfigure_hello_timer(self):
        unconfigure_lldp_hello_timer(self.d)
        self.assertIn("no lldp hello-timer", self.d.cfg())


class TestInterfaceModeApis(unittest.TestCase):
    """configure_lldp_interface_mode, unconfigure_lldp_interface_mode"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_mode(self):
        configure_lldp_interface_mode(self.d, "swp1", "RX_ONLY")
        self.assertIn("lldp interface swp1 mode RX_ONLY", self.d.cfg())

    def test_unconfigure_interface_mode(self):
        unconfigure_lldp_interface_mode(self.d, "swp1")
        self.assertIn("no lldp interface swp1 mode", self.d.cfg())


class TestInterfaceEnabledApis(unittest.TestCase):
    """configure_lldp_interface_enabled, unconfigure_lldp_interface_enabled,
    configure_lldp_interface_disabled, unconfigure_lldp_interface_disabled"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_interface_enabled_default_true(self):
        configure_lldp_interface_enabled(self.d, "swp2")
        self.assertIn("lldp interface swp2 enabled true", self.d.cfg())

    def test_interface_enabled_false(self):
        configure_lldp_interface_enabled(self.d, "swp2", enabled=False)
        self.assertIn("lldp interface swp2 enabled false", self.d.cfg())

    def test_unconfigure_interface_enabled(self):
        unconfigure_lldp_interface_enabled(self.d, "swp2")
        self.assertIn("no lldp interface swp2 enabled", self.d.cfg())

    def test_interface_disabled_shortcut(self):
        """configure_lldp_interface_disabled delegates to
        configure_lldp_interface_enabled(enabled=False)."""
        configure_lldp_interface_disabled(self.d, "swp2")
        self.assertIn("lldp interface swp2 enabled false", self.d.cfg())

    def test_unconfigure_interface_disabled_shortcut(self):
        """unconfigure_lldp_interface_disabled delegates to
        configure_lldp_interface_enabled(enabled=True)."""
        unconfigure_lldp_interface_disabled(self.d, "swp2")
        self.assertIn("lldp interface swp2 enabled true", self.d.cfg())


class TestSubCommandFailureWrapping(unittest.TestCase):
    """Every direct configure_*/unconfigure_* helper wraps a
    device.configure() failure in a re-raised SubCommandFailure with a
    descriptive message. The two shortcut helpers
    (configure/unconfigure_lldp_interface_disabled) delegate to
    configure_lldp_interface_enabled, so its failure path covers them too.
    """

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_hello_timer_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_lldp_hello_timer(self.d, 35)

    def test_unconfigure_hello_timer_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_lldp_hello_timer(self.d)

    def test_interface_mode_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_lldp_interface_mode(self.d, "swp1", "RX_ONLY")

    def test_unconfigure_interface_mode_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_lldp_interface_mode(self.d, "swp1")

    def test_interface_enabled_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_lldp_interface_enabled(self.d, "swp2")

    def test_unconfigure_interface_enabled_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_lldp_interface_enabled(self.d, "swp2")

    def test_interface_disabled_shortcut_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_lldp_interface_disabled(self.d, "swp2")

    def test_unconfigure_interface_disabled_shortcut_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_lldp_interface_disabled(self.d, "swp2")


class TestLldpConfigureCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in lldp/configure.py must be referenced by name somewhere in
    this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(lldp_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == lldp_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered LLDP configure/unconfigure functions: {missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nLLDP configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
