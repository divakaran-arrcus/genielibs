#!/usr/bin/env python3
"""Unit tests for arcOS Bridge Isolation configure/unconfigure APIs (full
coverage).

Every configure_* / unconfigure_* helper in
genie.libs.sdk.apis.arcos.bridge_isolation.configure builds an arcOS CLI
config list (an `interface <name>` context with a `bridge-isolation
isolation <enable|disable>` line) and calls `device.configure(config)`.
Tests mock `device.configure` and assert on a distinctive substring of the
emitted CLI, plus the SubCommandFailure wrap path for each helper.
"""

import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

from genie.libs.sdk.apis.arcos.bridge_isolation import configure as bi_configure
from genie.libs.sdk.apis.arcos.bridge_isolation.configure import (
    configure_bridge_isolation,
    unconfigure_bridge_isolation,
)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class _FailingDevice:
    """Device whose .configure() always raises SubCommandFailure."""

    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(side_effect=SubCommandFailure("boom"))


class TestConfigureBridgeIsolation(unittest.TestCase):
    """configure_bridge_isolation / unconfigure_bridge_isolation"""

    def setUp(self):
        self.d = _CfgDevice()

    def test_bridge_isolation_enable_default(self):
        configure_bridge_isolation(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("bridge-isolation isolation enable", c)

    def test_bridge_isolation_enable_explicit(self):
        configure_bridge_isolation(self.d, "swp1", enabled=True)
        self.assertIn("bridge-isolation isolation enable", self.d.cfg())

    def test_bridge_isolation_disable(self):
        configure_bridge_isolation(self.d, "swp1", enabled=False)
        self.assertIn("bridge-isolation isolation disable", self.d.cfg())

    def test_bridge_isolation_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            configure_bridge_isolation(d, "swp1")

    def test_unconfigure_bridge_isolation(self):
        unconfigure_bridge_isolation(self.d, "swp1")
        c = self.d.cfg()
        self.assertIn("interface swp1", c)
        self.assertIn("no bridge-isolation", c)

    def test_unconfigure_bridge_isolation_failure_wrapped(self):
        d = _FailingDevice()
        with self.assertRaises(SubCommandFailure):
            unconfigure_bridge_isolation(d, "swp1")


class TestBridgeIsolationConfigureFunctionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in bridge_isolation/configure.py must be referenced by name
    somewhere in this test file's source.
    """

    def test_all_public_functions_covered(self):
        import inspect

        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(bi_configure).items()
            if inspect.isfunction(obj)
            and obj.__module__ == bi_configure.__name__
            and (name.startswith("configure_") or name.startswith(
                "unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered Bridge Isolation configure/unconfigure functions: "
            f"{missing}")

        configure_count = sum(1 for n in names if n.startswith("configure_"))
        unconfigure_count = sum(
            1 for n in names if n.startswith("unconfigure_"))
        print(
            f"\nBridge Isolation configure/unconfigure coverage: "
            f"{configure_count} configure_*, {unconfigure_count} "
            f"unconfigure_*, {len(names)} total, 0 missing"
        )


if __name__ == "__main__":
    unittest.main()
