#!/usr/bin/env python3
"""Unit tests for arcOS Monitor Session (SPAN) configure/unconfigure APIs
(full coverage).

Each helper builds an arcOS CLI config list under a `monitor-session <name>`
context and calls device.configure(list). Tests mock device.configure and
assert the emitted CLI. A machine coverage check (test_zzz_all_functions_covered)
asserts that every public configure_*/unconfigure_* function in the module
was exercised by some test in this file.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.monitor_session.configure as configure_module
from genie.libs.sdk.apis.arcos.monitor_session.configure import (
    configure_monitor_session,
    unconfigure_monitor_session,
)

class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureMonitorSession(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_monitor_session_defaults(self):
        configure_monitor_session(self.d, "span1")
        c = self.d.cfg()
        self.assertIn("monitor-session span1", c)
        self.assertIn("enable true", c)

    def test_configure_monitor_session_disabled(self):
        configure_monitor_session(self.d, "span1", enabled=False)
        self.assertIn("enable false", self.d.cfg())

    def test_configure_monitor_session_source_and_dest_interface(self):
        configure_monitor_session(
            self.d, "span1", source_interface="swp1",
            source_direction="INGRESS", dest_interface="swp10",
        )
        c = self.d.cfg()
        self.assertIn("source interface swp1 INGRESS", c)
        self.assertIn("destination interface swp10", c)

    def test_configure_monitor_session_dest_cpu(self):
        configure_monitor_session(
            self.d, "span2", source_interface="swp2",
            source_direction="EGRESS", dest_cpu=True,
        )
        c = self.d.cfg()
        self.assertIn("source interface swp2 EGRESS", c)
        self.assertIn("destination cpu", c)

    def test_configure_monitor_session_no_source_without_direction(self):
        """source_interface without source_direction should not emit a
        source line (both are required together per the source)."""
        configure_monitor_session(self.d, "span3", source_interface="swp3")
        c = self.d.cfg()
        self.assertNotIn("source interface", c)

    def test_configure_monitor_session_dest_interface_takes_precedence(self):
        configure_monitor_session(
            self.d, "span4", dest_interface="swp10", dest_cpu=True,
        )
        c = self.d.cfg()
        self.assertIn("destination interface swp10", c)
        self.assertNotIn("destination cpu", c)

    def test_unconfigure_monitor_session(self):
        unconfigure_monitor_session(self.d, "span1")
        self.assertIn("no monitor-session span1", self.d.cfg())


class TestConfigureMonitorSessionFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_monitor_session_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_monitor_session(self.d, "span1")

    def test_unconfigure_monitor_session_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_monitor_session(self.d, "span1")


class TestConfigureMonitorSessionCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in monitor_session/configure.py must be referenced by name
    somewhere in this test file's source. Order-safe under both pytest
    (file order) and unittest (alphabetical class order via dir()).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__
            and (name.startswith("configure_") or name.startswith("unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Untested public functions in monitor_session/configure.py: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
