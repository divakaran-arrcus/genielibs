#!/usr/bin/env python3
"""Unit tests for arcOS SNMP configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under the `system snmp-server`
context and calls device.configure(list). Tests mock device.configure and
assert the emitted CLI. A machine coverage check (test_all_public_functions_covered)
asserts that every public configure_*/unconfigure_* function in the module
is referenced by name in this test file's source.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.snmp.configure as configure_module
from genie.libs.sdk.apis.arcos.snmp.configure import (
    configure_snmp_server,
    unconfigure_snmp_server,
    configure_snmp_target,
    unconfigure_snmp_target,
    configure_snmp_threshold_traps,
    unconfigure_snmp_threshold_traps,
)

class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigureSnmpServer(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_snmp_server_defaults(self):
        configure_snmp_server(self.d)
        c = self.d.cfg()
        self.assertIn("system snmp-server", c)
        self.assertIn("enable true", c)

    def test_configure_snmp_server_disabled(self):
        configure_snmp_server(self.d, enabled=False)
        self.assertIn("enable false", self.d.cfg())

    def test_configure_snmp_server_all_options(self):
        configure_snmp_server(
            self.d,
            community="public",
            listen_addresses=["10.0.0.1", "10.0.0.2"],
            network_instance="default",
            port=161,
            contact="noc@arrcus.com",
            location="Lab Rack 3",
            protocol_version="V2C",
            trap_source_ip="10.0.0.1",
        )
        c = self.d.cfg()
        self.assertIn("community public", c)
        self.assertIn("listen-addresses 10.0.0.1", c)
        self.assertIn("listen-addresses 10.0.0.2", c)
        self.assertIn("network-instance default", c)
        self.assertIn("port 161", c)
        self.assertIn("contact noc@arrcus.com", c)
        self.assertIn('location "Lab Rack 3"', c)
        self.assertIn("protocol-version V2C", c)
        self.assertIn("trap-source-ip 10.0.0.1", c)

    def test_configure_snmp_server_single_listen_address(self):
        configure_snmp_server(self.d, listen_addresses="10.0.0.5")
        self.assertIn("listen-addresses 10.0.0.5", self.d.cfg())

    def test_unconfigure_snmp_server(self):
        unconfigure_snmp_server(self.d)
        c = self.d.cfg()
        self.assertIn("system snmp-server", c)
        self.assertIn("enable false", c)


class TestConfigureSnmpTarget(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_snmp_target(self):
        configure_snmp_target(self.d, "trapsrv1", "10.0.0.100")
        c = self.d.cfg()
        self.assertIn("system snmp-server target trapsrv1", c)
        self.assertIn("address 10.0.0.100", c)
        self.assertIn("port 162", c)

    def test_configure_snmp_target_with_params(self):
        configure_snmp_target(
            self.d, "trapsrv1", "10.0.0.100", port=1620,
            target_parameters="tp1",
        )
        c = self.d.cfg()
        self.assertIn("port 1620", c)
        self.assertIn("target-parameters tp1", c)

    def test_unconfigure_snmp_target(self):
        unconfigure_snmp_target(self.d, "trapsrv1")
        self.assertIn("no system snmp-server target trapsrv1", self.d.cfg())


class TestConfigureSnmpThresholdTraps(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_snmp_threshold_traps(self):
        configure_snmp_threshold_traps(self.d, cpu=80, memory=90)
        c = self.d.cfg()
        self.assertIn("system snmp-server", c)
        self.assertIn("threshold-traps cpu 80", c)
        self.assertIn("threshold-traps memory 90", c)

    def test_configure_snmp_threshold_traps_cpu_only(self):
        configure_snmp_threshold_traps(self.d, cpu=75)
        c = self.d.cfg()
        self.assertIn("threshold-traps cpu 75", c)
        self.assertNotIn("threshold-traps memory", c)

    def test_unconfigure_snmp_threshold_traps(self):
        unconfigure_snmp_threshold_traps(self.d)
        c = self.d.cfg()
        self.assertIn("no threshold-traps cpu", c)
        self.assertIn("no threshold-traps memory", c)


class TestConfigureSnmpFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_snmp_server_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_snmp_server(self.d)

    def test_unconfigure_snmp_server_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_snmp_server(self.d)

    def test_configure_snmp_target_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_snmp_target(self.d, "trapsrv1", "10.0.0.100")

    def test_unconfigure_snmp_target_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_snmp_target(self.d, "trapsrv1")

    def test_configure_snmp_threshold_traps_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_snmp_threshold_traps(self.d, cpu=80)

    def test_unconfigure_snmp_threshold_traps_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_snmp_threshold_traps(self.d)


class TestConfigureSnmpCoverage(unittest.TestCase):
    """Machine-checked coverage: every public configure_*/unconfigure_*
    function in snmp/configure.py must be referenced by name somewhere in
    this test file's source. Order-safe under both pytest and
    ``python -m unittest`` (unlike a runtime call-tracking gate, which
    depends on other test classes having already executed).
    """

    def test_all_public_functions_covered(self):
        with open(__file__, "r") as f:
            source = f.read()

        names = [
            name for name, obj in vars(configure_module).items()
            if inspect.isfunction(obj)
            and obj.__module__ == configure_module.__name__
            and (name.startswith("configure_") or name.startswith("unconfigure_"))
        ]

        missing = [n for n in names if n not in source]
        self.assertEqual(
            missing, [],
            f"Uncovered SNMP configure functions: {missing}")


if __name__ == "__main__":
    unittest.main()
