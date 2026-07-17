#!/usr/bin/env python3
"""Unit tests for arcOS SNMP configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under the `system snmp-server`
context and calls device.configure(list). Tests mock device.configure and
assert the emitted CLI. A machine coverage check (test_zzz_all_functions_covered)
asserts that every public configure_*/unconfigure_* function in the module
was exercised by some test in this file.
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

# ---------------------------------------------------------------------------
# Machine coverage tracking: wrap each imported function so calling it during
# a test records its name. The final test asserts every public function in
# the module was called at least once.
# ---------------------------------------------------------------------------
_CALLED = set()


def _track(name, fn):
    def _wrapper(*args, **kwargs):
        _CALLED.add(name)
        return fn(*args, **kwargs)
    return _wrapper


configure_snmp_server = _track("configure_snmp_server", configure_snmp_server)
unconfigure_snmp_server = _track("unconfigure_snmp_server", unconfigure_snmp_server)
configure_snmp_target = _track("configure_snmp_target", configure_snmp_target)
unconfigure_snmp_target = _track("unconfigure_snmp_target", unconfigure_snmp_target)
configure_snmp_threshold_traps = _track(
    "configure_snmp_threshold_traps", configure_snmp_threshold_traps
)
unconfigure_snmp_threshold_traps = _track(
    "unconfigure_snmp_threshold_traps", unconfigure_snmp_threshold_traps
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
    def test_zzz_all_functions_covered(self):
        """Machine coverage check: every public function in configure.py
        must have been called by at least one test above."""
        public_fns = {
            name
            for name, obj in inspect.getmembers(configure_module, inspect.isfunction)
            if obj.__module__ == configure_module.__name__ and not name.startswith("_")
        }
        missing = public_fns - _CALLED
        self.assertEqual(
            missing, set(),
            f"Untested public functions in snmp/configure.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
