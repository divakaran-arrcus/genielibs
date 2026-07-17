#!/usr/bin/env python3
"""Unit tests for arcOS PTP configure/unconfigure APIs (full coverage).

Each helper builds an arcOS CLI config list under a `ptp instance-list
<id>[ port-ds-list <port>]` context and calls device.configure(list). Tests
mock device.configure and assert the emitted CLI. A machine coverage check
(test_zzz_all_functions_covered) asserts that every public
configure_*/unconfigure_* function in the module was exercised by some test
in this file.

Note: ptp has no get.py or verify.py in the arcOS SDK (configure-only
feature), so this is the only test file for this feature.
"""

import inspect
import unittest
from unittest.mock import Mock

from unicon.core.errors import SubCommandFailure

import genie.libs.sdk.apis.arcos.ptp.configure as configure_module
from genie.libs.sdk.apis.arcos.ptp.configure import (
    configure_ptp_instance,
    unconfigure_ptp_instance,
    configure_ptp_port,
    unconfigure_ptp_port,
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


configure_ptp_instance = _track("configure_ptp_instance", configure_ptp_instance)
unconfigure_ptp_instance = _track("unconfigure_ptp_instance", unconfigure_ptp_instance)
configure_ptp_port = _track("configure_ptp_port", configure_ptp_port)
unconfigure_ptp_port = _track("unconfigure_ptp_port", unconfigure_ptp_port)


class _CfgDevice:
    def __init__(self):
        self.name = "rtr1"
        self.configure = Mock(return_value=True)

    def cfg(self):
        self.configure.assert_called()
        c = self.configure.call_args[0][0]
        return "\n".join(c) if isinstance(c, (list, tuple)) else str(c)


class TestConfigurePtpInstance(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ptp_instance_defaults(self):
        configure_ptp_instance(self.d, 1, "G8275.1")
        c = self.d.cfg()
        self.assertIn("ptp instance-list 1", c)
        self.assertIn("clock-profile G8275.1", c)
        self.assertIn("clock-role T-BC", c)

    def test_configure_ptp_instance_all_options(self):
        configure_ptp_instance(
            self.d, 2, "G8275.2", clock_role="T-GM",
            domain_number=24, priority2=128, servo_alg="linreg",
        )
        c = self.d.cfg()
        self.assertIn("ptp instance-list 2", c)
        self.assertIn("clock-profile G8275.2", c)
        self.assertIn("clock-role T-GM", c)
        self.assertIn("default-ds domain-number 24", c)
        self.assertIn("default-ds priority2 128", c)
        self.assertIn("servo-alg linreg", c)

    def test_unconfigure_ptp_instance(self):
        unconfigure_ptp_instance(self.d, 1)
        self.assertIn("no ptp instance-list 1", self.d.cfg())


class TestConfigurePtpPort(unittest.TestCase):
    def setUp(self):
        self.d = _CfgDevice()

    def test_configure_ptp_port_defaults(self):
        configure_ptp_port(self.d, 1, 1, "swp1")
        c = self.d.cfg()
        self.assertIn("ptp instance-list 1 port-ds-list 1", c)
        self.assertIn("underlying-interface interface swp1", c)
        self.assertIn("delay-mechanism e2e", c)

    def test_configure_ptp_port_p2p_master_only(self):
        configure_ptp_port(
            self.d, 1, 2, "swp2", delay_mechanism="p2p", master_only=True,
        )
        c = self.d.cfg()
        self.assertIn("delay-mechanism p2p", c)
        self.assertIn("master-only true", c)

    def test_configure_ptp_port_master_only_false(self):
        configure_ptp_port(self.d, 1, 3, "swp3", master_only=False)
        self.assertIn("master-only false", self.d.cfg())

    def test_unconfigure_ptp_port(self):
        unconfigure_ptp_port(self.d, 1, 2)
        c = self.d.cfg()
        self.assertIn("ptp instance-list 1", c)
        self.assertIn("no port-ds-list 2", c)


class TestConfigurePtpFailures(unittest.TestCase):
    """Exercise the SubCommandFailure re-raise path of every helper."""

    def setUp(self):
        self.d = _CfgDevice()
        self.d.configure = Mock(side_effect=SubCommandFailure("boom"))

    def test_configure_ptp_instance_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_ptp_instance(self.d, 1, "G8275.1")

    def test_unconfigure_ptp_instance_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_ptp_instance(self.d, 1)

    def test_configure_ptp_port_failure(self):
        with self.assertRaises(SubCommandFailure):
            configure_ptp_port(self.d, 1, 1, "swp1")

    def test_unconfigure_ptp_port_failure(self):
        with self.assertRaises(SubCommandFailure):
            unconfigure_ptp_port(self.d, 1, 1)


class TestConfigurePtpCoverage(unittest.TestCase):
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
            f"Untested public functions in ptp/configure.py: {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
